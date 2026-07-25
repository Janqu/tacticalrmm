"""SNMP devices (printers, UPS, switches) that cannot run an agent.

Devices hang off a Site, so they slot into the existing Client -> Site tree. They are
polled by an agent at the same site acting as a probe, because customer devices sit in
customer LANs and are not reachable from the server.
"""

from django.db import models
from django.utils import timezone as djangotime


class SnmpDeviceType(models.TextChoices):
    PRINTER = "printer", "Printer"
    UPS = "ups", "UPS"
    SWITCH = "switch", "Switch"
    FIREWALL = "firewall", "Firewall"
    NAS = "nas", "NAS"
    OTHER = "other", "Other"


class SnmpDeviceStatus(models.TextChoices):
    ONLINE = "online", "Online"
    OFFLINE = "offline", "Offline"
    PENDING = "pending", "Pending"


class SnmpDeviceQuerySet(models.QuerySet):
    def filter_by_role(self, user) -> "models.QuerySet":
        """Mirrors PermissionQuerySet's Agent branch for our site-scoped model.

        Necessary because the upstream filter_by_role returns a model without an
        `agent` attribute *unfiltered* — a new model silently gets no scoping at all.
        """
        role = user.role

        if user.is_superuser or (role and getattr(role, "is_superuser")):
            return self

        if not role:
            return self.none()

        clients_q = models.Q()
        sites_q = models.Q()

        can_view_clients = role.can_view_clients.all()
        can_view_sites = role.can_view_sites.all()

        if can_view_clients:
            clients_q = models.Q(site__client__in=can_view_clients)
        if can_view_sites:
            sites_q = models.Q(site__in=can_view_sites)

        # no restrictions configured means the role sees everything, same as upstream
        return self.filter(clients_q | sites_q)


class SnmpDevice(models.Model):
    objects = SnmpDeviceQuerySet.as_manager()

    site = models.ForeignKey(
        "clients.Site",
        related_name="snmp_devices",
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=255)
    device_type = models.CharField(
        max_length=20, choices=SnmpDeviceType.choices, default=SnmpDeviceType.PRINTER
    )
    ip = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=161)
    community = models.CharField(max_length=255, default="public")
    enabled = models.BooleanField(default=True)
    description = models.CharField(max_length=255, null=True, blank=True)

    # how long without a successful poll before the device counts as offline
    offline_minutes = models.PositiveIntegerField(default=30)

    # {"supply.black": {"oid": "1.3...9.1.1", "max_oid": "1.3...8.1.1"},
    #  "uptime.seconds": {"oid": "1.3.6.1.2.1.1.3.0", "scale": 0.01}}
    # Empty means the probe falls back to the built-in profile for device_type.
    # Printers differ enough between vendors that hardcoding every quirk is hopeless,
    # so the mapping lives on the device where discovery can write it.
    metric_map = models.JSONField(default=dict, blank=True)

    # filled in by the probe
    model_name = models.CharField(max_length=255, null=True, blank=True)
    serial = models.CharField(max_length=255, null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(null=True, blank=True)

    created_time = models.DateTimeField(auto_now_add=True)
    modified_time = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("site", "name")
        constraints = [
            models.UniqueConstraint(
                fields=["site", "ip", "port"], name="unique_snmp_device_per_site"
            )
        ]

    def __str__(self) -> str:
        return f"{self.site} - {self.name}"

    @property
    def client(self):
        return self.site.client

    @property
    def status(self) -> str:
        if not self.last_seen:
            return SnmpDeviceStatus.PENDING
        offline_at = djangotime.now() - djangotime.timedelta(
            minutes=self.offline_minutes
        )
        return (
            SnmpDeviceStatus.ONLINE
            if self.last_seen > offline_at
            else SnmpDeviceStatus.OFFLINE
        )


class SnmpReading(models.Model):
    """One numeric (or textual) sample. This is what gives real trend graphs, which
    script checks cannot provide — those only ever store pass/fail in CheckHistory."""

    # high volume table, so it gets a bigint pk like CheckResult and AgentHistory do
    id = models.BigAutoField(primary_key=True)
    device = models.ForeignKey(
        SnmpDevice, related_name="readings", on_delete=models.CASCADE
    )
    metric = models.CharField(max_length=100)
    value = models.FloatField(null=True, blank=True)
    text = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-timestamp",)
        indexes = [
            models.Index(fields=["device", "metric", "-timestamp"]),
        ]

    def __str__(self) -> str:
        return f"{self.device.name} {self.metric}={self.value}"

    @staticmethod
    def prune(days: int = 90) -> int:
        """Readings grow without bound; call this from celerybeat once wired up."""
        # ponytail: manual prune for now, add a beat schedule when volume justifies it
        cutoff = djangotime.now() - djangotime.timedelta(days=days)
        deleted, _ = SnmpReading.objects.filter(timestamp__lt=cutoff).delete()
        return deleted
