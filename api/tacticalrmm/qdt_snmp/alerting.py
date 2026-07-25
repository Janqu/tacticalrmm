"""Turn readings into alerts on state change, not on every poll.

The probe runs every few minutes. Alerting per sample would mean an alert per poll
for as long as a toner stays low, so an alert is opened when a threshold is first
crossed and resolved when the value recovers. SnmpAlert remembers which TRMM alert
belongs to which device metric so it can be found again.
"""

from typing import Optional

from django.db import IntegrityError, transaction

from alerts.models import Alert
from tacticalrmm.constants import AlertSeverity, AlertType

from .models import SnmpAlert, SnmpDevice

# Sensible starting points per device type, overridden by SnmpDevice.thresholds.
# A key ending in "." matches by prefix, so "supply." covers black, cyan, whatever
# the device happens to report - which is the point of normalising the metric names.
DEFAULT_THRESHOLDS = {
    "printer": {
        "supply.": {"warning": 20, "error": 10, "direction": "below"},
    },
    "ups": {
        "battery.charge_percent": {"warning": 50, "error": 20, "direction": "below"},
        "battery.minutes_remaining": {"warning": 15, "error": 5, "direction": "below"},
        "output.load_percent": {"warning": 80, "error": 95, "direction": "above"},
    },
}

# metric name used for "the device did not answer at all"
UNREACHABLE_METRIC = "__unreachable__"


def thresholds_for(device: SnmpDevice, metric: str) -> Optional[dict]:
    """Per-device settings win over the type default; exact key wins over a prefix."""
    for source in (device.thresholds or {}, DEFAULT_THRESHOLDS.get(device.device_type, {})):
        if metric in source:
            return source[metric]
        for key, spec in source.items():
            if key.endswith(".") and metric.startswith(key):
                return spec
    return None


def severity_for(value: float, spec: dict) -> Optional[str]:
    """Returns "error", "warning" or None. error is checked first so it wins."""
    below = spec.get("direction", "below") == "below"

    for level, severity in (("error", AlertSeverity.ERROR), ("warning", AlertSeverity.WARNING)):
        limit = spec.get(level)
        if limit is None:
            continue
        if (value <= limit) if below else (value >= limit):
            return severity
    return None


def _open(device: SnmpDevice, metric: str, severity: str, message: str) -> None:
    existing = SnmpAlert.objects.filter(device=device, metric=metric).first()
    if existing and existing.severity == severity:
        return  # already open at this level, do not notify again

    probe = device.site.agents.filter(monitoring_type__isnull=False).first()

    if existing:
        # severity changed, resolve the old one so history stays honest
        _close_alert(existing)
        existing.delete()

    alert = Alert.objects.create(
        agent=probe,
        alert_type=AlertType.CUSTOM,
        severity=severity,
        message=message,
    )
    try:
        # savepoint: the ingest runs inside a transaction, and a concurrent poll
        # may have linked this metric between our check and here
        with transaction.atomic():
            SnmpAlert.objects.create(
                device=device, metric=metric, severity=severity, alert=alert
            )
    except IntegrityError:
        # the concurrent link wins; our duplicate alert goes away
        alert.delete()

    if device.email_alerts:
        _notify(device, probe, message)


def _close_alert(link: SnmpAlert) -> None:
    if link.alert and not link.alert.resolved:
        link.alert.resolve()


def _resolve(device: SnmpDevice, metric: str) -> None:
    link = SnmpAlert.objects.filter(device=device, metric=metric).first()
    if not link:
        return
    _close_alert(link)
    link.delete()


def _notify(device: SnmpDevice, probe, message: str) -> None:
    from core.models import CoreSettings

    core = CoreSettings.objects.first()
    if not core:
        return
    core.send_mail(
        f"{device.site.client.name} - {device.name}",
        message,
        alert_template=probe.alert_template if probe else None,
    )


def evaluate(device: SnmpDevice, metrics: dict, reachable: bool) -> list[str]:
    """Called once per device per ingest. Returns the messages it raised."""
    raised = []
    where = f"{device.site.client.name} / {device.site.name}"

    if not reachable:
        message = f"{device.name} ({device.ip}) at {where} is not answering SNMP."
        if not SnmpAlert.objects.filter(device=device, metric=UNREACHABLE_METRIC).exists():
            raised.append(message)
        _open(device, UNREACHABLE_METRIC, AlertSeverity.ERROR, message)
        # a silent device says nothing about its toner, so leave those alerts alone
        return raised

    _resolve(device, UNREACHABLE_METRIC)

    for metric, value in metrics.items():
        spec = thresholds_for(device, metric)
        if not spec:
            continue

        severity = severity_for(value, spec)
        if severity is None:
            _resolve(device, metric)
            continue

        message = f"{device.name} at {where}: {metric} is {value} ({severity})."
        link = SnmpAlert.objects.filter(device=device, metric=metric).first()
        if not link or link.severity != severity:
            raised.append(message)
        _open(device, metric, severity, message)

    return raised
