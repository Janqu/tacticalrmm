import json
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone as djangotime
from model_bakery import baker
from rest_framework.exceptions import ValidationError

from tacticalrmm.test import TacticalTestCase

from .models import SnmpAlert, SnmpDevice, SnmpReading
from .serializers import validate_metric_map, validate_thresholds

BASE = "/qdt_snmp"


class TestSnmpDevices(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

        self.client_a = baker.make("clients.Client")
        self.client_b = baker.make("clients.Client")
        self.site_a = baker.make("clients.Site", client=self.client_a)
        self.site_b = baker.make("clients.Site", client=self.client_b)

        self.printer_a = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site_a, name="Drucker A", ip="10.0.0.10",
            community="secret-a",
        )
        self.printer_b = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site_b, name="Drucker B", ip="10.0.1.10",
            community="secret-b",
        )

    def _scoped_user(self, client):
        """A user whose role may only see one client."""
        user = self.create_user_with_roles(["can_list_sites", "can_manage_sites"])
        user.role.can_view_clients.set([client])
        return user

    def test_not_authenticated(self):
        for method, url in (
            ("get", f"{BASE}/devices/"),
            ("post", f"{BASE}/devices/"),
            ("get", f"{BASE}/devices/{self.printer_a.pk}/"),
            ("get", f"{BASE}/devices/{self.printer_a.pk}/readings/"),
        ):
            with self.subTest(url=url):
                self.check_not_authenticated(method, url)

    def test_role_scoping_hides_other_clients_devices(self):
        """The upstream filter_by_role leaves models without an `agent` attribute
        completely unfiltered, so this is the test that matters most."""
        self.client.force_authenticate(user=self._scoped_user(self.client_a))

        r = self.client.get(f"{BASE}/devices/")
        self.assertEqual(r.status_code, 200)
        names = [d["name"] for d in r.data]
        self.assertEqual(names, ["Drucker A"])

        # and the other client's device must not be reachable directly either
        r = self.client.get(f"{BASE}/devices/{self.printer_b.pk}/")
        self.assertEqual(r.status_code, 403)

    def test_superuser_sees_every_client(self):
        r = self.client.get(f"{BASE}/devices/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 2)

    def test_read_permission_is_required(self):
        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(f"{BASE}/devices/").status_code, 403)

    def test_write_permission_is_required(self):
        user = self.create_user_with_roles(["can_list_sites"])
        self.client.force_authenticate(user=user)
        r = self.client.post(
            f"{BASE}/devices/",
            {"site": self.site_a.pk, "name": "Neu", "ip": "10.0.0.99"},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

    def test_cannot_create_device_in_a_foreign_site(self):
        self.client.force_authenticate(user=self._scoped_user(self.client_a))
        r = self.client.post(
            f"{BASE}/devices/",
            {"site": self.site_b.pk, "name": "Fremd", "ip": "10.0.1.99"},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

    def test_cannot_move_device_into_a_foreign_site(self):
        self.client.force_authenticate(user=self._scoped_user(self.client_a))
        r = self.client.put(
            f"{BASE}/devices/{self.printer_a.pk}/",
            {"site": self.site_b.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

    def test_community_is_masked_and_survives_a_round_trip(self):
        r = self.client.get(f"{BASE}/devices/{self.printer_a.pk}/")
        self.assertEqual(r.status_code, 200)
        masked = r.data["community"]
        self.assertNotEqual(masked, "secret-a")
        self.assertIn("•", masked)
        self.assertTrue(masked.endswith("et-a"))

        # submitting the masked value back must not overwrite the stored community
        r = self.client.put(
            f"{BASE}/devices/{self.printer_a.pk}/",
            {"community": masked, "name": "Drucker A neu"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.printer_a.refresh_from_db()
        self.assertEqual(self.printer_a.community, "secret-a")
        self.assertEqual(self.printer_a.name, "Drucker A neu")


class TestMetricMapValidation(TacticalTestCase):
    """A bad map would not fail loudly, it would quietly produce wrong readings."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")

    def _post(self, metric_map):
        return self.client.post(
            f"{BASE}/devices/",
            {
                "site": self.site.pk,
                "name": "Drucker",
                "ip": "10.0.0.1",
                "metric_map": metric_map,
            },
            format="json",
        )

    def test_valid_map_is_accepted_and_reaches_the_probe(self):
        good = {
            "supply.black": {
                "oid": "1.3.6.1.2.1.43.11.1.1.9.1.1",
                "max_oid": "1.3.6.1.2.1.43.11.1.1.8.1.1",
            },
            "uptime.seconds": {"oid": "1.3.6.1.2.1.1.3.0", "scale": 0.01},
        }
        r = self._post(good)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(SnmpDevice.objects.get(pk=r.data["id"]).metric_map, good)

        agent = baker.make_recipe("agents.agent", site=self.site)
        r = self.client.get(f"{BASE}/probe/{agent.agent_id}/devices/")
        self.assertEqual(r.data[0]["metric_map"], good)

    def test_bad_maps_are_rejected(self):
        cases = {
            "not an object": [1, 2],
            "entry not an object": {"a": "1.2.3"},
            "missing oid": {"a": {"scale": 2}},
            "oid is not an oid": {"a": {"oid": "sysDescr"}},
            "max_oid is not an oid": {"a": {"oid": "1.3.6", "max_oid": "nope"}},
            "scale not numeric": {"a": {"oid": "1.3.6", "scale": "zwei"}},
            # what the browser actually sends for an unparseable number
            "scale is null": {"a": {"oid": "1.3.6", "scale": None}},
            "unknown key": {"a": {"oid": "1.3.6", "multiply": 2}},
        }
        for label, bad in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self._post(bad).status_code, 400)

    def test_empty_map_is_allowed_and_means_use_the_builtin_profile(self):
        r = self._post({})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(SnmpDevice.objects.get(pk=r.data["id"]).metric_map, {})


class TestValidatorsDirectly(SimpleTestCase):
    """Values strict json cannot carry, so they never arrive over HTTP - but they can
    be set through the ORM or a lenient parser, and NaN is a float that an isinstance
    check happily accepts."""

    def test_non_finite_numbers_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_metric_map({"a": {"oid": "1.3.6", "scale": value}})
                with self.assertRaises(ValidationError):
                    validate_thresholds({"a": {"warning": value}})

    def test_bool_is_not_a_number(self):
        with self.assertRaises(ValidationError):
            validate_metric_map({"a": {"oid": "1.3.6", "scale": True}})


class TestSnmpProbe(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

        self.site_a = baker.make("clients.Site")
        self.site_b = baker.make("clients.Site")
        self.probe = baker.make_recipe("agents.agent", site=self.site_a)

        self.printer_a = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site_a, name="Drucker A", ip="10.0.0.10"
        )
        self.disabled = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site_a, name="Aus", ip="10.0.0.11",
            enabled=False,
        )
        self.printer_b = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site_b, name="Drucker B", ip="10.0.1.10"
        )

    def test_probe_only_gets_its_own_sites_enabled_devices(self):
        r = self.client.get(f"{BASE}/probe/{self.probe.agent_id}/devices/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([d["name"] for d in r.data], ["Drucker A"])
        # the probe needs the community in the clear to talk snmp
        self.assertEqual(r.data[0]["community"], self.printer_a.community)

    def test_ingest_updates_the_device_and_stores_readings(self):
        r = self.client.post(
            f"{BASE}/probe/{self.probe.agent_id}/devices/",
            [
                {
                    "id": self.printer_a.pk,
                    "reachable": True,
                    "model_name": "HP M404",
                    "serial": "ABC123",
                    "metrics": {"toner.black": 42.0, "pages.total": 15234.0},
                }
            ],
            format="json",
        )
        self.assertEqual(r.status_code, 200)

        self.printer_a.refresh_from_db()
        self.assertIsNotNone(self.printer_a.last_seen)
        self.assertEqual(self.printer_a.model_name, "HP M404")
        self.assertEqual(self.printer_a.serial, "ABC123")
        self.assertEqual(self.printer_a.status, "online")

        self.assertEqual(
            {(x.metric, x.value) for x in SnmpReading.objects.all()},
            {("toner.black", 42.0), ("pages.total", 15234.0)},
        )

    def test_unreachable_device_records_the_error_and_stays_offline(self):
        r = self.client.post(
            f"{BASE}/probe/{self.probe.agent_id}/devices/",
            [{"id": self.printer_a.pk, "reachable": False, "error": "timeout"}],
            format="json",
        )
        self.assertEqual(r.status_code, 200)

        self.printer_a.refresh_from_db()
        self.assertEqual(self.printer_a.last_error, "timeout")
        self.assertIsNone(self.printer_a.last_seen)
        self.assertEqual(self.printer_a.status, "pending")

    def test_probe_cannot_write_readings_for_another_site(self):
        r = self.client.post(
            f"{BASE}/probe/{self.probe.agent_id}/devices/",
            [{"id": self.printer_b.pk, "reachable": True, "metrics": {"x": 1.0}}],
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(SnmpReading.objects.count(), 0)
        self.printer_b.refresh_from_db()
        self.assertIsNone(self.printer_b.last_seen)

    def test_ingest_is_atomic(self):
        """One bad id must not let the good ones through half-applied."""
        self.client.post(
            f"{BASE}/probe/{self.probe.agent_id}/devices/",
            [
                {"id": self.printer_a.pk, "reachable": True, "metrics": {"a": 1.0}},
                {"id": self.printer_b.pk, "reachable": True, "metrics": {"b": 2.0}},
            ],
            format="json",
        )
        self.assertEqual(SnmpReading.objects.count(), 0)
        self.printer_a.refresh_from_db()
        self.assertIsNone(self.printer_a.last_seen)

    def test_ingest_rejects_unbounded_or_invalid_metrics(self):
        """A buggy or compromised probe must get a 400, not a 500 or silent bloat."""
        cases = {
            "metric name too long": {"x" * 101: 1.0},
            # DRF's json parser accepts NaN; a stored NaN breaks the dashboard later
            "nan value": {"supply.black": float("nan")},
            "infinity value": {"supply.black": float("inf")},
            "too many metrics": {f"m{i}": 1.0 for i in range(65)},
        }
        for label, metrics in cases.items():
            with self.subTest(case=label):
                # raw json: the test client's own encoder refuses NaN, which is
                # exactly the leniency under test on the parsing side
                r = self.client.post(
                    f"{BASE}/probe/{self.probe.agent_id}/devices/",
                    json.dumps(
                        [{"id": self.printer_a.pk, "reachable": True, "metrics": metrics}]
                    ),
                    content_type="application/json",
                )
                self.assertEqual(r.status_code, 400)
        self.assertEqual(SnmpReading.objects.count(), 0)


class TestThresholdAlerting(TacticalTestCase):
    """Alerts must follow state changes, not fire once per poll."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")
        self.probe = baker.make_recipe("agents.agent", site=self.site)
        self.printer = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site, name="Drucker", device_type="printer"
        )

    def _ingest(self, metrics=None, reachable=True):
        return self.client.post(
            f"{BASE}/probe/{self.probe.agent_id}/devices/",
            [{"id": self.printer.pk, "reachable": reachable, "metrics": metrics or {}}],
            format="json",
        )

    def _open_alerts(self):
        return SnmpAlert.objects.filter(device=self.printer)

    def test_default_thresholds_apply_to_any_supply_colour(self):
        # "supply." is a prefix rule, so a colour nobody configured still alerts
        r = self._ingest({"supply.magenta": 8.0})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data["alerts"]), 1)
        self.assertEqual(self._open_alerts().get().severity, "error")

    def test_repeated_polls_below_the_threshold_do_not_realert(self):
        self._ingest({"supply.black": 8.0})
        r = self._ingest({"supply.black": 7.0})
        self.assertEqual(r.data["alerts"], [], "an unchanged state must stay quiet")
        self.assertEqual(self._open_alerts().count(), 1)

    def test_severity_change_raises_again(self):
        self._ingest({"supply.black": 15.0})
        self.assertEqual(self._open_alerts().get().severity, "warning")
        r = self._ingest({"supply.black": 5.0})
        self.assertEqual(len(r.data["alerts"]), 1)
        self.assertEqual(self._open_alerts().get().severity, "error")
        self.assertEqual(self._open_alerts().count(), 1, "no duplicate for one metric")

    def test_recovery_resolves_the_alert(self):
        self._ingest({"supply.black": 5.0})
        alert = self._open_alerts().get().alert
        self._ingest({"supply.black": 80.0})
        self.assertFalse(self._open_alerts().exists())
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)

    def test_per_device_thresholds_override_the_type_default(self):
        self.printer.thresholds = {"supply.black": {"warning": 90, "error": 85}}
        self.printer.save()
        r = self._ingest({"supply.black": 88.0})
        self.assertEqual(self._open_alerts().get().severity, "warning")
        self.assertEqual(len(r.data["alerts"]), 1)

    def test_unreachable_raises_once_and_leaves_supply_alerts_alone(self):
        self._ingest({"supply.black": 5.0})
        r = self._ingest(reachable=False)
        self.assertEqual(len(r.data["alerts"]), 1)
        # a silent device says nothing about its toner
        self.assertEqual(
            set(self._open_alerts().values_list("metric", flat=True)),
            {"supply.black", "__unreachable__"},
        )
        r = self._ingest(reachable=False)
        self.assertEqual(r.data["alerts"], [])

        self._ingest({"supply.black": 5.0})
        self.assertEqual(
            set(self._open_alerts().values_list("metric", flat=True)), {"supply.black"}
        )

    def test_metrics_without_a_threshold_are_ignored(self):
        r = self._ingest({"pages.total": 15234.0})
        self.assertEqual(r.data["alerts"], [])
        self.assertFalse(self._open_alerts().exists())


class TestThresholdValidation(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")

    def _post(self, thresholds):
        return self.client.post(
            f"{BASE}/devices/",
            {"site": self.site.pk, "name": "D", "ip": "10.0.0.5", "thresholds": thresholds},
            format="json",
        )

    def test_valid(self):
        good = {"supply.": {"warning": 20, "error": 10, "direction": "below"}}
        r = self._post(good)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(SnmpDevice.objects.get(pk=r.data["id"]).thresholds, good)

    def test_rejected(self):
        cases = {
            "no level": {"a": {"direction": "below"}},
            "level not numeric": {"a": {"warning": "viel"}},
            "level is null": {"a": {"warning": None}},
            "bad direction": {"a": {"warning": 1, "direction": "sideways"}},
            "unknown key": {"a": {"warning": 1, "colour": "red"}},
            "entry not object": {"a": 5},
        }
        for label, bad in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self._post(bad).status_code, 400)


class TestDiscoverSnmpDevice(TacticalTestCase):
    """The form's "Erkennen" button: the same walk the discover_snmp_device MCP
    tool does, but reachable from the dashboard without an assistant in the loop."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")
        self.agent = baker.make_recipe("agents.online_agent", site=self.site)

    def _post(self, **overrides):
        return self.client.post(
            f"{BASE}/discover/",
            {"site": self.site.pk, "ip": "10.0.0.10", **overrides},
            format="json",
        )

    def test_not_authenticated(self):
        self.check_not_authenticated("post", f"{BASE}/discover/")

    def test_write_permission_is_required(self):
        user = self.create_user_with_roles(["can_list_sites"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self._post().status_code, 403)

    def test_run_scripts_permission_is_required(self):
        """Discovery executes code on an agent, so site management alone must not
        be enough - same bar as the upstream runscript endpoints."""
        user = self.create_user_with_roles(["can_list_sites", "can_manage_sites"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self._post().status_code, 403)

    def test_foreign_site_is_rejected(self):
        other_client = baker.make("clients.Client")
        baker.make("clients.Site", client=other_client)
        user = self.create_user_with_roles(["can_list_sites", "can_manage_sites"])
        user.role.can_view_clients.set([other_client])
        self.client.force_authenticate(user=user)
        self.assertEqual(self._post().status_code, 403)

    def test_no_online_agent_at_the_site(self):
        self.agent.last_seen = None
        self.agent.save()
        r = self._post()
        self.assertEqual(r.status_code, 400)

    @patch("agents.models.Agent.nats_cmd")
    def test_walk_returns_the_suggestion(self, nats_cmd):
        dump = {
            "host": "10.0.0.10",
            "sys_descr": "HP LaserJet",
            "suggested_metric_map": {
                "supply.black": {"oid": "1.3.6.1.43.11.1.1.9.1.1", "max_oid": "1.3.6.1.43.11.1.1.8.1.1"},
            },
        }
        nats_cmd.return_value = {"stdout": json.dumps(dump), "stderr": "", "retcode": 0}

        r = self._post()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["suggested_metric_map"], dump["suggested_metric_map"])

        data = nats_cmd.call_args.args[0]
        self.assertEqual(data["func"], "runscriptfull")
        self.assertEqual(
            data["script_args"], ["--dump", "10.0.0.10", "--community", "public", "--port", "161"]
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_masked_community_means_the_stored_one(self, nats_cmd):
        """The edit form only ever sees the masked community; sending it back must
        probe with the real one, not with the bullets."""
        device = baker.make(
            "qdt_snmp.SnmpDevice", site=self.site, community="secret-a"
        )
        nats_cmd.return_value = {"stdout": "{}", "stderr": "", "retcode": 0}

        r = self._post(community="••••et-a", device=device.pk)
        self.assertEqual(r.status_code, 200)
        data = nats_cmd.call_args.args[0]
        self.assertIn("secret-a", data["script_args"])

    @patch("agents.models.Agent.nats_cmd")
    def test_probe_failure_surfaces_the_error(self, nats_cmd):
        nats_cmd.return_value = {"stdout": "", "stderr": "snmp timeout", "retcode": 1}
        r = self._post()
        self.assertEqual(r.status_code, 400)

    @patch("agents.models.Agent.nats_cmd", return_value="timeout")
    def test_agent_timeout_is_a_400_not_a_hang(self, nats_cmd):
        self.assertEqual(self._post().status_code, 400)

    def test_malformed_port_is_rejected(self):
        self.assertEqual(self._post(port="abc").status_code, 400)

    def test_ip_must_be_a_host_not_an_argument(self):
        """The ip lands in the probe's argv; anything else is rejected at the door."""
        for bad in ("--community", "not a host!", "{{agent.x}}", "-e"):
            with self.subTest(ip=bad):
                self.assertEqual(self._post(ip=bad).status_code, 400)

    @patch("agents.models.Agent.nats_cmd")
    def test_a_hostname_is_accepted(self, nats_cmd):
        nats_cmd.return_value = {"stdout": "{}", "stderr": "", "retcode": 0}
        r = self._post(ip="drucker.office.example")
        self.assertEqual(r.status_code, 200)
        data = nats_cmd.call_args.args[0]
        self.assertIn("drucker.office.example", data["script_args"])

    def test_community_must_not_look_like_a_flag(self):
        self.assertEqual(self._post(community="-x").status_code, 400)

    @patch("agents.models.Agent.nats_cmd")
    def test_parallel_probe_runs_per_user_are_rejected(self, nats_cmd):
        """Each run can hold a web worker for two minutes; piling up is a DoS."""
        from django.core.cache import cache

        cache.add(f"qdt-snmp-probe-lock-{self.john.pk}", 1, timeout=60)
        try:
            self.assertEqual(self._post().status_code, 400)
        finally:
            cache.delete(f"qdt-snmp-probe-lock-{self.john.pk}")

        # and a finished run releases its lock, so the next one goes through
        nats_cmd.return_value = {"stdout": "{}", "stderr": "", "retcode": 0}
        self.assertEqual(self._post().status_code, 200)
        self.assertEqual(self._post().status_code, 200)


class TestScanSnmpSubnet(TacticalTestCase):
    """Subnet scans from the probe agent: same bar as discovery, since both send
    packets from inside the customer's LAN."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")
        self.agent = baker.make_recipe("agents.online_agent", site=self.site)

    def _post(self, **overrides):
        return self.client.post(
            f"{BASE}/scan/",
            {"site": self.site.pk, "cidr": "10.0.0.0/29", **overrides},
            format="json",
        )

    def test_not_authenticated(self):
        self.check_not_authenticated("post", f"{BASE}/scan/")

    def test_permissions(self):
        for roles in (["can_list_sites"], ["can_list_sites", "can_manage_sites"]):
            with self.subTest(roles=roles):
                user = self.create_user_with_roles(roles)
                self.client.force_authenticate(user=user)
                self.assertEqual(self._post().status_code, 403)

    def test_invalid_or_oversized_cidr_is_rejected(self):
        self.assertEqual(self._post(cidr="not-a-subnet").status_code, 400)
        self.assertEqual(self._post(cidr="10.0.0.0/16").status_code, 400)

    def test_community_must_not_look_like_a_flag(self):
        self.assertEqual(self._post(community="-x").status_code, 400)

    def test_no_online_agent_is_a_400(self):
        self.agent.last_seen = None
        self.agent.save()
        self.assertEqual(self._post().status_code, 400)

    @patch("agents.models.Agent.nats_cmd")
    def test_scan_returns_the_responders(self, nats_cmd):
        responders = [
            {"ip": "10.0.0.5", "sys_descr": "HP LaserJet", "sys_name": "drucker1"},
            {"ip": "10.0.0.6", "sys_descr": "APC UPS", "sys_name": None},
        ]
        nats_cmd.return_value = {"stdout": json.dumps(responders), "stderr": "", "retcode": 0}

        r = self._post(community="secret")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, responders)

        data = nats_cmd.call_args.args[0]
        self.assertEqual(
            data["script_args"],
            ["--scan", "10.0.0.0/29", "--community", "secret", "--port", "161"],
        )

        # the community must not land in the audit log in the clear
        from logs.models import AuditLog

        entry = AuditLog.objects.order_by("-id").first()
        self.assertNotIn("secret", str(entry.before_value))


@patch("qdt_snmp.provisioning.create_win_task_schedule")
class TestProbeProvisioning(TacticalTestCase):
    """The first device at a site must not mean four manual setup steps."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")
        self.agent = baker.make_recipe("agents.online_agent", site=self.site)

    def _post(self, site_id=None):
        return self.client.post(f"{BASE}/sites/{site_id or self.site.pk}/probe/")

    def test_provisions_script_key_and_task(self, sched):
        r = self._post()
        self.assertEqual(r.status_code, 200)

        from accounts.models import APIKey
        from autotasks.models import AutomatedTask
        from core.models import GlobalKVStore
        from scripts.models import Script

        script = Script.objects.get(name="QDT SNMP Poller", category="QDT")
        self.assertEqual(script.shell, "python")
        self.assertIn("SNMP poller", script.script_body)

        store = GlobalKVStore.objects.get(name="snmp_api_key")
        api_key = APIKey.objects.get(name="snmp-probe")
        self.assertEqual(store.value, api_key.key)

        # the key belongs to a minimal service user, not to the provisioning admin:
        # it may read sites and post readings, nothing else
        service = api_key.user
        self.assertEqual(service.username, "snmp-probe")
        self.assertTrue(service.block_dashboard_login)
        self.assertFalse(service.has_usable_password())
        self.assertTrue(service.role.can_list_sites)
        self.assertFalse(service.role.is_superuser)
        self.assertFalse(service.role.can_run_scripts)

        task = AutomatedTask.objects.get(name="QDT SNMP Poller", agent=self.agent)
        self.assertEqual(task.task_type, "daily")
        self.assertEqual(task.task_repetition_interval, "5M")
        self.assertEqual(task.task_repetition_duration, "1D")
        self.assertEqual(
            task.actions[0]["script_args"],
            [
                "--url",
                "http://testserver",
                "--agent-id",
                "{{agent.agent_id}}",
                "--api-key",
                "{{global.snmp_api_key}}",
            ],
        )
        self.assertEqual(task.actions[0]["script"], script.pk)
        sched.delay.assert_called_once_with(pk=task.pk)

        # and the status endpoint reports all of it
        r = self.client.get(f"{BASE}/sites/{self.site.pk}/probe/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            {
                "script": True,
                "api_key": True,
                "online_agent": self.agent.hostname,
                "task": {"enabled": True, "agent": self.agent.hostname},
            },
        )

    def test_is_idempotent_and_refreshes_a_stale_script(self, sched):
        from scripts.models import Script

        self._post()
        script = Script.objects.get(name="QDT SNMP Poller")
        script.script_body = "hand edited, now stale"
        script.save()

        r = self._post()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Script.objects.filter(name="QDT SNMP Poller").count(), 1)
        script.refresh_from_db()
        self.assertNotEqual(script.script_body, "hand edited, now stale")

        from autotasks.models import AutomatedTask

        self.assertEqual(AutomatedTask.objects.count(), 1)

    def test_rehomes_the_task_when_its_agent_went_away(self, sched):
        from autotasks.models import AutomatedTask

        self._post()
        # the original probe agent falls silent
        self.agent.last_seen = None
        self.agent.save()
        probe2 = baker.make_recipe("agents.online_agent", site=self.site)

        r = self._post()
        self.assertEqual(r.status_code, 200)
        task = AutomatedTask.objects.get(name="QDT SNMP Poller")
        self.assertEqual(task.agent, probe2)

    def test_no_online_agent_is_a_400(self, sched):
        self.agent.last_seen = None
        self.agent.save()
        self.assertEqual(self._post().status_code, 400)
        sched.delay.assert_not_called()

    def test_permissions(self, sched):
        user = self.create_user_with_roles(["can_list_sites"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self._post().status_code, 403)

        # scheduling code execution on an agent wants more than site management
        user = self.create_user_with_roles(["can_list_sites", "can_manage_sites"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self._post().status_code, 403)

        # a foreign site is out of scope even with all the right permissions
        other_client = baker.make("clients.Client")
        baker.make("clients.Site", client=other_client)
        user = self.create_user_with_roles(
            ["can_list_sites", "can_manage_sites", "can_run_scripts"]
        )
        user.role.can_view_clients.set([other_client])
        self.client.force_authenticate(user=user)
        self.assertEqual(self._post().status_code, 403)

    def test_adding_the_first_device_provisions_the_site(self, sched):
        from autotasks.models import AutomatedTask

        r = self.client.post(
            f"{BASE}/devices/",
            {"site": self.site.pk, "name": "Drucker", "ip": "10.0.0.10"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("probe_warning", r.data)
        self.assertEqual(AutomatedTask.objects.count(), 1)
        sched.delay.assert_called_once()

        # the second device at the same site does not reprovision
        r = self.client.post(
            f"{BASE}/devices/",
            {"site": self.site.pk, "name": "Drucker 2", "ip": "10.0.0.11"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(AutomatedTask.objects.count(), 1)

    def test_device_creation_without_online_agent_still_works(self, sched):
        self.agent.last_seen = None
        self.agent.save()
        r = self.client.post(
            f"{BASE}/devices/",
            {"site": self.site.pk, "name": "Drucker", "ip": "10.0.0.10"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn("probe_warning", r.data)
        sched.delay.assert_not_called()

    def test_device_creation_without_run_scripts_warns_instead_of_provisioning(
        self, sched
    ):
        """The device is created either way, but only a user with script rights
        gets an automatic poller."""
        user = self.create_user_with_roles(["can_list_sites", "can_manage_sites"])
        self.client.force_authenticate(user=user)
        r = self.client.post(
            f"{BASE}/devices/",
            {"site": self.site.pk, "name": "Drucker", "ip": "10.0.0.10"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn("can_run_scripts", r.data["probe_warning"])
        sched.delay.assert_not_called()


class TestFleetEndpoints(TacticalTestCase):
    """The list page needs fleet-wide data without one request per device."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.client_a = baker.make("clients.Client")
        self.client_b = baker.make("clients.Client")
        self.device_a = baker.make(
            "qdt_snmp.SnmpDevice", site=baker.make("clients.Site", client=self.client_a)
        )
        self.device_b = baker.make(
            "qdt_snmp.SnmpDevice", site=baker.make("clients.Site", client=self.client_b)
        )

        from django.utils import timezone as djangotime

        old = baker.make(
            "qdt_snmp.SnmpReading", device=self.device_a, metric="supply.black", value=50.0
        )
        new = baker.make(
            "qdt_snmp.SnmpReading", device=self.device_a, metric="supply.black", value=30.0
        )
        baker.make("qdt_snmp.SnmpReading", device=self.device_b, metric="supply.cyan", value=80.0)
        # make the order unambiguous instead of relying on insert timing
        SnmpReading.objects.filter(pk=old.pk).update(
            timestamp=djangotime.now() - djangotime.timedelta(hours=1)
        )
        SnmpReading.objects.filter(pk=new.pk).update(timestamp=djangotime.now())

    def _scoped_user(self, client):
        user = self.create_user_with_roles(["can_list_sites"])
        user.role.can_view_clients.set([client])
        return user

    def test_latest_returns_only_the_newest_sample_per_metric(self):
        r = self.client.get(f"{BASE}/latest/")
        self.assertEqual(r.status_code, 200)
        # r.data is the pre-render python object, so the keys are still ints
        self.assertEqual(r.data[self.device_a.pk]["supply.black"]["value"], 30.0)

    def test_latest_is_role_scoped(self):
        self.client.force_authenticate(user=self._scoped_user(self.client_a))
        r = self.client.get(f"{BASE}/latest/")
        self.assertIn(self.device_a.pk, r.data)
        self.assertNotIn(self.device_b.pk, r.data)

    def test_open_alerts_are_role_scoped(self):
        baker.make("qdt_snmp.SnmpAlert", device=self.device_a, metric="supply.black", severity="error")
        baker.make("qdt_snmp.SnmpAlert", device=self.device_b, metric="supply.cyan", severity="warning")

        r = self.client.get(f"{BASE}/alerts/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 2)
        self.assertEqual(r.data[0]["metric"], "supply.black")
        self.assertIn("device_name", r.data[0])

        self.client.force_authenticate(user=self._scoped_user(self.client_a))
        r = self.client.get(f"{BASE}/alerts/")
        self.assertEqual([a["metric"] for a in r.data], ["supply.black"])

    def test_read_permission_is_required(self):
        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(f"{BASE}/latest/").status_code, 403)
        self.assertEqual(self.client.get(f"{BASE}/alerts/").status_code, 403)


class TestSnmpDeviceCounters(TacticalTestCase):
    """Monthly page counts for billing, robust against counter resets."""

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.device = baker.make("qdt_snmp.SnmpDevice")

    def _reading(self, year, month, day, value):
        reading = baker.make(
            "qdt_snmp.SnmpReading", device=self.device, metric="pages.total", value=value
        )
        SnmpReading.objects.filter(pk=reading.pk).update(
            timestamp=djangotime.datetime(year, month, day, tzinfo=djangotime.utc)
        )

    def test_monthly_deltas_use_the_last_reading_of_each_month(self):
        self._reading(2026, 5, 31, 1000.0)
        self._reading(2026, 6, 10, 1500.0)
        self._reading(2026, 6, 30, 1600.0)
        self._reading(2026, 7, 15, 500.0)  # counter reset

        r = self.client.get(f"{BASE}/devices/{self.device.pk}/counters/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            [
                {"month": "2026-05", "counter": 1000.0, "pages": None, "reset": False},
                {"month": "2026-06", "counter": 1600.0, "pages": 600, "reset": False},
                {"month": "2026-07", "counter": 500.0, "pages": None, "reset": True},
            ],
        )

    def test_scoped_user_gets_no_counters(self):
        other_client = baker.make("clients.Client")
        baker.make("clients.Site", client=other_client)
        user = self.create_user_with_roles(["can_list_sites"])
        user.role.can_view_clients.set([other_client])
        self.client.force_authenticate(user=user)
        r = self.client.get(f"{BASE}/devices/{self.device.pk}/counters/")
        self.assertEqual(r.status_code, 403)


class TestSnmpReadingPrune(TacticalTestCase):
    def test_prune_removes_only_old_readings(self):
        from django.utils import timezone as djangotime

        device = baker.make("qdt_snmp.SnmpDevice")
        old = baker.make("qdt_snmp.SnmpReading", device=device, metric="t", value=1.0)
        baker.make("qdt_snmp.SnmpReading", device=device, metric="t", value=2.0)

        # timestamp is auto_now_add, so it has to be pushed back explicitly
        SnmpReading.objects.filter(pk=old.pk).update(
            timestamp=djangotime.now() - djangotime.timedelta(days=200)
        )

        self.assertEqual(SnmpReading.prune(days=90), 1)
        self.assertEqual(SnmpReading.objects.count(), 1)

    @patch("qdt_snmp.tasks.redis_lock")
    def test_celery_task_runs_the_prune(self, lock):
        lock.return_value.__enter__.return_value = True

        from qdt_snmp.tasks import prune_old_readings

        device = baker.make("qdt_snmp.SnmpDevice")
        baker.make("qdt_snmp.SnmpReading", device=device, metric="t", value=1.0)

        self.assertEqual(prune_old_readings(), "pruned 0")
