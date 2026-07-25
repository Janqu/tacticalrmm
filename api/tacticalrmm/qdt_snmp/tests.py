from model_bakery import baker

from tacticalrmm.test import TacticalTestCase

from .models import SnmpAlert, SnmpDevice, SnmpReading

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
            "unknown key": {"a": {"oid": "1.3.6", "multiply": 2}},
        }
        for label, bad in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self._post(bad).status_code, 400)

    def test_empty_map_is_allowed_and_means_use_the_builtin_profile(self):
        r = self._post({})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(SnmpDevice.objects.get(pk=r.data["id"]).metric_map, {})


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
            "bad direction": {"a": {"warning": 1, "direction": "sideways"}},
            "unknown key": {"a": {"warning": 1, "colour": "red"}},
            "entry not object": {"a": 5},
        }
        for label, bad in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self._post(bad).status_code, 400)


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
