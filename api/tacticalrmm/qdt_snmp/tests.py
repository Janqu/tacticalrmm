from model_bakery import baker

from tacticalrmm.test import TacticalTestCase

from .models import SnmpDevice, SnmpReading

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
