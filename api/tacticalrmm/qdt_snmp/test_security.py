import importlib
from types import SimpleNamespace
from unittest.mock import patch

from django.apps import apps
from django.db import connection
from model_bakery import baker
from rest_framework.test import APIClient

from accounts.models import APIKey
from core.models import GlobalKVStore
from scripts.models import Script
from tacticalrmm.test import TacticalTestCase

from .models import SnmpProbeCredential, SnmpReading
from .provisioning import ensure_probe_for_site


class TestProbeIsolation(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site_a = baker.make("clients.Site")
        self.site_b = baker.make("clients.Site")
        self.agent_a = baker.make_recipe("agents.online_agent", site=self.site_a)
        self.agent_b = baker.make_recipe("agents.online_agent", site=self.site_b)
        self.device_a = baker.make("qdt_snmp.SnmpDevice", site=self.site_a)
        self.device_b = baker.make("qdt_snmp.SnmpDevice", site=self.site_b)
        self.credential = SnmpProbeCredential.objects.create(
            site=self.site_a, agent=self.agent_a
        )
        self.client = APIClient()
        self.client.credentials(HTTP_X_API_KEY=self.credential.key)

    def endpoint(self, agent):
        return f"/qdt_snmp/probe/{agent.agent_id}/devices/"

    def test_bound_probe_can_read_secrets_and_submit_own_readings(self):
        response = self.client.get(self.endpoint(self.agent_a))
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["id"] for row in response.data], [self.device_a.pk])
        self.assertEqual(response.data[0]["community"], self.device_a.community)
        response = self.client.post(
            self.endpoint(self.agent_a),
            [{"id": self.device_a.pk, "reachable": True, "metrics": {"pages": 12}}],
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(SnmpReading.objects.get().device_id, self.device_a.pk)

    def test_probe_cannot_select_another_site_by_changing_agent_id(self):
        self.assertEqual(self.client.get(self.endpoint(self.agent_b)).status_code, 403)
        response = self.client.post(
            self.endpoint(self.agent_b),
            [{"id": self.device_b.pk, "reachable": True, "metrics": {"pages": 999}}],
            format="json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(SnmpReading.objects.exists())
        self.device_b.refresh_from_db()
        self.assertIsNone(self.device_b.last_seen)

    def test_probe_cannot_select_another_agent_at_the_same_site(self):
        other = baker.make_recipe("agents.agent", site=self.site_a)
        self.assertEqual(self.client.get(self.endpoint(other)).status_code, 403)

    def test_moving_agent_to_another_site_invalidates_credential(self):
        self.agent_a.site = self.site_b
        self.agent_a.save(update_fields=["site"])
        self.assertEqual(self.client.get(self.endpoint(self.agent_a)).status_code, 401)
        self.assertIsNone(self.agent_a.snmp_probe_key)

    def test_unknown_missing_and_malformed_keys_fail_closed(self):
        for key in ("", "bad", "f" * 64):
            with self.subTest(key_length=len(key)):
                self.client.credentials(HTTP_X_API_KEY=key)
                self.assertEqual(
                    self.client.get(self.endpoint(self.agent_a)).status_code, 401
                )

    def test_regular_user_and_admin_api_keys_cannot_use_probe_endpoint(self):
        reader = self.create_user_with_roles(["can_list_sites"])
        reader.role.can_view_sites.add(self.site_a)
        for user in (reader, self.john):
            key = baker.make(
                "accounts.APIKey", user=user, key=("a" if user == reader else "b") * 32
            )
            self.client.credentials(HTTP_X_API_KEY=key.key)
            with self.subTest(user=user.pk):
                self.assertEqual(
                    self.client.get(self.endpoint(self.agent_a)).status_code, 401
                )
                self.assertEqual(
                    self.client.post(
                        self.endpoint(self.agent_a), [], format="json"
                    ).status_code,
                    401,
                )

    def test_forced_dashboard_identity_is_not_a_probe(self):
        reader = self.create_user_with_roles(["can_list_sites"])
        self.client.force_authenticate(user=reader)
        self.assertEqual(self.client.get(self.endpoint(self.agent_a)).status_code, 403)
        self.assertEqual(
            self.client.post(
                self.endpoint(self.agent_a), [], format="json"
            ).status_code,
            403,
        )

    def test_probe_key_is_not_a_general_rmm_api_key(self):
        self.assertEqual(self.client.get("/clients/").status_code, 401)

    def test_deleted_credential_is_revoked(self):
        self.credential.delete()
        self.assertEqual(self.client.get(self.endpoint(self.agent_a)).status_code, 401)

    @patch("qdt_snmp.provisioning.create_win_task_schedule")
    def test_each_site_has_a_different_key_and_task_stores_only_template(
        self, schedule
    ):
        for site in (self.site_a, self.site_b):
            with self.captureOnCommitCallbacks(execute=True):
                ensure_probe_for_site(site=site, api_url="https://api.example.com")
        second = SnmpProbeCredential.objects.get(site=self.site_b)
        self.assertNotEqual(second.key, self.credential.key)
        from autotasks.models import AutomatedTask

        for task in AutomatedTask.objects.filter(name="QDT SNMP Poller"):
            self.assertIn("{{agent.snmp_probe_key}}", task.actions[0]["script_args"])
            self.assertNotIn(self.credential.key, str(task.actions))
            self.assertNotIn(second.key, str(task.actions))
        self.assertFalse(GlobalKVStore.objects.filter(name="snmp_api_key").exists())

    @patch("qdt_snmp.provisioning.create_win_task_schedule")
    def test_rehoming_probe_rotates_key_and_revokes_retired_agent(self, schedule):
        with self.captureOnCommitCallbacks(execute=True):
            ensure_probe_for_site(site=self.site_a, api_url="https://api.example.com")
        old_key = self.credential.key
        self.agent_a.last_seen = None
        self.agent_a.save(update_fields=["last_seen"])
        replacement = baker.make_recipe("agents.online_agent", site=self.site_a)
        with self.captureOnCommitCallbacks(execute=True):
            ensure_probe_for_site(site=self.site_a, api_url="https://api.example.com")
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.agent_id, replacement.pk)
        self.assertNotEqual(self.credential.key, old_key)
        self.assertEqual(self.client.get(self.endpoint(self.agent_a)).status_code, 401)
        self.assertIsNone(self.agent_a.snmp_probe_key)
        self.client.credentials(HTTP_X_API_KEY=self.credential.key)
        self.assertEqual(self.client.get(self.endpoint(replacement)).status_code, 200)

    def test_template_resolves_only_key_of_execution_agent(self):
        from tacticalrmm.constants import ScriptShell

        own = Script.parse_script_args(
            self.agent_a, ScriptShell.PYTHON, ["{{agent.snmp_probe_key}}"]
        )
        other = Script.parse_script_args(
            self.agent_b, ScriptShell.PYTHON, ["{{agent.snmp_probe_key}}"]
        )
        self.assertIn(self.credential.key, own[0])
        self.assertNotIn(self.credential.key, str(other))


class TestLegacyProbeMigration(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_existing_tasks_are_rekeyed_and_shared_credentials_revoked(self):
        from autotasks.models import AutomatedTask

        named_key = baker.make(
            "accounts.APIKey",
            name="snmp-probe",
            user=self.john,
            key="legacy-probe-test-key",
        )
        shared_admin_key = baker.make(
            "accounts.APIKey", user=self.john, key="shared-admin-test-key"
        )
        unrelated_key = baker.make(
            "accounts.APIKey", user=self.john, key="unrelated-test-key"
        )
        GlobalKVStore.objects.create(name="snmp_api_key", value=shared_admin_key.key)
        GlobalKVStore.objects.create(name="unrelated", value="keep-me")
        script = baker.make("scripts.Script", name="QDT SNMP Poller", category="QDT")
        agents = [baker.make_recipe("agents.agent") for _ in range(2)]
        for agent in agents:
            baker.make(
                "autotasks.AutomatedTask",
                agent=agent,
                name="QDT SNMP Poller",
                actions=[
                    {
                        "type": "script",
                        "script": script.pk,
                        "script_args": ["--api-key", "{{global.snmp_api_key}}"],
                    }
                ],
            )

        migration = importlib.import_module(
            "qdt_snmp.migrations.0004_probe_credentials"
        )
        migration.migrate_pollers(apps, SimpleNamespace(connection=connection))
        keys = set()
        for task in AutomatedTask.objects.filter(name="QDT SNMP Poller"):
            credential = SnmpProbeCredential.objects.get(site=task.agent.site)
            self.assertEqual(credential.agent_id, task.agent_id)
            self.assertEqual(
                task.actions[0]["script_args"][-1], "{{agent.snmp_probe_key}}"
            )
            keys.add(credential.key)
        self.assertEqual(len(keys), 2)
        self.assertFalse(
            APIKey.objects.filter(pk__in=[named_key.pk, shared_admin_key.pk]).exists()
        )
        self.assertTrue(APIKey.objects.filter(pk=unrelated_key.pk).exists())
        self.assertFalse(GlobalKVStore.objects.filter(name="snmp_api_key").exists())
        self.assertEqual(GlobalKVStore.objects.get(name="unrelated").value, "keep-me")
        migration.migrate_pollers(apps, SimpleNamespace(connection=connection))
        self.assertEqual(
            set(SnmpProbeCredential.objects.values_list("key", flat=True)), keys
        )
