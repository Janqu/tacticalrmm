"""Patch policy CRUD serializer, audit, scope and rollback contracts."""
import hashlib
import json
from datetime import datetime, timezone


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from automation.models import Policy
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.core.management.color import no_style
    from django.db import connection
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdatePolicy

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)

    def setup(scope="all"):
        WinUpdatePolicy.objects.all().delete()
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        seed()
        Role.objects.filter(pk=1).update(can_manage_automation_policies=scope != "denied")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "scoped":
            role.can_view_sites.add(1)
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
        Client.objects.bulk_create([Client(id=91, name="Other")])
        Site.objects.bulk_create([Site(id=91, client_id=91, name="Other")])
        Agent.objects.bulk_create([Agent(id=91, agent_id="patch-policy-agent-one-0001", hostname="Local", site_id=1),
                                   Agent(id=92, agent_id="patch-policy-agent-two-0002", hostname="Other", site_id=91)])
        Policy.objects.bulk_create([Policy(id=91, name="Patch policy"), Policy(id=92, name="Second")])
        WinUpdatePolicy.objects.bulk_create([WinUpdatePolicy(id=91, policy_id=91),
                                             WinUpdatePolicy(id=92, agent_id=91),
                                             WinUpdatePolicy(id=93, agent_id=92)])
        WinUpdatePolicy.objects.update(created_time=fixed, modified_time=fixed)
        with connection.cursor() as cursor:
            for sql in connection.ops.sequence_reset_sql(no_style(), [WinUpdatePolicy]):
                cursor.execute(sql)
        cache.clear()

    def state():
        rows = list(WinUpdatePolicy.objects.order_by("id").values())
        for row in rows:
            for field in ["created_time", "modified_time"]:
                value = row[field]
                if value is not None and value != fixed:
                    assert abs((value - datetime.now(timezone.utc)).total_seconds()) < 10
                    row[field] = "current timestamp"
        return rows, snapshot()

    def without_auth(value):
        return value[0], {k: v for k, v in value[1].items() if k != "tokens"}

    base = "/automation/patchpolicy/"
    count = 0

    def compare(method, path, data, scope="all", user=1, safer=False):
        setup(scope)
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        response = client.generic(method, path, data=json.dumps(data) if data is not None else "", content_type="application/json")
        expected = (response.status_code, json.loads(response.content) if response.content and response.status_code < 500 else None)
        expected_state = state()
        setup(scope)
        baseline = state()
        actual = go_request(method, path, data, user_id=user)
        if safer:
            assert actual[0] == 400, (method, path, data, expected, actual)
            assert without_auth(state()) == without_auth(baseline)
        else:
            assert actual == expected, (method, path, data, expected, actual)
            assert state() == expected_state, (method, path, data, "database/audit mismatch", expected_state, state())

    try:
        for scope, user in [("all", 1), ("all", 5), ("all", 2), ("denied", 2), ("all", 3), ("all", 4), ("installer", 6)]:
            for method, path, data in [("POST", base, {"policy": 91}),
                                       ("PUT", base + "91/", {"critical": "approve"}),
                                       ("DELETE", base + "91/", None)]:
                compare(method, path, data, scope, user)
                count += 1
        writes = [
            ("POST", base, {"policy": 91, "agent": 91, "run_time_days": [0, "2", "-3.0"]}),
            ("POST", base, {"policy": 999}),
            ("POST", base, {"policy": 91, "agent": 999}),
            ("POST", base, {"policy": 91, "critical": "manual", "important": "approve", "moderate": "ignore", "low": "inherit", "other": "manual", "run_time_hour": "23", "run_time_day": 31, "run_time_frequency": "monthly", "reboot_after_install": "required", "run_time_days": None}),
            ("POST", base, {"policy": 91, "created_by": "Custom", "modified_by": "Custom", "created_time": "bad", "modified_time": "ignored", "id": 91}),
            ("PUT", base + "91/", {}),
            ("PUT", base + "91/", {"critical": "inherit"}),
            ("PUT", base + "91/", {"run_time_days": [], "reprocess_failed_inherit": False, "reprocess_failed": "true", "email_if_fail": 1, "reprocess_failed_times": "8.0"}),
            ("PUT", base + "91/", {"policy": 92}),
            ("PUT", base + "92/", {"agent": 92, "policy": 91}),
            ("PUT", base + "92/", {"agent": None, "policy": 91}),
            ("PUT", base + "91/", {"critical": None, "run_time_day": 32, "run_time_hour": -1, "run_time_days": [None, True, "bad"], "policy": 999}),
            ("PUT", base + "91/", {"run_time_days": [2147483647, -2147483648]}),
            ("PUT", base + "91/", {"run_time_days": [-2147483649, 2147483648]}),
            ("PUT", base + "91/", {"run_time_days": "Monday", "reprocess_failed_times": -1}),
            ("PUT", base + "91/", {"created_by": None, "modified_by": "changed"}),
            ("PUT", base + "999/", {}),
            ("DELETE", base + "92/", None), ("DELETE", base + "999/", None),
        ]
        for method, path, data in writes:
            compare(method, path, data)
            count += 1
        for method, path, data in [("POST", base, {}), ("PUT", base + "91/", {"policy": None})]:
            compare(method, path, data, safer=True)
            count += 1
        # Agent scopes protect both the existing owner and the requested owner.
        for method, path, data in [("POST", base, {"policy": 91, "agent": 92}),
                                   ("PUT", base + "92/", {"agent": 92}),
                                   ("PUT", base + "93/", {"agent": 91}),
                                   ("DELETE", base + "93/", None)]:
            setup("scoped")
            baseline = without_auth(state())
            actual = go_request(method, path, data, user_id=2)
            assert actual[0] == 403 and without_auth(state()) == baseline, (method, path, actual)
            count += 1
        # Fail audit writes after validation; transaction must restore deletion.
        setup()
        baseline = without_auth(state())
        with connection.cursor() as cursor:
            cursor.execute("CREATE FUNCTION patch_contract_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$")
            cursor.execute("CREATE TRIGGER patch_contract_fail_audit BEFORE INSERT ON logs_auditlog FOR EACH ROW EXECUTE FUNCTION patch_contract_fail_audit()")
        try:
            actual = go_request("DELETE", base + "91/", user_id=1)
            assert actual[0] == 500 and without_auth(state()) == baseline
        finally:
            with connection.cursor() as cursor:
                cursor.execute("DROP TRIGGER patch_contract_fail_audit ON logs_auditlog")
                cursor.execute("DROP FUNCTION patch_contract_fail_audit()")
        print(f"Patch policy write contracts: {count} cases plus rollback passed")
        return count + 1
    finally:
        WinUpdatePolicy.objects.all().delete()
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        seed()
