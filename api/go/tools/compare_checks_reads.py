"""Bounded check reads; inherited agent checks remain on Django intentionally."""
import hashlib
import json
from datetime import datetime, timedelta, timezone


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from alerts.models import AlertTemplate
    from automation.models import Policy
    from autotasks.models import AutomatedTask
    from checks.models import Check, CheckResult, CheckHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from scripts.models import Script

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    recent = datetime.now(timezone.utc).replace(microsecond=123400) - timedelta(hours=2)

    def cleanup():
        AutomatedTask.objects.all().delete()
        CheckHistory.objects.all().delete()
        Check.objects.all().delete()
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        Script.objects.all().delete()
        AlertTemplate.objects.all().delete()

    def setup(scope):
        cleanup()
        seed()
        Role.objects.filter(pk=1).update(can_list_checks=scope != "denied",
                                        can_manage_checks=scope == "manager",
                                        can_list_automation_policies=scope != "denied",
                                        can_manage_automation_policies=scope == "manager")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client", "combined"}:
            role.can_view_clients.add(1)
        if scope == "manager":
            Role.objects.filter(pk=1).update(can_list_checks=False, can_list_automation_policies=False)
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
        Client.objects.bulk_create([Client(id=51, name="Other")])
        Site.objects.bulk_create([Site(id=51, client_id=51, name="Other")])
        if scope in {"site", "combined"}:
            role.can_view_sites.add(51)
        AlertTemplate.objects.bulk_create([AlertTemplate(id=51, name="Template", check_always_email=True)])
        Agent.objects.bulk_create([
            Agent(id=51, agent_id="check-agent-contract-001", hostname="First", site_id=1, alert_template_id=51),
            Agent(id=52, agent_id="check-agent-contract-002", hostname="Second", site_id=51),
        ])
        Policy.objects.bulk_create([Policy(id=51, name="Policy"), Policy(id=52, name="Empty")])
        Script.objects.bulk_create([Script(id=51, name="Diagnostic script")])
        Check.objects.bulk_create([
            Check(id=51+i, check_type=kind, agent_id=51 if i < 3 else (52 if i < 5 else None),
                  policy_id=51 if i >= 5 else None, script_id=51 if kind == "script" else None,
                  name=None if i == 1 else "Check ü", warning_threshold=20,
                  error_threshold=10, disk="C:", svc_display_name="Service display",
                  script_args=["a", None, ""], env_vars=None, event_message="event text")
            for i, kind in enumerate(["diskspace", "ping", "cpuload", "memory", "winsvc", "eventlog", "script", "other"])
        ])
        Check.objects.filter(pk=53).update(warning_threshold=None, error_threshold=0)
        AutomatedTask.objects.bulk_create([
            AutomatedTask(id=51, name="Assigned", assigned_check_id=51, agent_id=51,
                          win_task_name="checks-contract-task", run_time_date=fixed,
                          actions=[{"type": "cmd", "command": "echo fixture"}], expire_date=fixed),
            AutomatedTask(id=52, name="Policy task", assigned_check_id=57, policy_id=51,
                          win_task_name="checks-contract-policy-task"),
        ])
        CheckResult.objects.bulk_create([
            CheckResult(id=51, assigned_check_id=51, agent_id=51, last_run=fixed,
                        status="failing", retcode=9223372036854775806,
                        stdout="Grüße", outage_history={"items": []}, extra_details={"percent": 30}),
            CheckResult(id=52, assigned_check_id=57, agent_id=52, history=None),
        ])
        CheckHistory.objects.bulk_create([
            CheckHistory(id=51, check_id=51, agent_id="check-agent-contract-001", y=10, results={"sample": 1}),
            CheckHistory(id=52, check_id=51, agent_id="check-agent-contract-001", y=None, results=None),
            CheckHistory(id=53, check_id=51, agent_id="check-agent-contract-002", y=99),
            CheckHistory(id=54, check_id=51, agent_id="check-agent-contract-001", y=77),
        ])
        CheckHistory.objects.filter(pk=51).update(x=fixed)
        CheckHistory.objects.filter(pk=52).update(x=recent)
        CheckHistory.objects.filter(pk=53).update(x=recent)
        CheckHistory.objects.filter(pk=54).update(x=recent + timedelta(days=30))
        for model in [Check, AutomatedTask, Policy, Script, AlertTemplate]:
            model.objects.update(created_time=fixed, modified_time=fixed)
        cache.clear()

    def state():
        return snapshot(), list(Check.objects.order_by("id").values()), list(CheckResult.objects.order_by("id").values()), list(CheckHistory.objects.order_by("id").values())

    def normalize(value, field=None):
        if isinstance(value, list):
            # Check, CheckResult and assigned-task models have no Meta.ordering.
            # Graph history has no id key and keeps its required descending x.
            items = [normalize(v) for v in value]
            if field in {None, "assignedtasks"} and items and all(isinstance(v, dict) and "id" in v for v in items):
                return sorted(items, key=lambda v: v["id"])
            return items
        if isinstance(value, dict):
            return {k: normalize(v, k) for k, v in value.items()}
        return value

    routes = [("GET", path, None) for path in [
        "/checks/", "/checks/51/", "/checks/54/", "/checks/57/", "/checks/0/", "/checks/999/",
        "/automation/policies/0/checks/", "/automation/policies/51/checks/", "/automation/policies/52/checks/", "/automation/policies/999/checks/",
        "/automation/checks/51/status/", "/automation/checks/57/status/", "/automation/checks/999/status/",
    ]] + [("PATCH", "/checks/51/history/", {}), ("PATCH", "/checks/52/history/", {}),
          ("PATCH", "/checks/999/history/", {})]
    count = 0

    def compare(scope, user_id, method, path, data):
        setup(scope)
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest())
        response = client.generic(method, path, data=json.dumps(data) if data is not None else "", content_type="application/json")
        expected = (response.status_code, json.loads(response.content) if response.content and response.status_code < 500 else None)
        expected_state = state()
        setup(scope)
        actual = go_request(method, path, data, user_id=user_id)
        if expected[0] >= 500:
            # Deliberate safety improvement: invalid history ranges are validation
            # errors instead of Django's uncaught TypeError/OverflowError.
            wanted = 400 if method == "PATCH" and "timeFilter" in (data or {}) else expected[0]
            assert actual[0] == wanted, (scope, method, path, data, expected, actual)
        else:
            assert (actual[0], normalize(actual[1])) == (expected[0], normalize(expected[1])), (scope, method, path, data, expected, actual)
        assert state() == expected_state, (scope, method, path, "unexpected database state")

    try:
        for scope, user_id in [("all", 1), ("all", 5), ("all", 2), ("client", 2),
                               ("site", 2), ("combined", 2), ("denied", 2), ("all", 3),
                               ("all", 4), ("installer", 6)]:
            for method, path, data in routes:
                compare(scope, user_id, method, path, data)
                count += 1
        for scope in ["all", "manager"]:
            for method, path, data in routes:
                if method == "GET":
                    compare(scope, 2, "HEAD", path, data)
                    count += 1
        for value in [0, 1, 0.5, -1, True, False, "1", None, [], 1000000000]:
            compare("all", 1, "PATCH", "/checks/51/history/", {"timeFilter": value})
            count += 1
        print(f"Check read contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
