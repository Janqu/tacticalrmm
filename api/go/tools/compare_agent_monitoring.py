"""Agent checks/tasks compare Django policy resolution and serialized results.

Only run through the isolated compare_django harness. Fresh override flags,
cache freshness, and HEAD scope enforcement are explicit Go improvements.
"""
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch

A1 = "go-monitoring-agent-one-00001"
A2 = "go-monitoring-agent-two-00002"
MISSING = "go-monitoring-agent-missing-0"


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from alerts.models import AlertTemplate
    from automation.models import Policy
    from autotasks.models import AutomatedTask, TaskResult
    from checks.models import Check, CheckResult
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from django.db import connection
    from rest_framework.test import APIClient
    from scripts.models import Script

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    kinds = ["diskspace", "ping", "cpuload", "memory", "winsvc", "script", "eventlog"]

    def cleanup():
        Agent.objects.all().delete()
        Policy.objects.filter(name__startswith="go-monitoring-").delete()
        Script.objects.filter(name__startswith="go-monitoring-").delete()
        AlertTemplate.objects.filter(name__startswith="go-monitoring-").delete()

    def setup(scenario="baseline", scope="all"):
        cleanup()
        seed()
        policies = Policy.objects.bulk_create([
            Policy(id=81+i, name="go-monitoring-"+name, active=True, enforced=i == 1)
            for i, name in enumerate(["agent", "site", "client", "default", "workstation"])])
        AlertTemplate.objects.bulk_create([AlertTemplate(id=81, name="go-monitoring-alert", check_always_email=True, task_always_text=True)])
        Client.objects.bulk_create([Client(id=81, name="Other")])
        Site.objects.bulk_create([Site(id=81, name="Other", client_id=81)])
        Client.objects.filter(pk=1).update(server_policy_id=83, workstation_policy_id=85)
        Site.objects.filter(pk=1).update(server_policy_id=82, workstation_policy_id=85)
        CoreSettings.objects.update(server_policy_id=84, workstation_policy_id=85)
        Agent.objects.bulk_create([
            Agent(id=81, hostname="One", agent_id=A1, site_id=1, policy_id=81, alert_template_id=81),
            Agent(id=82, hostname="Two", agent_id=A2, site_id=81, policy_id=81, alert_template_id=81),
        ])
        Script.objects.bulk_create([
            Script(id=81, name="go-monitoring-all", shell="powershell", script_body="exit 0", supported_platforms=[]),
            Script(id=82, name="go-monitoring-linux", shell="shell", script_body="true", supported_platforms=["linux"]),
        ])
        def check(pk, kind, **relations):
            return Check(id=pk, name=None, check_type=kind, disk="C:", ip="192.0.2.1", svc_name="Spooler",
                         script_id=81 if kind == "script" else None, log_name="Application", event_id="100",
                         warning_threshold=20, error_threshold=10, **relations)
        Check.objects.bulk_create([
            *[check(81+i, kind, agent_id=81, overridden_by_policy=i % 2 == 0) for i, kind in enumerate(kinds)],
            *[check(181+i, kind, policy_id=81) for i, kind in enumerate(kinds)],
            *[check(281+i, kind, policy_id=82) for i, kind in enumerate(kinds)],
            check(381, "ping", policy_id=83), check(481, "ping", policy_id=84),
            check(581, "ping", policy_id=85),
            Check(id=382, policy_id=83, check_type="ping", ip="192.0.2.2"),
            Check(id=383, policy_id=83, check_type="script", script_id=82),
            Check(id=482, policy_id=84, check_type="eventlog", log_name="System", event_id="200"),
            Check(id=483, policy_id=84, check_type="diskspace", disk="D:", warning_threshold=20),
            Check(id=582, policy_id=85, check_type="ping", ip="192.0.2.85"),
        ])
        AutomatedTask.objects.bulk_create([
            AutomatedTask(id=81, agent_id=81, name="own disabled other-platform", enabled=False,
                          assigned_check_id=81, task_supported_platforms=["darwin"]),
            AutomatedTask(id=82, agent_id=81, policy_id=81, name="own and policy", task_supported_platforms=["windows", "linux"]),
            AutomatedTask(id=181, policy_id=81, name="agent task", task_supported_platforms=["windows", "linux"]),
            AutomatedTask(id=281, policy_id=82, name="site task", assigned_check_id=281, enabled=False),
            AutomatedTask(id=381, policy_id=83, name="client task", task_supported_platforms=["linux"]),
            AutomatedTask(id=481, policy_id=84, name="default task", task_supported_platforms=[]),
            AutomatedTask(id=482, policy_id=84, name="default windows", task_supported_platforms=["windows"]),
            AutomatedTask(id=581, policy_id=85, name="workstation task", task_supported_platforms=["windows", "linux"]),
        ])
        # Stable UUID-like generated scheduler names and audit times permit
        # equivalent setup on Django and Go without masking serializer values.
        for task in AutomatedTask.objects.all():
            AutomatedTask.objects.filter(pk=task.pk).update(win_task_name=f"go-monitoring-task-{task.pk}")
        for model in (Check, AutomatedTask, Policy, AlertTemplate, Client, Site):
            model.objects.update(created_time=fixed, modified_time=fixed)
        CheckResult.objects.bulk_create([
            CheckResult(id=81, agent_id=81, assigned_check_id=81, status="passing", last_run=fixed, stdout="own"),
            CheckResult(id=82, agent_id=81, assigned_check_id=281, status="failing", last_run=fixed, alert_severity="error", history=[1,2], extra_details={"source":"one"}),
            CheckResult(id=83, agent_id=82, assigned_check_id=281, status="passing", stdout="MUST NOT LEAK"),
            CheckResult(id=84, agent_id=81, assigned_check_id=283, status="passing", history=[10,20,30], more_info="CPU"),
        ])
        TaskResult.objects.bulk_create([
            TaskResult(id=81, agent_id=81, task_id=81, status="passing", last_run=fixed, stdout="own task", retcode=0),
            TaskResult(id=82, agent_id=81, task_id=281, status="failing", last_run=fixed, stderr="inherited", retcode=2),
            TaskResult(id=83, agent_id=82, task_id=281, status="passing", stdout="MUST NOT LEAK"),
        ])
        if scenario == "agent-block": Agent.objects.filter(pk=81).update(block_policy_inheritance=True)
        elif scenario == "site-block": Site.objects.filter(pk=1).update(block_policy_inheritance=True)
        elif scenario == "client-block": Client.objects.filter(pk=1).update(block_policy_inheritance=True)
        elif scenario == "inactive": Policy.objects.filter(pk__in=[81,82]).update(active=False)
        elif scenario == "unenforced": Policy.objects.update(enforced=False)
        elif scenario == "exclude-agent": policies[1].excluded_agents.add(81)
        elif scenario == "exclude-site": policies[1].excluded_sites.add(1)
        elif scenario == "exclude-client": policies[1].excluded_clients.add(1)
        elif scenario == "duplicate-policy":
            Site.objects.filter(pk=1).update(server_policy_id=81)
            Client.objects.filter(pk=1).update(server_policy_id=81)
            CoreSettings.objects.update(server_policy_id=81)
        elif scenario == "linux": Agent.objects.filter(pk=81).update(plat="linux")
        elif scenario == "darwin": Agent.objects.filter(pk=81).update(plat="darwin")
        elif scenario == "workstation": Agent.objects.filter(pk=81).update(monitoring_type="workstation")
        elif scenario == "no-policies":
            Agent.objects.filter(pk=81).update(policy_id=None, block_policy_inheritance=True)
        elif scenario == "empty":
            Check.objects.filter(agent_id=81).delete()
            AutomatedTask.objects.filter(agent_id=81).delete()
            Agent.objects.filter(pk=81).update(policy_id=None, block_policy_inheritance=True)
        Role.objects.filter(pk=1).update(can_list_checks=scope != "denied", can_list_autotasks=scope != "denied",
                                         can_manage_checks=scope == "head", can_manage_autotasks=scope == "head")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"site", "head"}: role.can_view_sites.add(1)
        if scope == "installer": User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def flags():
        return dict(Check.objects.order_by("id").values_list("id", "overridden_by_policy"))

    def restore_flags(values):
        for value in (False, True):
            Check.objects.filter(pk__in=[pk for pk, flag in values.items() if flag == value]).update(overridden_by_policy=value)

    def data_state():
        return (list(Check.objects.order_by("id").values()), list(AutomatedTask.objects.order_by("id").values()),
                list(CheckResult.objects.order_by("id").values()), list(TaskResult.objects.order_by("id").values()))

    def django_request(method, path, uid):
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        with patch("celery.app.task.Task.apply_async") as tasks, patch("agents.push.send_push_to_all") as push:
            response = client.generic(method, path)
            tasks.assert_not_called()
            push.assert_not_called()
        return response.status_code, json.loads(response.content) if response.content and response.status_code < 500 else None

    def normalized(body, final_flags=None):
        if not isinstance(body, list): return body
        body = copy.deepcopy(body)
        if final_flags is not None:
            for row in body:
                if row.get("agent") is not None and "overridden_by_policy" in row:
                    row["overridden_by_policy"] = final_flags[row["id"]]
        # Direct model querysets have no ordering; preserve inherited group/
        # policy order and duplicates while stabilizing just the own prefix.
        split = next((i for i, row in enumerate(body) if row.get("agent") is None), len(body))
        return sorted(body[:split], key=lambda row: row["id"]) + body[split:]

    count = 0
    def compare(scenario, kind, uid=1, scope="all", method="GET", agent=A1, warm=False):
        nonlocal count
        setup(scenario, scope)
        path = f"/agents/{agent}/{kind}/"
        before_flags, before_state = flags(), data_state()
        expected_status, expected_body = django_request(method, path, uid)
        expected_flags, expected_state, expected_auth = flags(), data_state(), snapshot()
        restore_flags(before_flags)
        actual = go_request(method, path, user_id=uid)
        security = method == "HEAD" and scope == "head" and agent == A2
        if security:
            assert expected_status == 200 and actual[0] == 403, (kind, actual)
            assert data_state() == before_state
        else:
            assert (actual[0], normalized(actual[1])) == (expected_status, normalized(expected_body, expected_flags)), (scenario, kind, scope, uid, method, agent, expected_status, expected_body, actual)
            assert flags() == expected_flags, (scenario, kind, "override flags")
            assert data_state() == expected_state, (scenario, kind, "DB mutation differs")
            if method == "GET" and actual[0] == 200 and kind == "checks":
                assert all(row["overridden_by_policy"] == flags()[row["id"]] for row in actual[1] if row.get("agent") is not None)
        assert snapshot() == expected_auth, (scenario, kind, "unexpected auth/audit mutation")
        count += 1
        if warm and expected_status == 200:
            expected = django_request(method, path, uid)
            state = data_state()
            actual = go_request(method, path, user_id=uid)
            assert (actual[0], normalized(actual[1])) == (expected[0], normalized(expected[1], flags())), (scenario, kind, "warm", expected, actual)
            assert data_state() == state
            count += 1

    try:
        for scenario in ["baseline", "agent-block", "site-block", "client-block", "inactive", "unenforced",
                         "exclude-agent", "exclude-site", "exclude-client", "duplicate-policy", "linux", "darwin",
                         "workstation", "no-policies", "empty"]:
            for kind in ("checks", "tasks"):
                compare(scenario, kind, warm=scenario == "baseline")
        for uid, scope in [(5,"all"), (2,"all"), (2,"site"), (2,"denied"), (3,"all"), (4,"all"), (6,"installer"), (2,"head")]:
            for kind in ("checks", "tasks"):
                for method in ("GET", "HEAD"):
                    compare("baseline", kind, uid, scope, method)
                if scope in {"site", "head"}:
                    compare("baseline", kind, uid, scope, "HEAD" if scope == "head" else "GET", A2)
        for kind in ("checks", "tasks"):
            compare("baseline", kind, agent=MISSING)
            # A policy change via QuerySet.update intentionally leaves Django's
            # model cache stale. Go must match a fresh Django recomputation.
            setup()
            path = f"/agents/{A1}/{kind}/"
            assert django_request("GET", path, 1)[0] == 200
            Policy.objects.filter(pk=82).update(active=False)
            stale = django_request("GET", path, 1)
            actual = go_request("GET", path)
            cache.clear()
            fresh = django_request("GET", path, 1)
            assert [row["id"] for row in stale[1]] != [row["id"] for row in fresh[1]], (kind, "fixture did not exercise stale cache")
            assert (actual[0], normalized(actual[1])) == (fresh[0], normalized(fresh[1], flags())), (kind, "freshness", fresh, actual)
            count += 1
        # Force a late override write error after the reset to prove that the
        # entire read/recompute transaction rolls back its cached flags.
        setup()
        before = data_state()
        with connection.cursor() as cursor:
            cursor.execute("""CREATE FUNCTION go_monitoring_reject_override() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.id = 81 AND NEW.overridden_by_policy THEN RAISE EXCEPTION 'forced override failure'; END IF; RETURN NEW; END $$""")
            cursor.execute("CREATE TRIGGER go_monitoring_reject_override BEFORE UPDATE ON checks_check FOR EACH ROW EXECUTE FUNCTION go_monitoring_reject_override()")
        try:
            assert go_request("GET", f"/agents/{A1}/checks/")[0] == 500
            assert data_state() == before, "override transaction leaked a partial flag reset"
            count += 1
        finally:
            with connection.cursor() as cursor:
                cursor.execute("DROP TRIGGER go_monitoring_reject_override ON checks_check")
                cursor.execute("DROP FUNCTION go_monitoring_reject_override()")
        print(f"Agent monitoring contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
