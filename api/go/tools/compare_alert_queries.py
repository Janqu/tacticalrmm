"""PATCH /alerts/ compares scoped lists, dashboard counts, and filters with Django."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from alerts.models import Alert
    from autotasks.models import AutomatedTask
    from checks.models import Check
    from clients.models import Client, Site
    from rest_framework.test import APIClient

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)

    def cleanup():
        Alert.objects.all().delete()
        Agent.objects.all().delete()

    def setup(scope):
        cleanup()
        seed()
        Client.objects.bulk_create([Client(id=61, name="Other")])
        Site.objects.bulk_create([Site(id=61, name="Other", client_id=61)])
        Agent.objects.bulk_create([
            Agent(id=61, hostname="Allowed", agent_id="go-alert-query-agent-0001", site_id=1),
            Agent(id=62, hostname="Other", agent_id="go-alert-query-agent-0002", site_id=61),
        ])
        Check.objects.bulk_create([Check(id=61, agent_id=62)])
        AutomatedTask.objects.bulk_create([AutomatedTask(id=61, agent_id=62, name="Alert query task")])
        Alert.objects.bulk_create([
            Alert(id=61, agent_id=61, severity="error", message="Allowed", action_run=fixed, action_retcode=-3),
            Alert(id=62, agent_id=62, severity="warning", message="Other"),
            Alert(id=63, severity="info", message="Custom"),
            Alert(id=64, assigned_check_id=61, alert_type="check", message="Null-agent check"),
            Alert(id=65, assigned_task_id=61, alert_type="task", message="Null-agent task"),
            Alert(id=66, agent_id=61, resolved=True, resolved_on=fixed, severity="error"),
            Alert(id=67, agent_id=61, snoozed=True, snooze_until=fixed, severity="warning"),
            Alert(id=68, agent_id=61, hidden=True),
            Alert(id=69, agent_id=61, message="Old"),
            Alert(id=70, agent_id=61, message="Future"),
            Alert(id=71, agent_id=61, message="No date"),
        ])
        now = datetime.now(timezone.utc)
        for offset, pk in enumerate(range(61, 69)):
            Alert.objects.filter(pk=pk).update(alert_time=now - timedelta(hours=10 + offset))
        Alert.objects.filter(pk=69).update(alert_time=fixed)
        Alert.objects.filter(pk=70).update(alert_time=now + timedelta(days=2))
        Alert.objects.filter(pk=71).update(alert_time=None)
        Role.objects.filter(pk=1).update(can_list_alerts=scope != "denied", can_manage_alerts=False)
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client", "combined"}: role.can_view_clients.add(61)
        if scope in {"site", "combined"}: role.can_view_sites.add(1)
        if scope == "installer": User.objects.filter(pk=6).update(role_id=1)

    requests = [
        {}, {"unused": "ignored"}, {"top": 0}, {"top": 1}, {"top": 100}, {"top": "2"},
        {"top": 2.9}, {"top": False}, {"top": True, "clientFilter": "ignored", "timeFilter": "bad"},
        {"clientFilter": [1]}, {"clientFilter": [61]}, {"clientFilter": [1, 61]},
        {"clientFilter": []}, {"clientFilter": [999]}, {"clientFilter": [None, "1", 61.5, True]},
        {"severityFilter": ["error"]}, {"severityFilter": ["error", "warning"]},
        {"severityFilter": []}, {"severityFilter": ["unknown", None, 1, False]},
        {"resolvedFilter": False}, {"resolvedFilter": True}, {"resolvedFilter": None},
        {"snoozedFilter": False}, {"snoozedFilter": True}, {"snoozedFilter": None},
        {"resolvedFilter": 0, "snoozedFilter": 0.0},
        {"resolvedFilter": "false", "snoozedFilter": [1]},
        {"timeFilter": 1}, {"timeFilter": "2"}, {"timeFilter": 0}, {"timeFilter": -1},
        {"timeFilter": 1.5}, {"timeFilter": True},
        {"clientFilter": [1, 61], "severityFilter": ["error", "warning"], "resolvedFilter": False,
         "snoozedFilter": False, "timeFilter": 1},
    ]
    invalid = [
        {"top": -1}, {"top": None}, {"top": "bad"}, {"top": []}, {"top": 10**50},
        {"timeFilter": []}, {"timeFilter": "bad"}, {"timeFilter": None}, {"timeFilter": 10**50},
        {"clientFilter": "1"}, {"clientFilter": None}, {"clientFilter": ["bad"]},
        {"severityFilter": None}, {"severityFilter": "error"}, {"severityFilter": [{}]},
        {"resolvedFilter": ""}, {"snoozedFilter": []},
    ]

    count = 0
    try:
        for scope, uid in [("all", 1), ("all", 5), ("all", 2), ("site", 2), ("client", 2), ("combined", 2),
                           ("denied", 2), ("all", 3), ("all", 4), ("installer", 6)]:
            setup(scope)
            frozen = list(Alert.objects.order_by("id").values())
            for body in requests:
                client = APIClient(raise_request_exception=False)
                client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
                with patch("agents.push.send_push_to_all") as push, patch("celery.app.task.Task.apply_async") as tasks:
                    response = client.patch("/alerts/", body, format="json")
                    push.assert_not_called()
                    tasks.assert_not_called()
                expected = json.loads(response.content)
                expected_state = snapshot()
                actual = go_request("PATCH", "/alerts/", body, user_id=uid)
                def normalize(value):
                    # Default list querysets have no Meta.ordering. The dashboard
                    # has explicit alert_time order; preserve that array exactly.
                    return sorted(value, key=lambda row: row["id"]) if isinstance(value, list) else value
                assert (actual[0], normalize(actual[1])) == (response.status_code, normalize(expected)), (scope, uid, body, expected, actual)
                assert snapshot() == expected_state, (scope, body, "unexpected auth/audit change")
                assert list(Alert.objects.order_by("id").values()) == frozen, "read changed alerts"
                count += 1
        setup("all")
        frozen = list(Alert.objects.order_by("id").values())
        for body in invalid:
            assert go_request("PATCH", "/alerts/", body)[0] == 400, body
            assert list(Alert.objects.order_by("id").values()) == frozen, "invalid query changed alerts"
            count += 1
        print(f"Alert query contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
