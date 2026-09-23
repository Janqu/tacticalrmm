"""Alert mutations: Django parity, role isolation, cascades, and safe validation."""
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import UUID


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from alerts.models import Alert, MatrixChannel, MatrixDelivery
    from clients.models import Client, Site
    from checks.models import Check
    from autotasks.models import AutomatedTask
    from qdt_snmp.models import SnmpAlert, SnmpDevice
    from rest_framework.test import APIClient
    from django.db import connection

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)

    def cleanup():
        SnmpDevice.objects.all().delete()
        Alert.objects.all().delete()
        Agent.objects.all().delete()
        MatrixChannel.objects.filter(name="go-alert-write").delete()

    def setup(scope):
        cleanup()
        seed()
        Client.objects.bulk_create([Client(id=51, name="Other")])
        Site.objects.bulk_create([Site(id=51, name="Other", client_id=51)])
        Agent.objects.bulk_create([
            Agent(id=51, hostname="Allowed", agent_id="go-alert-write-agent-00001", site_id=1),
            Agent(id=52, hostname="Forbidden", agent_id="go-alert-write-agent-00002", site_id=51),
        ])
        Check.objects.bulk_create([Check(id=51, agent_id=51), Check(id=52, agent_id=52)])
        AutomatedTask.objects.bulk_create([
            AutomatedTask(id=51, name="Allowed", agent_id=51),
            AutomatedTask(id=52, name="Forbidden", agent_id=52),
        ])
        Alert.objects.bulk_create([
            Alert(id=51, agent_id=51, message="Allowed", snoozed=True, snooze_until=fixed),
            Alert(id=52, agent_id=52, message="Forbidden", snoozed=True, snooze_until=fixed),
            Alert(id=53, message="Custom", snoozed=True, snooze_until=fixed),
            Alert(id=54, assigned_check_id=52, message="Null agent check", snoozed=True, snooze_until=fixed),
            Alert(id=55, assigned_task_id=52, message="Null agent task", snoozed=True, snooze_until=fixed),
        ])
        Alert.objects.update(alert_time=fixed)
        channel = MatrixChannel.objects.bulk_create([MatrixChannel(id=51, name="go-alert-write", homeserver="https://example.test", room_id="!r:e", token_key="x")])[0]
        MatrixDelivery.objects.bulk_create([MatrixDelivery(id=51, channel=channel, alert_id=51, event="failure:error", body="pending", transaction_id=UUID(int=51))])
        device = SnmpDevice.objects.bulk_create([SnmpDevice(id=51, site_id=1, name="go-alert-write", ip="192.0.2.1")])[0]
        SnmpAlert.objects.bulk_create([SnmpAlert(id=51, device=device, alert_id=51, metric="online", severity="error")])
        SnmpAlert.objects.update(created_time=fixed)
        Role.objects.filter(pk=1).update(can_manage_alerts=scope != "denied", can_list_alerts=True)
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "site": role.can_view_sites.add(1)
        if scope == "client": role.can_view_clients.add(1)
        if scope == "installer": User.objects.filter(pk=6).update(role_id=1)

    def state(dynamic=False):
        rows = list(Alert.objects.order_by("id").values())
        if dynamic:
            for row in rows:
                for field in ("resolved_on", "snooze_until"):
                    value = row[field]
                    if value and value != fixed:
                        days = round((value - datetime.now(timezone.utc)).total_seconds() / 86400)
                        assert abs((value - datetime.now(timezone.utc)).total_seconds() - days * 86400) < 15
                        row[field] = ("now", days)
        return (rows, list(MatrixDelivery.objects.order_by("id").values()),
                list(SnmpAlert.objects.order_by("id").values()), snapshot())

    def mutation_state(value):
        # Knox prunes expired tokens during authentication even on rejected
        # requests. Keep full snapshots for Django/Go parity; exclude only that
        # authentication housekeeping from mutation rollback assertions.
        return (*value[:3], {key: item for key, item in value[3].items() if key != "tokens"})

    def compare(method, path, body, scope="all", uid=1, deviation=None):
        setup(scope)
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        before = state()
        with patch("agents.push.send_push_to_all") as push, patch("celery.app.task.Task.apply_async") as tasks:
            response = client.generic(method, path, data=json.dumps(body) if body is not None else "", content_type="application/json")
            push.assert_not_called()
            tasks.assert_not_called()
        expected_body = json.loads(response.content) if response.content and response.status_code < 500 else None
        dynamic = isinstance(body, dict) and ("type" in body or "bulk_action" in body)
        expected = state(dynamic)
        setup(scope)
        actual = go_request(method, path, body, user_id=uid)
        if deviation:
            assert actual[0] == deviation, (method, path, body, actual)
            assert mutation_state(state()) == mutation_state(before), (method, path, body, "rejected mutation changed state")
        else:
            assert actual == (response.status_code, expected_body), (scope, uid, method, path, body, response.status_code, expected_body, actual)
            assert state(dynamic) == expected, (scope, uid, method, path, body, expected, state(dynamic))

    count = 0
    try:
        edits = [
            {}, {"message": "  Grüße  ", "severity": "error", "hidden": True},
            {"message": None, "resolved": "true", "snoozed": 0},
            {"agent": 51, "assigned_check": 51, "assigned_task": 51, "alert_type": "task"},
            {"agent": None, "assigned_check": "", "assigned_task": None},
            {"agent": "51", "message": 42},
            {"action_retcode": -9223372036854775808, "resolved_action_retcode": "9223372036854775807"},
            {"action_retcode": " -3.0 ", "resolved_action_retcode": 2.0},
            {"action_retcode": None, "action_stdout": " x ", "action_stderr": "", "action_execution_time": "1.00"},
            {"resolved_action_stdout": None, "resolved_action_stderr": "y", "resolved_action_execution_time": 1.2},
            {"email_sent": "2024-01-02T03:04:05.123400Z", "resolved_email_sent": None,
             "sms_sent": "2024-01-02T05:04:05.123400+02:00", "resolved_sms_sent": "2024-01-02",
             "action_run": "2024-01-02T03:04:05", "resolved_action_run": None,
             "resolved_on": "2024-01-02T03:04:05Z", "snooze_until": None},
            {"id": 999, "agent_id": "ignored", "hostname": "ignored", "client": "ignored", "alert_time": "bad"},
            {"type": "resolve", "severity": "invalid"}, {"type": "unsnooze"},
            *[{"type": "snooze", "snooze_days": days} for days in (0, 2, -1, "3", 1.5, True)],
            {"type": "snooze"}, {"type": "bogus"},
            {"message": [], "severity": "bad", "resolved": None},
            {"message": "bad\x00", "agent": 999, "assigned_task": False},
            {"action_retcode": 9223372036854775808, "resolved_action_retcode": -9223372036854775809},
            {"action_retcode": "x", "action_run": "y", "snooze_until": False},
            {"action_retcode": 1.5, "action_execution_time": "a" * 101},
        ]
        for body in edits:
            compare("PUT", "/alerts/51/", body)
            count += 1
        for scope, uid in [("all", 5), ("all", 2), ("site", 2), ("client", 2), ("denied", 2), ("all", 3), ("all", 4), ("installer", 6)]:
            for method, path, body in [
                ("PUT", "/alerts/51/", {"type": "resolve"}),
                ("PUT", "/alerts/52/", {"type": "unsnooze"}),
                ("PUT", "/alerts/53/", {"message": "Custom edit"}),
                ("DELETE", "/alerts/51/", None),
                ("POST", "/alerts/bulk/", {"bulk_action": "resolve", "alerts": [51, 52, 53, 54, 55, 999]}),
                ("POST", "/alerts/bulk/", {"bulk_action": "snooze", "alerts": [51, 52, 53, 54, 55], "snooze_days": 2}),
            ]:
                compare(method, path, body, scope, uid)
                count += 1
        for body in [
            {"bulk_action": "resolve", "alerts": []},
            {"bulk_action": "resolve", "alerts": [51, 51, "52", 999]},
            {"bulk_action": "snooze", "alerts": [51], "snooze_days": -1},
            {"bulk_action": "snooze", "alerts": [51]}, {"bulk_action": "bad", "alerts": [51]},
        ]:
            compare("POST", "/alerts/bulk/", body)
            count += 1
        for method, path, body, scope, uid, status in [
            ("DELETE", "/alerts/999/", None, "all", 1, 404),
            ("DELETE", "/alerts/0/", None, "all", 1, 404),
            ("PUT", "/alerts/51/", {"agent": 52}, "site", 2, 403),
            ("PUT", "/alerts/51/", {"assigned_check": 52}, "site", 2, 403),
            ("PUT", "/alerts/51/", {"assigned_task": 52}, "site", 2, 403),
            *[("PUT", "/alerts/51/", {"type": "snooze", "snooze_days": days}, "all", 1, 400)
              for days in (None, "bad", [], 10**30)],
            *[("POST", "/alerts/bulk/", body, "all", 1, 400) for body in (
                {"bulk_action": "resolve"}, {"bulk_action": "resolve", "alerts": None},
                {"bulk_action": "resolve", "alerts": [51, "bad"]})],
        ]:
            compare(method, path, body, scope, uid, status)
            count += 1
        # A database failure after deleting deliveries / nulling SNMP links
        # must roll back both operations, not leave a half-deleted alert.
        setup("all")
        before = state()
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE go_alert_delete_block (alert_id bigint REFERENCES alerts_alert(id))")
            cursor.execute("INSERT INTO go_alert_delete_block VALUES (51)")
        try:
            assert go_request("DELETE", "/alerts/51/")[0] == 500
            assert mutation_state(state()) == mutation_state(before), "delete failure did not roll back related rows"
            count += 1
        finally:
            with connection.cursor() as cursor:
                cursor.execute("DROP TABLE go_alert_delete_block")
        print(f"Alert write contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
