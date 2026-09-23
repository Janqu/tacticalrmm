"""Alerts Manager read contracts against actual Django views (isolated harness)."""
import hashlib
import json
from datetime import datetime, timezone


def normalize_unordered(value):
    # Agent and Policy have no Meta.ordering; SQL row order is not a contract.
    # Preserve ordered client/site relations, only canonicalize agent sets.
    if isinstance(value, dict):
        return {k: sorted(normalize_unordered(v), key=lambda x: x["id"] if isinstance(x, dict) else x)
                if k in {"excluded_agents", "agents", "policies", "matrix_channels"} and isinstance(v, list)
                else normalize_unordered(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_unordered(v) for v in value]
    return value


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from alerts.models import Alert, AlertTemplate, MatrixChannel
    from automation.models import Policy
    from clients.models import Client, Site
    from checks.models import Check
    from autotasks.models import AutomatedTask
    from core.models import CoreSettings, URLAction
    from scripts.models import Script
    from rest_framework.test import APIClient

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)

    def cleanup():
        Alert.objects.all().delete()
        Agent.objects.all().delete()
        for model in (Policy, AlertTemplate, MatrixChannel, Script, URLAction):
            model.objects.filter(name__startswith="go-alert-").delete()

    def setup(scope):
        cleanup()
        seed()
        Script.objects.bulk_create([Script(id=31, name="go-alert-script", shell="powershell", script_body="exit 0")])
        URLAction.objects.bulk_create([URLAction(id=31, name="go-alert-rest", pattern="https://example.test")])
        templates = AlertTemplate.objects.bulk_create([
            AlertTemplate(id=31, name="go-alert-default"),
            AlertTemplate(id=32, name="go-alert-configured", action_id=31, action_type="rest", action_rest_id=31,
                          resolved_action_id=31, agent_always_alert=True, check_text_alert_severity=["warning"],
                          task_periodic_alert_days=3, email_recipients=["one@example.test", "two@example.test"],
                          action_args=["a", None], action_env_vars=["KEY=value"], resolved_action_args=None),
            AlertTemplate(id=33, name="go-alert-text", text_recipients=["123"], action_id=31,
                          resolved_action_type="rest", resolved_action_rest_id=31),
            AlertTemplate(id=34, name="go-alert-email", email_from="sender@example.test"),
        ])
        channel = MatrixChannel.objects.bulk_create([MatrixChannel(id=31, name="go-alert-matrix", homeserver="https://example.test", room_id="!r:e", token_key="key")])[0]
        templates[0].matrix_channels.add(channel)
        CoreSettings.objects.update(alert_template_id=31)
        Client.objects.bulk_create([Client(id=31, name="Zulu", alert_template_id=32), Client(id=32, name="Alpha", alert_template_id=32)])
        Site.objects.bulk_create([Site(id=31, name="Zulu", client_id=31, alert_template_id=32), Site(id=32, name="Alpha", client_id=32, alert_template_id=32)])
        Agent.objects.bulk_create([
            Agent(id=31, agent_id="go-alert-agent-00000000001", hostname="Zulu", site_id=31),
            Agent(id=32, agent_id="go-alert-agent-00000000002", hostname="Alpha", site_id=32),
        ])
        policy = Policy.objects.bulk_create([Policy(id=31, name="go-alert-policy", alert_template_id=32, active=True)])[0]
        for obj in (templates[1], policy):
            obj.excluded_clients.add(31, 32)
            obj.excluded_sites.add(31, 32)
            obj.excluded_agents.add(31, 32)
        Check.objects.bulk_create([Check(id=31, agent_id=31)])
        AutomatedTask.objects.bulk_create([AutomatedTask(id=31, agent_id=31, name="go-alert-task")])
        Alert.objects.bulk_create([
            Alert(id=31, agent_id=31, message="Grüße", action_run=fixed, snooze_until=fixed, resolved_on=fixed),
            Alert(id=32, agent_id=32, message="Other site", resolved=True, email_sent=fixed, action_retcode=3),
            Alert(id=33, message=None, agent=None),
            Alert(id=34, agent_id=None, assigned_check_id=31, alert_type="check"),
            Alert(id=35, agent_id=None, assigned_task_id=31, alert_type="task"),
        ])
        Alert.objects.update(alert_time=fixed)
        for model in (Client, Site, Policy, AlertTemplate):
            model.objects.update(created_time=fixed, modified_time=fixed)
        Role.objects.filter(pk=1).update(can_list_alerttemplates=True, can_list_alerts=True,
                                       can_manage_alerttemplates=scope == "manage", can_manage_alerts=scope == "manage")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "site": role.can_view_sites.add(31)
        if scope == "client": role.can_view_clients.add(32)
        if scope == "denied": Role.objects.filter(pk=1).update(can_list_alerttemplates=False, can_list_alerts=False)
        if scope == "installer": User.objects.filter(pk=6).update(role_id=1)

    paths = ["/alerts/templates/", "/alerts/templates/31/", "/alerts/templates/32/", "/alerts/templates/33/",
             "/alerts/templates/34/", "/alerts/templates/32/related/", "/alerts/templates/31/related/",
             "/alerts/templates/0/", "/alerts/0/", "/alerts/templates/999/", "/alerts/templates/999/related/", "/alerts/31/", "/alerts/32/", "/alerts/33/", "/alerts/34/", "/alerts/35/", "/alerts/999/"]
    count = 0
    try:
        for scope, uid in [("all", 1), ("all", 5), ("all", 2), ("site", 2), ("client", 2),
                           ("denied", 2), ("all", 3), ("all", 4), ("installer", 6), ("manage", 2)]:
            setup(scope)
            for method in ("GET", "HEAD"):
                for path in paths:
                    client = APIClient(raise_request_exception=False)
                    client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
                    expected = client.generic(method, path)
                    state = snapshot()
                    actual = go_request(method, path, user_id=uid)
                    body = json.loads(expected.content) if expected.content else None
                    if path == "/alerts/templates/" and isinstance(body, list) and isinstance(actual[1], list):
                        # AlertTemplate has no Meta.ordering.
                        body = sorted(body, key=lambda row: row["id"])
                        actual = (actual[0], sorted(actual[1], key=lambda row: row["id"]))
                    assert normalize_unordered((actual[0], actual[1])) == normalize_unordered((expected.status_code, body)), (scope, uid, method, path, body, actual)
                    assert snapshot() == state, (scope, method, path, "read changed state")
                    count += 1
        print(f"Alerts read contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
