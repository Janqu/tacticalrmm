"""Core settings, URL action, key store and code-sign contracts against Django.

Secrets: Django audits CoreSettings/GlobalKVStore with plaintext secrets. The Go
port deliberately writes "[redacted]" instead, so Django's audit rows are
redacted the same way before comparison and the raw values must never appear in
Go's audit table. Cases Go refuses with 501 (side effects that need Celery, the
Django cache or the code-sign service) are asserted Go-only: no mutation, no audit.
"""

import copy
import hashlib
import json
import re
from unittest.mock import patch

SECRET_FIELDS = {"open_ai_token", "minimax_token", "twilio_auth_token", "twilio_account_sid",
                 "smtp_host_password", "mesh_token", "value"}
TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?Z$")


def redact(value):
    if isinstance(value, dict):
        # Timestamps differ between the two seeded runs; only their presence matters.
        return {k: "[redacted]" if k in SECRET_FIELDS and isinstance(v, str) and v
                else "timestamp" if k in ("created_time", "modified_time") and v is not None else v
                for k, v in value.items()}
    return value


def diff(actual, expected, path=""):
    """Small readable difference report (Go value, Django value) for failures."""
    if isinstance(actual, dict) and isinstance(expected, dict):
        return {k: d for k in actual.keys() | expected.keys()
                if (d := diff(actual.get(k), expected.get(k), path + "/" + k))}
    if isinstance(actual, list) and isinstance(expected, list) and len(actual) == len(expected):
        return [d for a, e in zip(actual, expected) if (d := diff(a, e))]
    if isinstance(actual, list) and isinstance(expected, list):
        return ("length", len(actual), len(expected), actual[:1], expected[:1])
    return None if actual == expected else (actual, expected)


def normalize_body(body):
    body = copy.deepcopy(body)
    rows = body if isinstance(body, list) else [body]
    for row in rows:
        if isinstance(row, dict):
            for field in ("created_time", "modified_time"):
                if row.get(field) is not None:
                    assert TIME.match(row[field]), row[field]
                    row[field] = "timestamp"
    return body


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from alerts.models import AlertTemplate
    from automation.models import Policy
    from core.models import CodeSignToken, CoreSettings, GlobalKVStore, URLAction
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.test import APIClient

    def state():
        def norm(rows):
            rows = list(rows)
            for row in rows:
                for field in ("created_time", "modified_time"):
                    if row.get(field) is not None:
                        row[field] = "timestamp"
            return rows
        audits = []
        for entry in AuditLog.objects.order_by("id").values():
            del entry["id"]
            entry["entry_time"] = "timestamp"
            entry["before_value"] = redact(entry["before_value"])
            entry["after_value"] = redact(entry["after_value"])
            audits.append(entry)
        with connection.cursor() as cursor:
            cursor.execute("SELECT generation FROM go_mesh_sync")
            mesh = cursor.fetchall()
        return {"core": norm(CoreSettings.objects.order_by("id").values()),
                "urlaction": norm(URLAction.objects.order_by("id").values()),
                "keystore": norm(GlobalKVStore.objects.order_by("id").values()),
                "codesign": list(CodeSignToken.objects.order_by("id").values()),
                "audit": audits, "mesh": mesh}

    def setup(scenario):
        seed()
        for model in (URLAction, GlobalKVStore, CodeSignToken):
            model.objects.all().delete()
        Policy.objects.all().delete()
        with connection.cursor() as cursor:
            # New rows must get the same id in the Django run and the Go run.
            for table in ("core_urlaction", "core_globalkvstore"):
                cursor.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), 100, true)")
        CoreSettings.objects.update(
            open_ai_token="sk-secret-1234", minimax_token="ab", twilio_auth_token="tw-secret",
            twilio_account_sid="AC-secret", smtp_host_password="smtp-secret",
            email_alert_recipients=["one@example.com"], sms_alert_recipients=["+15551234"])
        URLAction.objects.bulk_create([
            URLAction(id=31, name="Web", pattern="https://x/{{agent.hostname}}", desc="d"),
            URLAction(id=32, name="Rest", pattern="https://y", action_type="rest", rest_method="get",
                      rest_body=None, rest_headers="a: b")])
        GlobalKVStore.objects.bulk_create([GlobalKVStore(id=41, name="k1", value="s3cret"),
                                           GlobalKVStore(id=42, name="k2", value="")])
        if scenario in {"token", "policy"}:
            CodeSignToken.objects.bulk_create([CodeSignToken(id=1, token="0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f")])
        if scenario == "policy":
            Policy.objects.bulk_create([Policy(id=51, name="P")])
        if scenario == "block":
            CoreSettings.objects.update(block_local_user_logon=True, sso_enabled=False)
        flags = dict.fromkeys(["can_view_core_settings", "can_edit_core_settings", "can_run_urlactions",
                               "can_view_global_keystore", "can_edit_global_keystore", "can_code_sign"], False)
        if scenario == "view":
            flags |= {"can_view_core_settings": True, "can_run_urlactions": True, "can_view_global_keystore": True}
        Role.objects.filter(pk=1).update(**flags)

    dispatched = []

    def django(method, path, data, user_id):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest())
        kwargs = {} if data is None else {"data": json.dumps(data), "content_type": "application/json"}
        with patch("core.views.sync_mesh_perms_task.delay") as mesh, \
                patch("alerts.tasks.cache_agents_alert_template.delay"):
            response = client.generic(method, path, **kwargs)
        dispatched.append(mesh.call_count)
        return response.status_code, json.loads(response.content) if response.content else None

    S = "/core/settings/"
    U, K, C = "/core/urlaction/", "/core/keystore/", "/core/codesign/"
    # (scenario, user, method, path, body)
    cases = []
    for scenario, user in [("view", 2), ("none", 2), ("none", 1), ("none", 3), ("none", 5)]:
        cases += [(scenario, user, m, p, None) for m in ("GET", "HEAD") for p in (S, U, K, C)]
    # Unsupported method/path pairs (DRF 403/405) are a documented pending gap, not compared.
    cases += [("view", 2, m, p, {}) for m, p in (("PUT", S), ("POST", U), ("POST", K))]
    cases += [("view", 2, "DELETE", p, None) for p in (U + "31/", K + "41/", C)]
    settings_bodies = [
        {}, {"smtp_host": "mail.example.com", "smtp_port": "2525", "smtp_requires_auth": "false"},
        {"email_alert_recipients": ["a@example.com", None, ""], "sms_alert_recipients": []},
        {"email_alert_recipients": ["a@example.com", "nope", 5]}, {"email_alert_recipients": "x"},
        {"sms_alert_recipients": None}, {"sms_alert_recipients": ["+1", None, "  "]},
        {"open_ai_token": "••••••••1234"}, {"open_ai_token": "sk-new-token-9876"}, {"open_ai_token": None},
        {"minimax_token": "ab••"}, {"twilio_auth_token": "rotated"},
        {"default_shell_windows": "custom"}, {"default_shell_windows": "custom", "default_shell_windows_custom": " /bin/x "},
        {"default_shell_linux": "powershell"}, {"default_shell_darwin": "custom", "default_shell_darwin_custom": ""},
        {"clear_faults_days": -5}, {"clear_faults_days": -99999999999}, {"clear_faults_days": "x"}, {"clear_faults_days": 3.0},
        {"default_time_zone": "Europe/Berlin"}, {"default_time_zone": "Mars/Base"},
        {"date_format": "x" * 31}, {"date_format": ""}, {"ai_provider": "minimax", "minimax_model": "m"},
        {"ai_provider": "other"}, {"ai_chat_enabled": True, "notify_on_info_alerts": "yes"}, {"ai_chat_enabled": None},
        {"check_history_prune_days": -1}, {"smtp_port": 99999999999}, {"terminal_mode": "legacy"},
        {"agent_debug_level": "error", "agent_auto_update": False},
        {"id": 5, "created_time": "2000-01-01T00:00:00Z", "modified_time": "2000-01-01T00:00:00Z", "unknown": 1},
        {"created_by": "someone", "modified_by": "ignored"}, {"created_by": None}, {"mesh_company_name": "Co"},
        {"workstation_policy": 999}, {"alert_template": None}, {"server_policy": "x"}, {"alert_template": 999},
        [1], None,
    ]
    cases += [("view", 1, "PUT", S, body) for body in settings_bodies]
    cases += [("block", 1, "PUT", S, {"ai_chat_enabled": True}), ("block", 1, "PUT", S, {"sso_enabled": False})]
    cases += [("view", 2, "PUT", S, {"smtp_host": "x"}), ("none", 3, "PUT", S, {"smtp_host": "x"})]
    urlaction_bodies = [
        {}, {"name": "New", "pattern": "https://z/{{site.name}}"}, {"name": "", "pattern": "x"}, {"name": None},
        {"name": "R", "pattern": "p", "action_type": "rest", "rest_method": "put", "rest_body": "{}", "rest_headers": None},
        {"action_type": "bad"}, {"rest_method": "GET"}, {"name": "x" * 256}, {"pattern": " "}, {"desc": "  trimmed  "},
        {"created_by": "creator"}, {"id": 99}, [], {"name": 5, "pattern": True}, {"desc": None, "rest_body": None},
    ]
    cases += [("none", 1, "POST", U, body) for body in urlaction_bodies]
    cases += [("none", 1, "PUT", U + "31/", body) for body in urlaction_bodies]
    cases += [("none", 1, "PUT", U + "32/", {"name": "Rest"}), ("none", 1, "PUT", U + "999/", {}),
              ("none", 1, "DELETE", U + "32/", None), ("none", 1, "DELETE", U + "999/", None),
              ("none", 1, "PUT", U + "0031/", {"name": "Zeros"})]
    keystore_bodies = [{}, {"name": "new", "value": "v3ry-secret"}, {"name": "x" * 26, "value": "v"},
                       {"name": "n", "value": ""}, {"value": None}, {"name": "same"}, {"value": "changed"}, [1]]
    cases += [("none", 1, "POST", K, body) for body in keystore_bodies]
    cases += [("none", 1, "PUT", K + "41/", body) for body in keystore_bodies]
    cases += [("none", 1, "PUT", K + "42/", {"value": "now-secret"}), ("none", 1, "PUT", K + "999/", {}),
              ("none", 1, "DELETE", K + "41/", None), ("none", 1, "DELETE", K + "42/", None), ("none", 1, "DELETE", K + "999/", None)]
    cases += [("token", 1, "GET", C, None), ("token", 1, "DELETE", C, None), ("none", 1, "DELETE", C, None)]
    cases += [("view", 2, "POST", U, {"name": "n"}), ("view", 2, "PUT", U + "31/", {"name": "n"}),
              ("view", 2, "POST", K, {"name": "n"}), ("view", 2, "PUT", K + "41/", {"name": "n"})]

    count = 0
    try:
        for scenario, user, method, path, body in cases:
            setup(scenario)
            expected = django(method, path, body, user)
            expected_state = state()
            # Django's Celery dispatch is mocked; Go records the same intent in its outbox.
            expected_state["mesh"] = [(1,)] if dispatched[-1] else []
            setup(scenario)
            actual = go_request(method, path, body, user_id=user)
            label = (scenario, user, method, path, body)
            assert actual[0] == expected[0], (label, actual, expected)
            assert normalize_body(actual[1]) == normalize_body(expected[1]), (label, actual, expected)
            actual_state = state()
            assert actual_state == expected_state, (label, "database effects differ", diff(actual_state, expected_state))
            audit_text = json.dumps(list(AuditLog.objects.values_list("before_value", "after_value")), default=str)
            for secret in ("sk-secret-1234", "sk-new-token-9876", "tw-secret", "AC-secret", "smtp-secret", "s3cret", "v3ry-secret", "now-secret", "rotated"):
                assert secret not in audit_text, (label, "secret leaked into Go audit")
            count += 1

        # Go-only: side effects Go refuses (Django would call Celery/network).
        go_only = [("view", 1, {"sso_enabled": True}), ("policy", 1, {"workstation_policy": 51}),
                   ("policy", 1, {"server_policy": 51}), ("none", 1, {"alert_template": None, "server_policy": None})]
        for scenario, user, body in go_only:
            setup(scenario)
            before = state()
            status, response = go_request("PUT", S, body, user_id=user)
            if body == {"alert_template": None, "server_policy": None}:
                assert status == 200, (body, status, response)  # unchanged nulls are not a change
                continue
            assert status == 501, (body, status, response)
            assert state() == before, (body, "refused request mutated state")
            count += 1
        print(f"Core contracts: {count} comparisons passed")
        return count
    finally:
        seed()
        for model in (URLAction, GlobalKVStore, CodeSignToken):
            model.objects.all().delete()
        AlertTemplate.objects.all().delete()
