"""Client/site writes and custom-field CRUD against actual Django views.

Each case runs twice from an identical database: through Django's test client,
then through the Go API. Status, body and the resulting rows (including audit
entries, minus timestamps) must match. Cases Go deliberately refuses (policy /
alert-template / site-client changes need Celery cache invalidation, and
initialsetup needs CoreSettings side effects) are asserted separately: Go must
answer 501 and leave the database untouched.
"""

import hashlib
import json
import re
from datetime import datetime
from unittest.mock import patch

TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d")
STATE_TABLES = [
    "clients_client", "clients_site", "clients_clientcustomfield", "clients_sitecustomfield",
    "core_customfield", "clients_deployment", "accounts_role_can_view_clients",
    "accounts_role_can_view_sites",
]


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, datetime):
        return "<timestamp>"
    if isinstance(value, str) and TIMESTAMP.match(value):
        return "<timestamp>"
    return value


def canon(result):
    # CustomField has no Meta.ordering, so Django's list order is plan-dependent.
    status, body = result
    if isinstance(body, list) and all(isinstance(b, dict) and "id" in b for b in body):
        body = sorted(body, key=lambda b: b["id"])
    return normalize([status, body])


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, ClientCustomField, Site, SiteCustomField
    from core.models import CustomField
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.test import APIClient

    def query(sql):
        with connection.cursor() as cursor:
            cursor.execute(sql)
            return [json.loads(row[0]) if isinstance(row[0], str) else row[0] for row in cursor.fetchall()]

    def state():
        out = {t: normalize(query(f"SELECT to_jsonb(t){' - ' + chr(39) + 'id' + chr(39) if t.startswith('accounts_') else ''} FROM {t} t ORDER BY 1")) for t in STATE_TABLES}
        out["agents"] = query("SELECT jsonb_build_object('id', id, 'site', site_id) FROM agents_agent ORDER BY id")
        audits = []
        for entry in AuditLog.objects.order_by("id").values():
            del entry["id"]
            audits.append(normalize(entry))
        out["audit"] = audits
        return out

    def setup(scope):
        Agent.objects.all().delete()
        seed()
        CustomField.objects.all().delete()
        Client.objects.bulk_create([
            Client(id=21, name="Alpha", failing_checks={"error": True, "warning": False}),
            Client(id=22, name="Zulu"),
        ])
        Site.objects.bulk_create([
            Site(id=21, name="A site", client_id=21), Site(id=22, name="Z site", client_id=21),
            Site(id=23, name="Empty", client_id=22),
        ])
        Agent.objects.bulk_create([
            Agent(id=21, agent_id="cw-1", hostname="one", site_id=21),
            Agent(id=22, agent_id="cw-2", hostname="two", site_id=22),
        ])
        fields = CustomField.objects.bulk_create([
            CustomField(id=21 + i, name=f"cw-{kind}", model="client", type=kind)
            for i, kind in enumerate(["text", "checkbox", "multiple"])
        ] + [CustomField(id=30, name="cw-site", model="site", type="text", options=["a", None]),
             CustomField(id=31, name="cw-agent", model="agent", type="multiple",
                         default_values_multiple=["x"], created_by="importer")])
        ClientCustomField.objects.bulk_create([
            ClientCustomField(id=21, client_id=21, field=fields[0], string_value="old"),
            ClientCustomField(id=22, client_id=21, field=fields[2], multiple_value=["a", None]),
        ])
        SiteCustomField.objects.bulk_create([SiteCustomField(id=21, site_id=21, field=fields[3], string_value="s")])
        AuditLog.objects.all().delete()
        for table in ("clients_client", "clients_site", "core_customfield", "clients_clientcustomfield", "clients_sitecustomfield"):
            query(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), 100, false)")
        manage = dict(can_manage_clients=True, can_manage_sites=True, can_manage_customfields=True,
                      can_view_customfields=True, can_list_clients=True, can_list_sites=True)
        Role.objects.filter(pk=1).update(**manage)
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "client":
            role.can_view_clients.add(21)
        elif scope == "site":
            role.can_view_sites.add(23)
        elif scope == "denied":
            Role.objects.filter(pk=1).update(**{k: False for k in manage})
        elif scope == "view-only":
            Role.objects.filter(pk=1).update(**{k: False for k in manage if k.startswith("can_manage")})
        cache.clear()

    def token(user_id):
        return hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest()

    def django_request(user_id, method, path, data):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token(user_id))
        body = json.dumps(data) if data is not None else None
        with patch("alerts.tasks.cache_agents_alert_template.delay"):
            try:
                response = client.generic(method, path, body, content_type="application/json")
            except Exception:  # unhandled Django error == HTTP 500 in production
                return 500, {"detail": "Internal server error."}
        return response.status_code, json.loads(response.content) if response.content else None

    count = 0

    def compare(scope, user_id, method, path, data=None, atomic=False):
        # atomic: Django is not transactional and leaves partial writes (or an
        # add+delete audit pair) when a later step fails validation; Go rolls
        # everything back. Body/status must match and Go must change nothing.
        nonlocal count
        setup(scope)
        expected = django_request(user_id, method, path, data)
        expected_state = state()
        setup(scope)
        if atomic:
            expected_state = state()
        actual = go_request(method, path, data, user_id=user_id)
        assert canon(actual) == canon(expected), (scope, user_id, method, path, data, expected, actual)
        got = state()
        assert got == expected_state, (scope, user_id, method, path, data, {
            k: [(a, b) for a, b in zip(expected_state[k], got[k]) if a != b] or (expected_state[k], got[k])
            for k in got if got[k] != expected_state[k]})
        count += 1

    def refused(method, path, data, user_id=1):
        from automation.models import Policy
        setup("unscoped")
        Policy.objects.all().delete()
        Policy.objects.bulk_create([Policy(id=41, name="cw-policy")])
        before = state()
        status, body = go_request(method, path, data, user_id=user_id)
        assert status == 501, (method, path, data, status, body)
        assert state() == before, (method, path, "refused request changed state")

    try:
        cf_values = [{"field": 21, "string_value": "  new  "}, {"field": 22, "bool_value": True},
                     {"field": 23, "multiple_value": ["x", None, " y "]}]
        client_posts = [
            {"client": {"name": "Beta"}, "site": {"name": "Main"}},
            {"client": {"name": " Beta ", "block_policy_inheritance": "true", "failing_checks": {"error": 1}},
             "site": {"name": "Main"}, "custom_fields": cf_values},
            {"client": {"name": "Alpha"}, "site": {"name": "Main"}},
            {"client": {"name": "Be|ta"}, "site": {"name": "Main"}},
            {"client": {"name": "Beta"}, "site": {"name": "Ma|in"}},
            {"client": {"name": "Beta"}, "site": {"name": ""}},
            {"client": {"name": ""}, "site": {"name": "Main"}},
            {"client": {}, "site": {"name": "Main"}},
            {"client": {"name": "Beta", "alert_template": 999}, "site": {"name": "Main"}},
            {"client": {"name": "Beta", "failing_checks": None, "server_policy": "x"}, "site": {"name": "Main"}},
            {"client": {"name": "x" * 256}, "site": {"name": "Main"}},
            {"client": {"name": "Beta"}, "site": {"name": "Main"}, "custom_fields": [{"field": 999}]},
            {"client": {"name": "Beta"}, "site": {"name": "Main"}, "custom_fields": [{"string_value": "x"}]},
        ]
        client_puts = [
            {"client": {"name": "Renamed"}}, {"client": {}}, {"client": {"name": "Zulu"}}, {"client": {"name": "a|b"}},
            {"client": {"block_policy_inheritance": True, "failing_checks": {"warning": True}}},
            {"client": {"name": "Alpha"}, "custom_fields": cf_values},
            {"client": {"name": "Alpha 2"}, "custom_fields": [{"field": 21, "string_value": None}, {"field": 22, "multiple_value": []}]},
            {"client": {"name": "Alpha"}, "custom_fields": [{"field": 999}]},
        ]
        def partial(d):
            bad_field = any(f.get("field") in (None, 999) for f in d.get("custom_fields", []))
            return bad_field or d.get("site", {}).get("name") in ("Ma|in", "")

        for user_id, scope in [(1, "unscoped"), (5, "unscoped"), (2, "unscoped"), (2, "client"), (2, "site"),
                               (2, "denied"), (2, "view-only"), (3, "unscoped")]:
            for data in client_posts[:3] if scope != "unscoped" or user_id == 3 else client_posts:
                compare(scope, user_id, "POST", "/clients/", data, atomic=partial(data))
            for data in client_puts[:2]:
                for pk in (21, 22, 999):
                    compare(scope, user_id, "PUT", f"/clients/{pk}/", data)
            for pk in (21, 22, 999):
                compare(scope, user_id, "DELETE", f"/clients/{pk}/")
        for data in client_puts:
            compare("unscoped", 1, "PUT", "/clients/21/", data, atomic=partial(data))
        for suffix in ("?move_to_site=23", "?move_to_site=21", "?move_to_site=999"):
            compare("unscoped", 1, "DELETE", "/clients/21/" + suffix, atomic=suffix.endswith(("=21", "=22")))
        compare("site", 2, "DELETE", "/clients/21/?move_to_site=21", atomic=True)
        compare("client", 2, "DELETE", "/clients/21/?move_to_site=23")

        site_posts = [
            {"site": {"client": 21, "name": "New"}}, {"site": {"client": "21", "name": "New", "block_policy_inheritance": True},
                                                      "custom_fields": [{"field": 30, "string_value": "v"}]},
            {"site": {"client": 21, "name": "A site"}}, {"site": {"client": 21, "name": "a|b"}},
            {"site": {"client": 999, "name": "New"}}, {"site": {"client": 21}},
            {"site": {"client": None, "name": "New"}}, {"site": {"client": 22, "name": "New", "server_policy": 999}},
            {"site": {"client": 21, "name": "New"}, "custom_fields": [{"field": 999}]},
        ]
        for user_id, scope in [(1, "unscoped"), (2, "unscoped"), (2, "client"), (2, "site"), (2, "denied"), (3, "unscoped")]:
            for data in site_posts if user_id in (1, 2) and scope in ("unscoped", "client") else site_posts[:2]:
                compare(scope, user_id, "POST", "/clients/sites/", data, atomic=partial(data))
            for pk in (21, 23, 999):
                compare(scope, user_id, "PUT", f"/clients/sites/{pk}/", {"site": {"name": "Renamed"}})
                compare(scope, user_id, "DELETE", f"/clients/sites/{pk}/")
        for data in [{"site": {"name": "Z site"}}, {"site": {"name": "a|b"}}, {"site": {"client": 21}},
                     {"site": {"client": 22}}, {"site": {"client": 999}}, {"site": {"client": "22"}},
                     {"site": {"block_policy_inheritance": True}, "custom_fields": [{"field": 30, "string_value": "n"}, {"field": 30, "bool_value": True}]}]:
            for pk in (21, 22, 23):
                if "client" in data["site"] and data["site"]["client"] not in (21, 999):
                    continue  # client moves need Celery; covered by refused()
                compare("unscoped", 1, "PUT", f"/clients/sites/{pk}/", data)
        compare("unscoped", 1, "PUT", "/clients/sites/23/", {"site": {"client": 21}})  # "must have one site"
        for suffix in ("?move_to_site=21", "?move_to_site=22", "?move_to_site=23", "?move_to_site=999"):
            compare("unscoped", 1, "DELETE", "/clients/sites/21/" + suffix, atomic=suffix.endswith("=21"))
        compare("site", 2, "DELETE", "/clients/sites/22/?move_to_site=21")

        field_posts = [
            {"model": "client", "name": "new", "type": "text"},
            {"model": "site", "name": "multi", "type": "multiple", "options": ["a", None, "b"],
             "default_values_multiple": ["a"], "order": 3, "hide_in_ui": True, "required": "yes",
             "default_value_string": None, "default_value_bool": True, "created_by": "seed"},
            {"model": "client", "name": "cw-text"}, {"model": "client"}, {"name": "x"}, {},
            {"model": "bogus", "name": "x"}, {"model": "client", "name": "x", "type": "bogus"},
            {"model": "client", "name": ""}, {"model": "client", "name": "x" * 101},
            {"model": "client", "name": "x", "order": -1}, {"model": "client", "name": "x", "options": "a"},
            {"model": "client", "name": "x", "required": None},
        ]
        for user_id, scope in [(1, "unscoped"), (2, "unscoped"), (2, "view-only"), (2, "denied"), (3, "unscoped")]:
            for data in field_posts if scope == "unscoped" and user_id == 1 else field_posts[:2]:
                compare(scope, user_id, "POST", "/core/customfields/", data)
            for method, path, data in [
                ("GET", "/core/customfields/", None), ("GET", "/core/customfields/?model=site", None),
                ("GET", "/core/customfields/?model=", None), ("PATCH", "/core/customfields/", {"model": "client"}),
                ("PATCH", "/core/customfields/", {}), ("GET", "/core/customfields/30/", None),
                ("GET", "/core/customfields/999/", None), ("PUT", "/core/customfields/30/", {"name": "renamed", "options": []}),
                ("DELETE", "/core/customfields/21/", None), ("DELETE", "/core/customfields/999/", None),
            ]:
                compare(scope, user_id, method, path, data)
        for data in [{}, {"name": "cw-checkbox"}, {"model": "site", "name": "cw-site"}, {"model": "client", "name": "cw-text"},
                     {"model": "agent"}, {"type": "number", "options": None, "default_values_multiple": ["1"]},
                     {"created_by": "somebody", "modified_by": "else"}, {"order": "7", "hide_in_summary": "0"},
                     {"name": "cw-text"}, {"model": "bogus"}]:
            for pk in (21, 30, 31):
                compare("unscoped", 1, "PUT", f"/core/customfields/{pk}/", data)
        compare("unscoped", 1, "DELETE", "/core/customfields/22/")
        compare("unscoped", 1, "DELETE", "/core/customfields/31/")

        refused("PUT", "/clients/21/", {"client": {"alert_template": None, "server_policy": 41}})
        refused("PUT", "/clients/sites/21/", {"site": {"client": 22}})
        print(f"Client/site/custom-field writes: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        CustomField.objects.all().delete()
        seed()
