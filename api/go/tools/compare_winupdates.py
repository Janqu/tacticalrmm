"""Windows update list and approval parity; no scans or installations."""
import hashlib
import json
from datetime import datetime, timezone


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdate

    agent = "winupdate-agent-contract-0001"
    other = "winupdate-agent-contract-0002"

    def setup(scope, tz="Europe/Berlin"):
        Agent.objects.all().delete()
        seed()
        CoreSettings.objects.update(default_time_zone=tz)
        Client.objects.bulk_create([Client(id=101, name="Other")])
        Site.objects.bulk_create([Site(id=101, name="Other", client_id=101)])
        Agent.objects.bulk_create([Agent(id=101, agent_id=agent, hostname="First", site_id=1),
                                   Agent(id=102, agent_id=other, hostname="Second", site_id=101)])
        WinUpdate.objects.bulk_create([
            WinUpdate(id=101, agent_id=101, kb="KB001", title="First", date_installed=datetime(2024, 1, 2, 3, 4, tzinfo=timezone.utc), installed=True, categories=["Security", None, ""], description="Grüße"),
            WinUpdate(id=102, agent_id=101, kb=None, title=None, date_installed=datetime(2024, 6, 2, 3, 4, tzinfo=timezone.utc), installed=False, categories=None, result="pending"),
            WinUpdate(id=103, agent_id=102, kb="KB003", action="ignore"),
        ])
        Role.objects.filter(pk=1).update(can_manage_winupdates=scope != "denied")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client", "combined"}:
            role.can_view_clients.add(1)
        if scope in {"site", "combined"}:
            role.can_view_sites.add(101)
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        return list(WinUpdate.objects.order_by("id").values()), snapshot()

    def without_auth(value):
        return value[0], {k: v for k, v in value[1].items() if k != "tokens"}

    base = "/winupdate/"
    count = 0

    def compare(scope, user, method, path, data=None, tz="Europe/Berlin"):
        setup(scope, tz)
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        response = client.generic(method, path, data=json.dumps(data) if data is not None else "", content_type="application/json")
        expected = (response.status_code, json.loads(response.content) if response.content and response.status_code < 500 else None)
        expected_state = state()
        setup(scope, tz)
        actual = go_request(method, path, data, user_id=user)
        if expected[0] >= 500:
            assert actual[0] == 500, (scope, method, path, expected, actual)
        else:
            assert actual == expected, (scope, user, method, path, data, expected, actual)
        assert state() == expected_state, (scope, method, path, "database/audit mismatch", expected_state, state())

    try:
        routes = [("GET", base + agent + "/", None), ("HEAD", base + other + "/", None),
                  ("GET", base + "missing-winupdate-agent-0001/", None),
                  ("PUT", base + "101/", {"action": "approve"}),
                  ("PUT", base + "103/", {"action": "nothing"}),
                  ("PUT", base + "bulk/", {"action": "approve", "pks": [101, 101, 103, 999]})]
        for scope, user in [("all", 1), ("all", 5), ("all", 2), ("client", 2), ("site", 2),
                            ("combined", 2), ("denied", 2), ("all", 3), ("all", 4), ("installer", 6)]:
            for method, path, data in routes:
                compare(scope, user, method, path, data)
                count += 1
        updates = [
            {"support_url": "https://example.invalid/" + "x" * 300,
             "more_info_urls": ["https://example.invalid/" + "y" * 300, None, ""]},
            {}, {"agent": 102, "kb": "KB-other"}, {"agent": None, "revision_number": "bad", "action": "bad"},
            {"agent": 999}, {"title": "x" * 300, "description": " text\n ", "kb": None, "guid": "  identifier  "},
            {"categories": None, "category_ids": [None, "", "  spaced  "], "kb_article_ids": [], "more_info_urls": ["https://example.invalid"]},
            {"categories": ["x" * 256], "category_ids": [True], "kb_article_ids": "bad"},
            {"revision_number": "-2.0", "installed": "true", "downloaded": 0, "result": "done"},
            {"revision_number": None, "severity": None, "support_url": None},
            {"result": "", "installed": None},
            {"id": 999, "date_installed": "bad", "created_by": "ignored", "unknown": True},
        ]
        for data in updates:
            compare("all", 1, "PUT", base + "101/", data)
            count += 1
        for data in [{}, {"action": "bad"}, {"action": "ignore"}, {"action": "nothing", "pks": []},
                     {"action": "inherit", "pks": [999]}, {"action": "approve", "pks": ["101", 102]}]:
            compare("all", 1, "PUT", base + "bulk/", data)
            count += 1
        compare("all", 1, "PUT", base + "999/", {})
        count += 1
        for tz in ["UTC", "America/New_York", "invalid/timezone"]:
            compare("all", 1, "GET", base + agent + "/", tz=tz)
            count += 1
        # Security improvement: a permitted source cannot be moved to a forbidden agent.
        setup("client")
        baseline = without_auth(state())
        actual = go_request("PUT", base + "101/", {"agent": 102}, user_id=2)
        assert actual[0] == 403 and without_auth(state()) == baseline
        count += 1
        for data in [{"action": "approve", "pks": "101"}, {"action": "approve", "pks": ["bad"]}]:
            setup("all")
            baseline = without_auth(state())
            actual = go_request("PUT", base + "bulk/", data, user_id=1)
            assert actual[0] == 400 and without_auth(state()) == baseline
            count += 1
        print(f"Windows update contracts: {count} cases passed")
        return count
    finally:
        Agent.objects.all().delete()
        seed()
