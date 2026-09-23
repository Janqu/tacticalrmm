"""Registry browsing contracts; isolated local broker, never a production agent."""
import hashlib
import json
from urllib.parse import urlencode
from unittest.mock import AsyncMock, patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from logs.models import PendingAction
    from rest_framework.test import APIClient
    from nats_fixture import responder

    allowed = "registry-contract-agent-31"
    other = "registry-contract-agent-32"
    missing = "registry-contract-missing-99"
    count = 0

    def setup(scope="all", version="2.10.0", platform="windows"):
        Agent.objects.all().delete()
        seed()
        Client.objects.bulk_create([Client(id=31, name="A"), Client(id=32, name="B")])
        Site.objects.bulk_create([Site(id=31, name="A", client_id=31), Site(id=32, name="B", client_id=32)])
        Agent.objects.bulk_create([
            Agent(id=31, agent_id=allowed, hostname="Host", site_id=31, version=version, plat=platform),
            Agent(id=32, agent_id=other, hostname="Other", site_id=32, version=version, plat=platform),
        ])
        Role.objects.filter(pk=1).update(can_use_registry=scope != "denied", can_list_agents=True)
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "client": role.can_view_clients.add(31)
        if scope == "site": role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        return {model._meta.db_table: list(model.objects.order_by("id").values())
                for model in (Agent, AgentHistory, PendingAction)}

    def compare(reply=None, *, method="GET", user=1, scope="all", target=allowed,
                query=(), version="2.10.0", platform="windows", subscribe=True):
        nonlocal count
        if reply is None: reply = {}
        path = f"/agents/{target}/registry/" + ("?" + urlencode(query) if query else "")
        setup(scope, version, platform)
        before = state()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        fake = AsyncMock(return_value=reply)
        with patch.object(Agent, "nats_cmd", fake), patch("celery.app.task.Task.apply_async") as jobs:
            response = client.generic(method, path)
        jobs.assert_not_called()
        expected = response.status_code, json.loads(response.content) if response.content else None
        assert state() == before, "Django registry browse mutated data"
        expected_base = snapshot()
        messages = []
        for call in fake.call_args_list:
            assert call.kwargs == {"timeout": 30}, call
            messages.append(call.args[0])
        setup(scope, version, platform)
        before = state()
        if subscribe:
            with responder(target, [reply]) as peer:
                actual = go_request(method, path, user_id=user)
            assert peer.messages == messages, (method, scope, query, messages, peer.messages)
        else:
            actual = go_request(method, path, user_id=user)
        assert actual == expected, (method, user, scope, target, query, version, expected, actual)
        assert state() == before, "Go registry browse mutated data"
        assert snapshot() == expected_base, "Registry audit/auth mismatch"
        count += 1

    try:
        for method in ("GET", "HEAD"):
            for user, scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (allowed, other, missing):
                    compare(method=method, user=user, scope=scope, target=target)
        for query in [
            [("path", "  cOmPuTeR  ")], [("path", "")], [("path", "  HKLM\\Software\\Äpp  ")],
            [("path", "first"), ("path", "last"), ("page", "2"), ("page", "3")],
            [("page", " +001_200 "), ("page_size", "-0")],
            [("page", "١٢"), ("page_size", "184467440737095516160000")],
            [("page", "-9"), ("page_size", "0")],
            *[[(key, value)] for key in ("page", "page_size") for value in ("", "1.0", "1__0", "_1", "1_", "++1")],
        ]:
            compare(query=query)
        for version in ("2.9.9", "2.10", "v2.10.0", "2.10.0rc1", "2.10.0.dev0", "2.10.0.post1.dev0", "2.10.0+local.1", "2.11rc1", "1!1.0", "0!2.9", "2.10.0.1"):
            compare(version=version)
        for platform in ("linux", "darwin"):
            compare(platform=platform)
        for reply in (
            {"path":"HKLM", "subkeys":["Äpp"], "values":[{"name":"big", "value":18446744073709551615}], "has_more":True, "page":99, "page_size":99},
            {"path":None, "subkeys":None, "values":None, "has_more":None},
            {"values":"unexpected scalar", "has_more":1},
            {"error":"Access denied"}, {"error":None}, {"error":False}, {"error":42}, "timeout",
        ):
            compare(reply)
        compare("timeout", subscribe=False)
        # Source crashes on non-dicts/natsdown; Go returns explicit safe errors.
        for reply, status in [(b"\xc1",502), (b"\xc0",502), ([],502), (True,502), ("bad",502), ("natsdown",400), ({"error":{}},502), ({"error":[]},502)]:
            setup()
            before = state()
            with responder(allowed, [reply]) as peer:
                actual = go_request("GET", f"/agents/{allowed}/registry/")
            assert actual[0] == status, (reply, actual)
            assert peer.messages == [{"func":"registry_browse", "payload":{"path":"Computer", "page":"1", "page_size":"200"}}]
            assert state() == before
            count += 1
        for version in ("garbage", "", "2.10.0evil"):
            setup(version=version)
            before = state()
            with responder(allowed, [{}]) as peer:
                actual = go_request("GET", f"/agents/{allowed}/registry/")
            assert actual == (400, "Invalid agent version."), actual
            assert not peer.messages
            assert state() == before
            count += 1
        print(f"Registry browse contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        seed()
