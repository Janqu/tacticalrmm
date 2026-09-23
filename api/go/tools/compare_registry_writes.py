"""Seven registry mutations, compared only against mocked/local test agents."""
import copy
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

    allowed = "registry-write-contract-agent-31"
    other = "registry-write-contract-agent-32"
    missing = "registry-write-contract-missing-99"
    count = 0
    bodies = {
        "create-key": {"path": "  HKLM\\Software\\Äpp  "},
        "delete-key": {"path": "  HKLM\\Software\\Äpp  "},
        "rename-key": {"old_path": " HKLM\\Old ", "new_path": " HKLM\\New "},
        "create-value": {"path": " HKLM\\App ", "name": " value ", "type": " reg_sz ", "data": "Äbc"},
        "delete-value": {"path": " HKLM\\App ", "name": " value "},
        "rename-value": {"path": " HKLM\\App ", "old_name": " old ", "new_name": " new "},
        "modify-value": {"path": " HKLM\\App ", "name": " value ", "type": " reg_sz ", "data": "Äbc"},
    }
    key_acks = {"create-key", "delete-key", "rename-key", "delete-value"}
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

    def compare(op, *, reply=None, body=None, user=1, scope="all", target=allowed,
                version="2.10.0", platform="windows", query=None, subscribe=True, method=None):
        nonlocal count
        reply = {} if reply is None else reply
        body = copy.deepcopy(bodies[op] if body is None else body)
        method = method or ("DELETE" if op.startswith("delete") else "POST")
        path = f"/agents/{target}/registry/{op}/"
        if method == "DELETE":
            path += "?" + urlencode(query if query is not None else body)
        setup(scope, version, platform)
        before = state()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        fake = AsyncMock(return_value=reply)
        with patch.object(Agent, "nats_cmd", fake), patch("celery.app.task.Task.apply_async") as jobs:
            response = client.generic(method, path, data=json.dumps(body), content_type="application/json")
        jobs.assert_not_called()
        expected = response.status_code, json.loads(response.content) if response.content else None
        assert state() == before, "Django registry write changed server data"
        expected_base = snapshot()
        messages = []
        for call in fake.call_args_list:
            assert call.kwargs == {"timeout": 60 if op == "rename-key" else 30}, call
            payload = call.args[0]
            assert payload["func"] == "registry_" + op.replace("-", "_"), payload
            messages.append(copy.deepcopy(payload))
        setup(scope, version, platform)
        before = state()
        if subscribe:
            with responder(target, [reply]) as peer:
                actual = go_request(method, path, body, user_id=user)
            assert peer.messages == messages, (op, body, messages, peer.messages)
        else:
            actual = go_request(method, path, body, user_id=user)
        assert actual == expected, (op, user, scope, target, body, version, expected, actual)
        assert state() == before, "Go registry write changed server data"
        assert snapshot() == expected_base, "Registry write audit/auth mismatch"
        count += 1

    def safe_failure(op, reply=None, *, body=None, version="2.10.0", status=502, publish=True):
        nonlocal count
        reply = {} if reply is None else reply
        setup(version=version)
        before = state()
        body = copy.deepcopy(bodies[op] if body is None else body)
        method = "DELETE" if op.startswith("delete") else "POST"
        path = f"/agents/{allowed}/registry/{op}/"
        if method == "DELETE": path += "?" + urlencode(body)
        with responder(allowed, [reply]) as peer:
            actual = go_request(method, path, body)
        assert actual[0] == status, (op, body, reply, actual)
        assert len(peer.messages) == int(publish), (op, "unexpected command or retry", peer.messages)
        assert state() == before
        count += 1

    try:
        for op in bodies:
            for user, scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (allowed, other, missing):
                    compare(op, user=user, scope=scope, target=target)
            compare(op, method="HEAD")
            compare(op, method="GET")
            compare(op, body={})
            for key in bodies[op]:
                if key == "data": continue
                for value in ("", "   "):
                    body = copy.deepcopy(bodies[op]); body[key] = value
                    compare(op, body=body)
            for version in ("2.9.9", "2.10.0rc1", "2.10.0.post1.dev0", "1!1.0"):
                compare(op, version=version)
            for platform in ("linux", "darwin"):
                compare(op, platform=platform)
            for reply in ({"error":"Access denied"}, {"error":None}, {"error":False}, "timeout"):
                compare(op, reply=reply)
            compare(op, reply="timeout", subscribe=False)
            if op in key_acks:
                compare(op, reply="ok")
            for reply in (b"\xc1", b"\xc0", [], False, "unexpected", {"error":[]}):
                safe_failure(op, reply)
            safe_failure(op, "natsdown", status=400)
            if op not in key_acks:
                safe_failure(op, "ok")
            safe_failure(op, version="not-a-version", status=400, publish=False)
            if not op.startswith("delete"):
                for key in bodies[op]:
                    if key == "data": continue
                    body = copy.deepcopy(bodies[op]); body[key] = ["unexpected"]
                    safe_failure(op, body=body, status=400, publish=False)
        for op in ("create-value", "modify-value"):
            for data in (None, False, 0, 18446744073709551615, "", ["Ä", None, True], {"nested":[1,2], "number":9007199254740993}):
                body = copy.deepcopy(bodies[op]); body["data"] = data
                compare(op, body=body)
            body = copy.deepcopy(bodies[op]); body["data"] = 18446744073709551616
            safe_failure(op, body=body, status=400, publish=False)
            body = copy.deepcopy(bodies[op]); del body["data"]
            compare(op, body=body)
            compare(op, reply={"name":None, "type":None, "data":None})
            compare(op, reply={"name":"normalized", "type":"REG_SZ", "data":["changed"]})
            # Validation order differs between create and modify when both fields are absent.
            compare(op, body={"path":"HKLM"})
            compare(op, body={"path":None, "name":None, "type":None})
        compare("rename-value", reply={"new_name":None})
        compare("rename-value", body={"path":"HKLM", "old_name":"same", "new_name":"same"})
        compare("rename-key", body={"old_path":" HKLM ", "new_path":"HKLM"})
        for op in ("delete-key", "delete-value"):
            compare(op, query=[("path","ignored"), ("path"," HKLM\\A & B+% "), ("name","ignored"), ("name"," final & +% ")])
            compare(op, query=[("path","HKLM"), ("path","")])
        print(f"Registry write contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        seed()
