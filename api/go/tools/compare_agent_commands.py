"""Agent commands against a local NATS responder only; no real agents."""
import hashlib
import json
from unittest.mock import AsyncMock, patch


def run_disabled(seed, go_request, snapshot):
    from agents.models import Agent
    from clients.models import Client, Site
    from winupdate.models import WinUpdate

    target = "disabled-command-agent-31"
    try:
        Agent.objects.all().delete()
        seed()
        Client.objects.bulk_create([Client(id=31, name="Disabled transport")])
        Site.objects.bulk_create([Site(id=31, name="Disabled transport", client_id=31)])
        Agent.objects.bulk_create([Agent(id=31, agent_id=target, hostname="Disabled", site_id=31, version="2.10.0")])
        before = list(Agent.objects.values())
        cases = [
            ("GET", f"/agents/{target}/ping/"),
            ("POST", f"/checks/{target}/run/"),
            ("POST", f"/agents/{target}/wmi/"),
            ("POST", f"/agents/{target}/runscript/"),
            ("POST", f"/agents/{target}/reboot/"),
            ("POST", f"/agents/{target}/shutdown/"),
            ("GET", f"/agents/{target}/processes/"),
            ("DELETE", f"/agents/{target}/processes/123/"),
            ("GET", f"/services/{target}/"),
            ("GET", f"/services/{target}/Spooler/"),
            ("GET", f"/agents/{target}/eventlog/Security/1/"),
            ("GET", f"/agents/{target}/registry/"),
        ]
        for method, path in cases:
            result = go_request(method, path, user_id=1)
            assert result[0] == 501, (method, path, result)
            assert list(Agent.objects.values()) == before
        for method, body in [("POST", {"sv_action": "restart"}), ("PUT", {"startType": "auto"})]:
            result = go_request(method, f"/services/{target}/Spooler/", body, user_id=1)
            assert result[0] == 501, (method, result)
            assert list(Agent.objects.values()) == before
        result = go_request("PATCH", f"/agents/{target}/reboot/", {"datetime": "2099-01-01T12:00"}, user_id=1)
        assert result[0] == 501, result
        assert list(Agent.objects.values()) == before
        for method, body in [("POST", {"name": "test-package"}), ("PUT", {})]:
            result = go_request(method, f"/software/{target}/", body, user_id=1)
            assert result[0] == 501, (method, result)
            assert list(Agent.objects.values()) == before
        registry_cases = [
            ("POST", "create-key/", {"path": "HKCU\\Software\\Test"}),
            ("POST", "rename-key/", {"old_path": "HKCU\\Software\\Test", "new_path": "HKCU\\Software\\New"}),
            ("POST", "create-value/", {"path": "HKCU\\Software\\Test", "name": "test", "type": "REG_SZ", "data": "x"}),
            ("POST", "rename-value/", {"path": "HKCU\\Software\\Test", "old_name": "test", "new_name": "new"}),
            ("POST", "modify-value/", {"path": "HKCU\\Software\\Test", "name": "test", "type": "REG_SZ", "data": "y"}),
            ("DELETE", "delete-key/?path=HKCU%5CSoftware%5CTest", None),
            ("DELETE", "delete-value/?path=HKCU%5CSoftware%5CTest&name=test", None),
        ]
        for method, suffix, body in registry_cases:
            result = go_request(method, f"/agents/{target}/registry/{suffix}", body, user_id=1)
            assert result[0] == 501, (method, suffix, result)
            assert list(Agent.objects.values()) == before
        result = go_request("POST", f"/agents/{target}/cmd/", {"cmd": "echo test", "shell": "cmd", "timeout": 10, "run_as_user": False}, user_id=1)
        assert result[0] == 501, result
        assert list(Agent.objects.values()) == before
        WinUpdate.objects.bulk_create([
            WinUpdate(agent_id=31, kb="KB123", title="Update (Version 1.0)"),
            WinUpdate(agent_id=31, kb="KB123", title="Update (Version 2.0)"),
        ])
        updates = list(WinUpdate.objects.order_by("id").values())
        result = go_request("POST", f"/winupdate/{target}/scan/", user_id=1)
        assert result[0] == 501, result
        assert list(Agent.objects.values()) == before
        assert list(WinUpdate.objects.order_by("id").values()) == updates
        result = go_request("POST", f"/winupdate/{target}/install/", user_id=1)
        assert result[0] == 501, result
        assert list(Agent.objects.values()) == before
        assert list(WinUpdate.objects.order_by("id").values()) == updates
        print(f"Disabled transport contracts: {len(cases) + 8 + len(registry_cases)} cases passed")
    finally:
        Agent.objects.all().delete()
        seed()


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, Site
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from nats_fixture import responder

    allowed="command-contract-agent-31"
    other="command-contract-agent-32"
    missing="command-contract-missing-99"

    def setup(scope="all"):
        Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=allowed,hostname="Host ü",site_id=31),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Role.objects.filter(pk=1).update(can_list_agents=scope!="denied",can_edit_agent=scope.startswith("manage"),can_run_checks=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope in ("client","manage-client"):role.can_view_clients.add(31)
        if scope in ("site","manage-site"):role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    count=0
    def compare(command, replies, *, user=1,scope="all",target=allowed,method=None,wire=None,subscribe=True):
        nonlocal count
        method=method or ("GET" if command=="ping" else "POST")
        path=(f"/agents/{target}/ping/" if command=="ping" else
              f"/agents/{target}/wmi/" if command=="sysinfo" else f"/checks/{target}/run/")
        setup(scope)
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        values=iter(replies)
        last=replies[-1]
        async def reference(*args,**kwargs):
            nonlocal last
            last=next(values,last)
            return last
        fake=AsyncMock(side_effect=reference)
        before=list(Agent.objects.order_by("id").values())
        with patch.object(Agent,"nats_cmd",fake):
            response=client.generic(method,path)
        expected=(response.status_code,json.loads(response.content) if response.content else None)
        expected_base=snapshot()
        assert list(Agent.objects.order_by("id").values())==before
        expected_messages=[call.args[0] for call in fake.call_args_list]
        for call in fake.call_args_list:
            assert call.kwargs=={"timeout":{"ping":2,"runchecks":15,"sysinfo":20}[command]},call
        setup(scope);before=list(Agent.objects.order_by("id").values())
        if subscribe:
            with responder(target,wire if wire is not None else replies) as peer:
                actual=go_request(method,path,user_id=user)
            messages=peer.messages
        else:
            actual=go_request(method,path,user_id=user);messages=None
        assert actual==expected,(command,target,method,user,scope,expected,actual)
        if messages is not None:
            # Invalid ping replies fail closed immediately instead of repeating malformed responses.
            if wire is not None and command=="ping" and expected_messages:expected_messages=expected_messages[:1]
            assert messages==expected_messages,(command,target,user,scope,"commands",expected_messages,messages)
        assert list(Agent.objects.order_by("id").values())==before,"command changed agent DB row"
        assert snapshot()==expected_base,(command,user,scope,"DB auth/audit state")
        count+=1

    try:
        for command in ("ping","runchecks"):
            for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (allowed,other,missing):
                    compare(command,["pong" if command=="ping" else "ok"],user=user,scope=scope,target=target)
        for user,scope in [(1,"all"),(2,"manage"),(2,"client")]:
            compare("ping",["pong"],user=user,scope=scope,method="HEAD")
        compare("ping",["not-pong","pong"])
        compare("ping",["not-pong"])
        for reply in ("busy","timeout","natsdown","unexpected",{"reply":"ok"}):
            compare("runchecks",[reply])
        compare("ping",[{}],wire=[b"\xc1"])
        compare("runchecks",[{}],wire=[b"\xc1"])
        compare("ping",["timeout"],subscribe=False)
        compare("runchecks",["timeout"],subscribe=False)
        for user,scope in [(1,"all"),(2,"all"),(2,"manage"),(2,"manage-client"),(2,"manage-site"),(2,"denied"),(3,"manage"),(4,"manage"),(5,"manage"),(6,"manage")]:
            for target in (allowed,other,missing):
                compare("sysinfo",["ok"],user=user,scope=scope,target=target)
        for reply in ("timeout","natsdown","unexpected",{"reply":"ok"},None):
            compare("sysinfo",[reply],wire=[{}] if reply is None else None)
        compare("sysinfo",[{}],wire=[b"\xc1"])
        compare("sysinfo",["timeout"],subscribe=False)
        print(f"Agent command contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();seed()
