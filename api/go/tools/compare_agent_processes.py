"""Process list/kill contracts use only an isolated local NATS responder."""
import hashlib
import json
from unittest.mock import AsyncMock, patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from logs.models import PendingAction
    from rest_framework.test import APIClient
    from nats_fixture import responder

    allowed="process-contract-agent-31"
    other="process-contract-agent-32"
    missing="process-contract-missing-99"
    payload=[{"pid":42,"name":"Äpp", "cpu":1.25,"memory":9007199254740993,"username":None}]

    def setup(scope="all"):
        Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=allowed,hostname="Host",site_id=31),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Role.objects.filter(pk=1).update(can_manage_procs=scope!="denied",can_list_agents=True)
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def data_state():
        return {model._meta.db_table:list(model.objects.order_by("id").values()) for model in (Agent,AgentHistory,PendingAction)}

    count=0
    def compare(method,reply,*,user=1,scope="all",target=allowed,pid="42",subscribe=True):
        nonlocal count
        path=f"/agents/{target}/processes/"+(pid+"/" if method=="DELETE" else "")
        setup(scope);before=data_state()
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        fake=AsyncMock(return_value=reply)
        with patch.object(Agent,"nats_cmd",fake):response=client.generic(method,path)
        expected=(response.status_code,json.loads(response.content) if response.content else None)
        assert data_state()==before,"Django process action changed DB"
        expected_base=snapshot()
        expected_messages=[]
        for call in fake.call_args_list:
            if method=="DELETE":
                assert call.kwargs=={"timeout":15},call
                expected_messages.append(call.args[0])
            else:
                assert call.kwargs=={"data":{"func":"procs"},"timeout":5},call
                expected_messages.append(call.kwargs["data"])
        setup(scope);before=data_state()
        if subscribe:
            with responder(target,[reply]) as peer:actual=go_request(method,path,user_id=user)
            assert peer.messages==expected_messages,(method,target,user,scope,expected_messages,peer.messages)
        else:actual=go_request(method,path,user_id=user)
        assert actual==expected,(method,target,user,scope,pid,expected,actual)
        assert data_state()==before,"Go process action changed DB"
        assert snapshot()==expected_base,(method,target,user,scope,"audit/auth state")
        count+=1

    try:
        for method in ("GET","HEAD","DELETE"):
            for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (allowed,other,missing):compare(method,"ok" if method=="DELETE" else payload,user=user,scope=scope,target=target)
        for method in ("GET","DELETE"):
            for reply in ("timeout","natsdown"):compare(method,reply)
            compare(method,"timeout",subscribe=False)
        compare("GET",[])
        compare("DELETE","Access denied")
        for pid in ("0","00042","2147483648","18446744073709551615"):compare("DELETE","ok",pid=pid)
        # Fail safely on malformed wire/type/schema rather than returning unusable process data.
        for method,reply in [("GET",b"\xc1"),("GET",{}),("GET",["invalid"]),("GET",True),("GET",[{"cpu":float("nan")}]),("DELETE",b"\xc1"),("DELETE",{}),("DELETE",False)]:
            setup();before=data_state();path=f"/agents/{allowed}/processes/"+("42/" if method=="DELETE" else "")
            with responder(allowed,[reply]) as peer:actual=go_request(method,path)
            assert actual[0]==502,(method,reply,actual)
            assert len(peer.messages)==1,"malformed response retried a command"
            assert data_state()==before
            count+=1
        setup();before=data_state()
        with responder(allowed,["ok"]) as peer:
            actual=go_request("DELETE",f"/agents/{allowed}/processes/18446744073709551616/")
        assert actual[0]==400,actual
        assert peer.messages==[],"overflowing PID published a command"
        assert data_state()==before
        count+=1
        print(f"Agent process contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();seed()
