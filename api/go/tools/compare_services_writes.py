"""Service write contracts against mock Django and an isolated local NATS peer."""
import copy
import hashlib
import json
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from nats_fixture import responder


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from logs.models import PendingAction
    from rest_framework.test import APIClient

    subject="service-write-agent-000031"
    other="service-write-agent-000032"
    missing="service-write-missing-00999"
    ok={"success":True,"errormsg":""}
    failed={"success":False,"errormsg":"Access denied"}
    base_path=f"/services/{subject}/Spooler/"

    def cleanup():
        Agent.objects.all().delete()

    def setup(scope="all",platform="windows"):
        cleanup();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([
            Agent(id=31,agent_id=subject,hostname="Service fixture",site_id=31,plat=platform,services=[{"name":"cached","status":"stopped"}]),
            Agent(id=32,agent_id=other,hostname="Other fixture",site_id=32),
        ])
        Role.objects.filter(pk=1).update(can_manage_winsvcs=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def data_state():
        return {model._meta.db_table:list(model.objects.order_by("id").values()) for model in (Agent,AgentHistory,PendingAction)}

    def auth_without_tokens():
        return {key:value for key,value in snapshot().items() if key!="tokens"}

    count=0
    def compare(method,data,replies,*,user=1,scope="all",target=subject,platform="windows",name="Spooler",subscribe=True):
        nonlocal count
        path=f"/services/{target}/{quote(name,safe='')}/"
        setup(scope,platform);before=data_state()
        messages=[];timeouts=[];reply_index=0
        async def reference(*args,**kwargs):
            nonlocal reply_index
            # Source mutates the same payload stop->start on restart; snapshot at each call.
            messages.append(copy.deepcopy(args[0] if args else kwargs["data"]))
            timeouts.append(kwargs["timeout"])
            value=replies[min(reply_index,len(replies)-1)];reply_index+=1
            return value
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        with patch.object(Agent,"nats_cmd",new=AsyncMock(side_effect=reference)),patch("celery.app.task.Task.apply_async") as tasks:
            response=client.generic(method,path,json.dumps(data),content_type="application/json")
            tasks.assert_not_called()
        expected=(response.status_code,json.loads(response.content) if response.content else None)
        assert timeouts==[32 if method=="POST" else 10]*len(messages),(method,timeouts)
        assert data_state()==before,"Django service action changed DB"
        expected_base=snapshot()
        setup(scope,platform);before=data_state()
        if subscribe:
            with responder(target,replies) as peer:actual=go_request(method,path,data,user_id=user)
            assert peer.messages==messages,(method,data,target,user,scope,messages,peer.messages)
        else:actual=go_request(method,path,data,user_id=user)
        assert actual==expected,(method,data,replies,target,user,scope,expected,actual)
        assert data_state()==before,"Go service action changed DB"
        assert snapshot()==expected_base,(method,data,user,scope,"audit/auth state")
        count+=1

    try:
        for method,data in [("POST",{"sv_action":"start"}),("POST",{"sv_action":"stop"}),("POST",{"sv_action":"restart"}),("PUT",{"startType":"auto"})]:
            for reply in [ok,failed,{"success":False,"errormsg":""},{"success":False,"errormsg":"timeout"},{"success":True,"errormsg":"timeout"},{"success":True,"errormsg":"warning"},"timeout","natsdown","other error"]:
                compare(method,data,[reply])
        for second in [failed,{"success":False,"errormsg":""},"timeout","natsdown"]:
            compare("POST",{"sv_action":"restart"},[ok,second])
        # Each supported startup type is sent unchanged, including POSIX PUT source behavior.
        for start_type in ("auto","autodelay","manual","disabled"):
            compare("PUT",{"startType":start_type},[ok])
        for platform in ("linux","darwin"):
            compare("POST",{"sv_action":"restart"},[ok],platform=platform)
            compare("PUT",{"startType":"manual"},[ok],platform=platform)
        for method,data in [("POST",{"sv_action":"restart"}),("PUT",{"startType":"disabled"})]:
            for user,scope in [(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (subject,other,missing):compare(method,data,[ok],user=user,scope=scope,target=target)
            compare(method,data,["timeout"],subscribe=False)
        for name in ("Print Spooler","Dienst-Ä","name%literal","name+plus"):
            compare("POST",{"sv_action":"restart"},[ok],name=name)
            compare("PUT",{"startType":"manual"},[ok],name=name)

        # Strict reply parsing: malformed replies fail closed, and stop never retries/starts.
        malformed=[b"\xc1",{}, {"success":True}, {"errormsg":""}, {"success":"yes","errormsg":""}, {"success":True,"errormsg":None},False,[],12]
        for method,data in [("POST",{"sv_action":"start"}),("POST",{"sv_action":"restart"}),("PUT",{"startType":"manual"})]:
            for reply in malformed:
                setup();before=data_state();base=auth_without_tokens()
                with responder(subject,[reply]) as peer:actual=go_request(method,base_path,data)
                assert actual[0]==502,(method,data,reply,actual)
                assert len(peer.messages)==1,"malformed response caused another service command"
                assert data_state()==before and auth_without_tokens()==base
                count+=1
        setup();before=data_state();base=auth_without_tokens()
        with responder(subject,[ok,b"\xc1"]) as peer:actual=go_request("POST",base_path,{"sv_action":"restart"})
        assert actual[0]==502,actual
        assert peer.messages==[{"func":"winsvcaction","payload":{"name":"Spooler","action":action}} for action in ("stop","start")]
        assert data_state()==before and auth_without_tokens()==base
        count+=1

        invalid=[("POST",{}),("POST",{"sv_action":"pause"}),("POST",{"sv_action":None}),("POST",{"sv_action":True}),("POST",{"sv_action":["start"]}),("POST",{"sv_action":" start "}),
                 ("PUT",{}),("PUT",{"startType":"Automatic"}),("PUT",{"startType":None}),("PUT",{"startType":2}),("PUT",{"startType":[]}),("PUT",{"startType":" auto "})]
        for method,data in invalid:
            setup();before=data_state();base=auth_without_tokens()
            with responder(subject,[ok]) as peer:actual=go_request(method,base_path,data)
            assert actual[0]==400,(method,data,actual)
            assert peer.messages==[],"invalid action/startup type reached NATS"
            assert data_state()==before and auth_without_tokens()==base
            count+=1
        print(f"Service write contracts: {count} comparisons passed")
        return count
    finally:
        cleanup();seed()
