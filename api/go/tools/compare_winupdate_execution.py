"""Windows scan/install publication and token-authenticated results, all isolated/local."""
import copy
import hashlib
import json
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdate, WinUpdatePolicy
    from nats_fixture import responder

    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    subject="update-scan-agent-000031"
    other="update-scan-agent-000032"
    missing="update-scan-agent-missing"
    token={pk:hashlib.sha1(f"isolated-winupdate-agent-{pk}".encode()).hexdigest() for pk in (31,32,33,34)}
    headers={"Authorization":"Token "+token[31]}
    count=0
    new={"guid":"new","kb_article_ids":["100"],"title":"  Unicode Ä update  ","description":None,"severity":"Important","categories":["Security",None],"category_ids":[],"more_info_urls":["https://example.invalid/a"],"support_url":None,"revision_number":3,"downloaded":False,"installed":False}

    def setup(scope="all",platform="windows",*,approve_critical=False):
        Token.objects.all().delete();Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Scan fixture",site_id=31,plat=platform),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=pk,username=f"scan-callback-{pk}",agent_id=pk if pk in (31,32) else None,is_active=pk!=33,date_joined=fixed) for pk in token])
        User.objects.filter(pk__in=token).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.bulk_create([Token(key=value,user_id=pk) for pk,value in token.items()]);Token.objects.update(created=fixed)
        policies=[WinUpdatePolicy(id=31,agent_id=31),WinUpdatePolicy(id=32,agent_id=32)]
        if approve_critical:policies[0].critical="approve"
        WinUpdatePolicy.objects.bulk_create(policies)
        WinUpdatePolicy.objects.update(created_time=fixed,modified_time=fixed)
        WinUpdate.objects.bulk_create([
            WinUpdate(id=31,agent_id=31,guid="known",kb="KB31",title="earlier duplicate",action="ignore",installed=True,result="success",date_installed=fixed),
            WinUpdate(id=32,agent_id=31,guid="known",kb="KB32",title="highest duplicate",action="approve",result="failed"),
            WinUpdate(id=33,agent_id=31,guid="stale",kb="KB33"),
            WinUpdate(id=34,agent_id=31,guid="installed",kb="KB34",installed=True),
            WinUpdate(id=35,agent_id=31,guid=None,kb=None,action="approve"),
            WinUpdate(id=36,agent_id=32,guid="known",kb="KB36"),
            WinUpdate(id=41,agent_id=31,guid="oldversion",kb="KB41",title="Update (Version 1.0)",installed=True),
            WinUpdate(id=42,agent_id=31,guid="newversion",kb="KB41",title="Update (Version 2.0)",installed=True),
            WinUpdate(id=50,agent_id=31,guid="critical-pending",kb="KB50",severity="Critical",action="ignore"),
        ])
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdate','id'),100,false)");cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdatepolicy','id'),100,false)")
        Role.objects.filter(pk=1).update(can_manage_winupdates=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        return {"base":snapshot(),"agents":list(Agent.objects.order_by("id").values()),"history":list(AgentHistory.objects.order_by("id").values()),"pending":list(PendingAction.objects.order_by("id").values()),"updates":list(WinUpdate.objects.order_by("id").values()),"policies":list(WinUpdatePolicy.objects.order_by("id").values()),"agent_tokens":list(Token.objects.order_by("key").values())}

    def normalize_install_message(message):
        return {"func":message["func"],"guids":sorted(message.get("guids") or [],key=lambda value:(value is not None,value or ""))}

    def client_for(auth):
        client=APIClient();client.credentials(**{"HTTP_"+k.upper().replace("-","_"):v for k,v in auth.items()});return client

    def compare_callback(data,*,endpoint="winupdates",auth=None,method="POST",platform="windows"):
        nonlocal count
        auth=headers if auth is None else auth
        path=f"/api/v3/{endpoint}/"
        setup(platform=platform)
        with patch.object(Agent,"nats_cmd") as commands,patch("celery.app.task.Task.apply_async") as jobs:
            response=client_for(auth).generic(method,path,json.dumps(data),content_type="application/json")
        commands.assert_not_called();jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(platform=platform)
        actual=go_request(method,path,data,headers=auth)
        assert actual==expected,(endpoint,method,expected,actual)
        assert state()==expected_state,(endpoint,method,"callback DB mismatch")
        count+=1

    def reject_callback(data,*,endpoint="winupdates",method="POST",status=400):
        nonlocal count
        setup();before=state()
        actual=go_request(method,f"/api/v3/{endpoint}/",data,headers=headers)
        assert actual[0]==status,(endpoint,data,actual)
        assert state()==before,"Rejected callback partially mutated state"
        count+=1

    def compare_scan(*,user=1,scope="all",target=subject,platform="windows",method="POST",with_callback=False,subscribe=True):
        nonlocal count
        path=f"/winupdate/{target}/scan/"
        scan_result={"wua_updates":[{"guid":"known","installed":True,"downloaded":True},copy.deepcopy(new)]}
        setup(scope,platform)
        auth={"Authorization":"Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest()}
        fake=AsyncMock(return_value=None)
        with patch.object(Agent,"nats_cmd",fake),patch("celery.app.task.Task.apply_async") as jobs:
            response=client_for(auth).generic(method,path,json.dumps({}),content_type="application/json")
        jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_messages=[]
        for call in fake.call_args_list:
            assert call.args==({"func":"getwinupdates"},) and call.kwargs=={"wait":False},call
            expected_messages.append(call.args[0])
        if with_callback:
            response=client_for(headers).post("/api/v3/winupdates/",scan_result,format="json")
            assert response.status_code==200
        expected_state=state()
        setup(scope,platform)
        seen=threading.Event();callback_results=[]
        def peer_received(payload):
            if with_callback:callback_results.append(go_request("POST","/api/v3/winupdates/",scan_result,headers=headers))
            seen.set()
            return None # publication has no reply subject; flush is not an execution acknowledgement
        if subscribe:
            with responder(target,[peer_received]) as peer:
                actual=go_request(method,path,{},user_id=user)
                if expected_messages:assert seen.wait(5),"Agent did not observe published scan"
                assert peer.messages==expected_messages,(method,user,scope,peer.messages,expected_messages)
        else:
            actual=go_request(method,path,{},user_id=user)
        if with_callback:assert callback_results==[(200,"ok")],callback_results
        assert actual==expected,(method,user,scope,target,expected,actual)
        assert state()==expected_state,"Scan/callback changed unexpected data"
        count+=1

    def compare_install(*,user=1,scope="all",target=subject,platform="windows",method="POST",subscribe=True,approve_critical=False):
        nonlocal count
        path=f"/winupdate/{target}/install/"
        setup(scope,platform,approve_critical=approve_critical)
        auth={"Authorization":"Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest()}
        fake=AsyncMock(return_value=None)
        with patch.object(Agent,"nats_cmd",fake),patch("celery.app.task.Task.apply_async") as jobs:
            response=client_for(auth).generic(method,path,json.dumps({}),content_type="application/json")
        jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_messages=[]
        for call in fake.call_args_list:
            assert call.kwargs=={"wait":False},call
            assert call.args[0]["func"]=="installwinupdates",call
            expected_messages.append(normalize_install_message(call.args[0]))
        expected_state=state()
        setup(scope,platform,approve_critical=approve_critical)
        seen=threading.Event()
        def peer_received(payload):
            seen.set()
            return None
        if subscribe:
            with responder(target,[peer_received]) as peer:
                actual=go_request(method,path,{},user_id=user)
                if expected_messages:assert seen.wait(5),"Agent did not observe published install"
                assert [normalize_install_message(message) for message in peer.messages]==expected_messages,(method,user,scope,peer.messages,expected_messages)
        else:
            actual=go_request(method,path,{},user_id=user)
        assert actual==expected,(method,user,scope,target,expected,actual)
        assert state()==expected_state,"Install changed unexpected data"
        count+=1

    def reject_posix_install(platform):
        nonlocal count
        # Django installs without a platform guard; Go rejects before mutation.
        setup(platform=platform)
        before=state()
        actual=go_request("POST",f"/winupdate/{subject}/install/",{})
        assert actual==(400,f"Not available for {platform}"),actual
        after=state()
        # Auth may refresh Knox expiry; prune/approve/policy rows must stay untouched.
        for key in ("agents","history","pending","updates","policies"):
            assert after[key]==before[key],(platform,key)
        count+=1

    try:
        for auth in (headers,{}, {"Authorization":"Token invalid"},{"Authorization":"Token "+token[33]},{"Authorization":"Token "+token[34]},{"Authorization":"Token "+hashlib.sha256(b"contract-user-1").hexdigest()},{"X-API-KEY":"valid-api-key"}):
            compare_callback({"wua_updates":[copy.deepcopy(new)]},auth=auth)
            compare_callback({"guid":"known"},endpoint="superseded",auth=auth)
        for payload in (
            {"wua_updates":[]},{"wua_updates":None},{"wua_updates":False},
            {"wua_updates":[{"guid":"known","downloaded":True,"installed":True}]},
            {"wua_updates":[copy.deepcopy(new)]},
            {"wua_updates":[copy.deepcopy(new),{"guid":"new","downloaded":True,"installed":True}]},
            {"wua_updates":[{"guid":"skip","kb_article_ids":[]}]},
            {"wua_updates":[{"guid":"skip","kb_article_ids":[1]}]},
            {"wua_updates":[{"guid":None,"downloaded":False,"installed":False}]},
            {"wua_updates":[{"guid":"known","installed":False,"downloaded":True,"agent":32,"action":"ignore","title":"must stay"}]},
        ):compare_callback(payload)
        for guid in ("known",None,"missing",""):
            compare_callback({"guid":guid},endpoint="superseded")
        compare_callback({"guid":"known"},endpoint="superseded",auth={"Authorization":"Token "+token[32]})
        for platform in ("linux","darwin"):
            compare_callback({"wua_updates":[copy.deepcopy(new)]},platform=platform)
        for endpoint in ("winupdates","superseded"):
            for method in ("GET","HEAD","DELETE"):
                compare_callback({},endpoint=endpoint,method=method)
        for method in ("PUT","PATCH"):
            compare_callback({},endpoint="superseded",method=method)
        for payload in ({},[],{"wua_updates":"bad"},{"wua_updates":[None]},{"wua_updates":[{"guid":[]} ]}, {"wua_updates":[{"guid":"known","downloaded":True,"installed":True},{"guid":"known","installed":False}]}, {"wua_updates":[{"guid":"new","kb_article_ids":["1"]}]}):
            reject_callback(payload)
        for key,value in [("revision_number",2147483648),("categories",{}),("installed","true"),("severity","x"*256),("title",42)]:
            item=copy.deepcopy(new);item[key]=value
            reject_callback({"wua_updates":[{"guid":"known","downloaded":True,"installed":True},item]})
        reject_callback({},endpoint="superseded")
        reject_callback({"guid":[]},endpoint="superseded")
        # Insert/delete failures must roll back earlier updates and stale/superseded pruning.
        setup();before=state()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE winupdate_winupdate ADD CONSTRAINT scan_callback_reject CHECK (guid IS DISTINCT FROM 'new') NOT VALID")
        try:
            actual=go_request("POST","/api/v3/winupdates/",{"wua_updates":[{"guid":"known","installed":True,"downloaded":True},copy.deepcopy(new)]},headers=headers)
            assert actual[0]==500 and state()==before,(actual,"scan rollback")
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE winupdate_winupdate DROP CONSTRAINT scan_callback_reject")
        for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
            for target in (subject,other,missing):compare_scan(user=user,scope=scope,target=target)
        for method in ("GET","HEAD","PUT","PATCH","DELETE"):compare_scan(method=method)
        for platform in ("linux","darwin"):compare_scan(platform=platform)
        compare_scan(subscribe=False) # successful broker flush does not imply an agent subscriber exists
        compare_scan(with_callback=True)
        # Invalid concrete subject is rejected before publication; pruning has already committed.
        setup()
        wildcard=subject+"*"
        Agent.objects.filter(pk=31).update(agent_id=wildcard)
        Agent.objects.get(pk=31).delete_superseded_updates()
        expected=state();expected["base"].pop("tokens")
        actual=go_request("POST",f"/winupdate/{wildcard}/scan/",{})
        assert actual==(503,"Unable to publish the Windows update scan request."),actual
        observed=state();observed["base"].pop("tokens")
        assert observed==expected,"Known publication failure changed more than the committed prune"
        count+=1
        for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
            for target in (subject,other,missing):compare_install(user=user,scope=scope,target=target)
        for method in ("GET","HEAD","PUT","PATCH","DELETE"):compare_install(method=method)
        for platform in ("linux","darwin"):reject_posix_install(platform)
        compare_install(subscribe=False)
        compare_install(approve_critical=True)
        setup()
        wildcard=subject+"*"
        Agent.objects.filter(pk=31).update(agent_id=wildcard)
        agent=Agent.objects.get(pk=31)
        agent.delete_superseded_updates()
        agent.approve_updates()
        expected=state();expected["base"].pop("tokens")
        actual=go_request("POST",f"/winupdate/{wildcard}/install/",{})
        assert actual==(503,"Unable to publish the Windows update install request."),actual
        observed=state();observed["base"].pop("tokens")
        assert observed==expected,"Known install publication failure changed more than the committed prune/approve"
        count+=1
        print(f"Windows scan/install execution contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();seed()
