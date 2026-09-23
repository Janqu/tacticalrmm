"""Chocolatey install and inventory refresh against an isolated local agent peer."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.test import APIClient
    from software.models import InstalledSoftware
    import psycopg
    from psycopg import sql

    subject="software-write-agent-0031"
    other="software-write-agent-0032"
    missing="software-write-missing-99"
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    inventory=[{"name":"App ü","version":"1.2", "size":18446744073709551615},None,True]
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema=cursor.fetchone()[0]
    assert schema.startswith("go_contract_"),"only an isolated contract schema is allowed"
    connect_options=connection.get_connection_params()
    connect_options["connect_timeout"]=2

    def setup(scope="all",platform="windows",mode="existing"):
        Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([
            Agent(id=31,agent_id=subject,hostname="Software fixture ü",site_id=31,plat=platform),
            Agent(id=32,agent_id=other,hostname="Other fixture",site_id=32),
        ])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        InstalledSoftware.objects.bulk_create([InstalledSoftware(id=32,agent_id=32,software=["other inventory"])])
        if mode!="missing":InstalledSoftware.objects.bulk_create([InstalledSoftware(id=31,agent_id=31,software=["old inventory"])])
        if mode=="duplicate":InstalledSoftware.objects.bulk_create([InstalledSoftware(id=30,agent_id=31,software=["first row must change"])])
        PendingAction.objects.bulk_create([PendingAction(id=31,agent_id=31,action_type="chocoinstall",details={"name":"unrelated","output":"keep","installed":True})])
        PendingAction.objects.filter(pk=31).update(entry_time=fixed)
        with connection.cursor() as cursor:
            for table in ("logs_pendingaction","software_installedsoftware"):
                cursor.execute("SELECT setval(pg_get_serial_sequence(%s,'id'),100,false)",[table])
        Role.objects.filter(pk=1).update(can_manage_software=scope!="denied",can_list_software=True)
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state(auth=True):
        result={model._meta.db_table:list(model.objects.order_by("id").values()) for model in (Agent,AgentHistory,PendingAction,InstalledSoftware)}
        for row in result["logs_pendingaction"]:
            if row["id"]!=31:
                assert abs((row["entry_time"]-datetime.now(timezone.utc)).total_seconds())<10
                row["entry_time"]="<current timestamp>"
        result["base"]={key:value for key,value in snapshot().items() if auth or key!="tokens"}
        return result

    def assert_pending_before_ack(payload, expected_agent=31):
        if payload.get("func")!="installwithchoco":return
        # A separate connection proves the row is committed and visible to agent callbacks.
        with psycopg.connect(**connect_options) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql.SQL("SELECT agent_id,action_type,status,details,entry_time FROM {}.logs_pendingaction WHERE id=%s").format(sql.Identifier(schema)),[payload["pending_action_pk"]])
                row=cursor.fetchone()
        assert row is not None,"pending action was not committed before agent publication"
        assert row[0]==expected_agent,"pending action belongs to the wrong agent"
        details=json.loads(row[3]) if isinstance(row[3],str) else row[3]
        assert (row[1],row[2],details)==("chocoinstall","pending",{"name":payload["choco_prog_name"],"output":None,"installed":False}),row
        assert abs((row[4]-datetime.now(timezone.utc)).total_seconds())<10

    count=0
    def compare(method,data,reply,*,user=1,scope="all",target=subject,platform="windows",mode="existing",subscribe=True):
        nonlocal count
        path=f"/software/{target}/"
        setup(scope,platform,mode)
        messages=[]
        async def reference(*args,**kwargs):
            payload=copy.deepcopy(args[0]);messages.append(payload)
            assert kwargs=={"timeout":2 if method=="POST" else 15},kwargs
            assert_pending_before_ack(payload,31 if target==subject else 32)
            return reply
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        with patch.object(Agent,"nats_cmd",new=AsyncMock(side_effect=reference)),patch("celery.app.task.Task.apply_async") as jobs:
            response=client.generic(method,path,json.dumps(data),content_type="application/json")
            jobs.assert_not_called()
        expected=(response.status_code,json.loads(response.content) if response.content else None)
        expected_state=state()
        setup(scope,platform,mode)
        def acknowledged(payload):
            assert_pending_before_ack(payload,31 if target==subject else 32)
            return reply
        if subscribe:
            with responder(target,[acknowledged]) as peer:actual=go_request(method,path,data,user_id=user)
            assert peer.messages==messages,(method,target,user,scope,messages,peer.messages)
        else:actual=go_request(method,path,data,user_id=user)
        assert actual==expected,(method,data,reply,target,user,scope,platform,mode,expected,actual)
        assert state()==expected_state,(method,data,reply,target,user,scope,mode,"state",expected_state,state())
        count+=1

    try:
        for method,data,reply in [("POST",{"name":"7zip"},"ok"),("PUT",{},inventory)]:
            for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (subject,other,missing):compare(method,data,reply,user=user,scope=scope,target=target)
            for platform in ("linux","darwin"):compare(method,data,reply,platform=platform)
            if method=="PUT":
                for error in ("timeout","natsdown"):compare(method,data,error)
                compare(method,data,"timeout",subscribe=False)
        for name in ("App ü","  package.name  ","pkg-with-dash","pkg+plus"):
            compare("POST",{"name":name},"ok")
        for error in ("busy","other failure",""):
            compare("POST",{"name":"7zip"},error)
        for mode in ("missing","existing","duplicate"):
            for reply in ([],inventory,{"nested":[True,False,9007199254740993]},"other string",False,12):
                compare("PUT",{},reply,mode=mode)

        for data in ({},{"name":None},{"name":""},{"name":"   "},{"name":True},{"name":12},{"name":["7zip"]}):
            setup();before=state(False)
            with responder(subject,["ok"]) as peer:actual=go_request("POST",f"/software/{subject}/",data)
            assert actual[0]==400,(data,actual)
            assert peer.messages==[] and state(False)==before,"invalid package created pending action or published"
            count+=1
        def retained_install(before, status="pending", details=None):
            expected=copy.deepcopy(before)
            expected["logs_pendingaction"].append({
                "id":100,"agent_id":31,"entry_time":"<current timestamp>",
                "action_type":"chocoinstall","status":status,
                "details":details or {"name":"7zip","output":None,"installed":False},
            })
            assert state(False)==expected,"ambiguous/completed install tracking was lost or unrelated data changed"

        # Safety difference from Django: uncertain delivery preserves callback tracking.
        for reply,status in [("timeout",400),("natsdown",400),(None,400),(b"\xc1",502),({},502),(["ok"],502),(True,502)]:
            setup();before=state(False)
            def uncertain(payload):
                assert_pending_before_ack(payload)
                return reply
            with responder(subject,[uncertain]) as peer:actual=go_request("POST",f"/software/{subject}/",{"name":"7zip"})
            assert actual[0]==status,(reply,actual)
            assert peer.messages==[{"func":"installwithchoco","choco_prog_name":"7zip","pending_action_pk":100}],"ambiguous install was retried"
            retained_install(before)
            count+=1
        setup();before=state(False)
        actual=go_request("POST",f"/software/{subject}/",{"name":"7zip"})
        assert actual==(400,"Unable to contact the agent"),actual
        retained_install(before)
        count+=1

        # A callback can finish before an explicit negative acknowledgement arrives.
        setup();before=state(False)
        completed_details={"name":"7zip","output":"Completed before acknowledgement","installed":True}
        def completed_before_negative(payload):
            assert_pending_before_ack(payload)
            with psycopg.connect(**connect_options) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql.SQL("UPDATE {}.logs_pendingaction SET status='completed',details=%s::jsonb WHERE id=%s").format(sql.Identifier(schema)),[json.dumps(completed_details),payload["pending_action_pk"]])
            return "explicit negative acknowledgement"
        with responder(subject,[completed_before_negative]) as peer:actual=go_request("POST",f"/software/{subject}/",{"name":"7zip"})
        assert actual==(400,"Unable to contact the agent"),actual
        assert peer.messages==[{"func":"installwithchoco","choco_prog_name":"7zip","pending_action_pk":100}]
        retained_install(before,"completed",completed_details)
        count+=1

        for reply in (b"\xc1",b"\xc0",[{"size":float("nan")}]):
            setup();before=state(False)
            with responder(subject,[reply]) as peer:actual=go_request("PUT",f"/software/{subject}/",{})
            assert actual[0]==502,(reply,actual)
            assert peer.messages==[{"func":"softwarelist"}]
            assert state(False)==before,"malformed refresh changed inventory"
            count+=1

        # Pending creation must succeed before publishing; failed refresh SQL preserves all rows.
        setup();before=state(False)
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction ADD CONSTRAINT software_contract_pending_reject CHECK (id < 100) NOT VALID")
        try:
            with responder(subject,["ok"]) as peer:actual=go_request("POST",f"/software/{subject}/",{"name":"7zip"})
            assert actual[0]==500,actual
            assert peer.messages==[] and state(False)==before
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction DROP CONSTRAINT software_contract_pending_reject")
        for mode in ("existing","missing"):
            setup(mode=mode);before=state(False)
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE software_installedsoftware ADD CONSTRAINT software_contract_refresh_reject CHECK (software IS DISTINCT FROM '\"blocked\"'::jsonb) NOT VALID")
            try:
                with responder(subject,["blocked"]) as peer:actual=go_request("PUT",f"/software/{subject}/",{})
                assert actual[0]==500,actual
                assert peer.messages==[{"func":"softwarelist"}]
                assert state(False)==before
                count+=1
            finally:
                with connection.cursor() as cursor:cursor.execute("ALTER TABLE software_installedsoftware DROP CONSTRAINT software_contract_refresh_reject")
        print(f"Software write contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();seed()
