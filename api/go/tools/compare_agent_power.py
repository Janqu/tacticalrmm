"""Reboot/shutdown scheduling contracts: local broker, never real agents."""
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from zoneinfo import ZoneInfo

from nats_fixture import responder


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.test import APIClient

    subject="power-contract-agent-00031"
    other="power-contract-agent-00032"
    missing="power-contract-missing-999"
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    future={"datetime":"2099-12-31T23:58"}
    task_name_re=re.compile(r"TacticalRMM_SchedReboot_[A-Za-z]{10}")

    def setup(scope="all",platform="windows",agent_tz="UTC",default_tz="UTC"):
        Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([
            Agent(id=31,agent_id=subject,hostname="Power fixture ü",site_id=31,plat=platform,time_zone=agent_tz),
            Agent(id=32,agent_id=other,hostname="Other fixture",site_id=32),
        ])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        CoreSettings.objects.update(default_time_zone=default_tz)
        PendingAction.objects.bulk_create([PendingAction(id=31,agent_id=31,action_type="choco_install",details={"name":"unchanged"})])
        PendingAction.objects.filter(pk=31).update(entry_time=fixed)
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence('logs_pendingaction','id'),100,false)")
        Role.objects.filter(pk=1).update(can_reboot_agents=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def data_state():
        return {model._meta.db_table:list(model.objects.order_by("id").values()) for model in (Agent,AgentHistory,PendingAction)}

    def mutation_state():
        return data_state(),{key:value for key,value in snapshot().items() if key!="tokens"}

    def normalize(result,messages):
        result=copy.deepcopy(result);messages=copy.deepcopy(messages)
        state=data_state()
        new=list(PendingAction.objects.exclude(pk=31).values())
        if result[0]==200 and isinstance(result[1],dict) and "task_name" in result[1]:
            name=result[1]["task_name"]
            assert task_name_re.fullmatch(name),name
            assert len(new)==1 and new[0]["details"]["taskname"]==name,(result,new)
            assert len(messages)==1 and messages[0]["schedtaskpayload"]["name"]==name,(result,messages)
            assert new[0]["status"]=="pending" and new[0]["action_type"]=="schedreboot",new
            assert abs((new[0]["entry_time"]-datetime.now(timezone.utc)).total_seconds())<10
            result[1]["task_name"]="<generated name>"
            messages[0]["schedtaskpayload"]["name"]="<generated name>"
            for row in state["logs_pendingaction"]:
                if row["id"]!=31:
                    row["details"]["taskname"]="<generated name>"
                    row["entry_time"]="<current timestamp>"
        else:
            assert new==[],"failed/instant power command created a pending action"
            for message in messages:
                if message.get("func")=="schedtask":
                    name=message["schedtaskpayload"]["name"]
                    assert task_name_re.fullmatch(name),name
                    message["schedtaskpayload"]["name"]="<generated name>"
        return result,messages,state,snapshot()

    count=0
    def compare(method,action,data,reply,*,user=1,scope="all",target=subject,platform="windows",agent_tz="UTC",default_tz="UTC",subscribe=True):
        nonlocal count
        path=f"/agents/{target}/{action}/"
        setup(scope,platform,agent_tz,default_tz)
        calls=[]
        async def reference(*args,**kwargs):
            calls.append(copy.deepcopy(args[0]))
            assert kwargs=={"timeout":10},kwargs
            return reply
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        with patch.object(Agent,"nats_cmd",new=AsyncMock(side_effect=reference)),patch("celery.app.task.Task.apply_async") as jobs:
            response=client.generic(method,path,json.dumps(data),content_type="application/json")
            jobs.assert_not_called()
        expected=(response.status_code,json.loads(response.content) if response.content else None)
        expected_bundle=normalize(expected,calls)
        setup(scope,platform,agent_tz,default_tz)
        if subscribe:
            with responder(target,[reply]) as peer:actual=go_request(method,path,data,user_id=user)
            actual_messages=peer.messages
        else:
            actual=go_request(method,path,data,user_id=user)
            # No live subscriber can capture requests here; response and DB are still compared.
            actual_messages=copy.deepcopy(calls)
        actual_bundle=normalize(actual,actual_messages)
        assert actual_bundle==expected_bundle,(method,action,data,reply,user,scope,platform,agent_tz,expected_bundle,actual_bundle)
        count+=1

    try:
        for method,action,data in [("POST","reboot",{}),("POST","shutdown",{}),("PATCH","reboot",future)]:
            for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                for target in (subject,other,missing):compare(method,action,data,"ok",user=user,scope=scope,target=target)
            for reply in ("timeout","natsdown","busy","permission denied"):
                compare(method,action,data,reply)
            compare(method,action,data,"timeout",subscribe=False)
        for platform in ("linux","darwin"):
            compare("PATCH","reboot",future,"ok",platform=platform)
            compare("POST","reboot",{},"ok",platform=platform)
            compare("POST","shutdown",{},"ok",platform=platform)
        for data in [{},{"datetime":None},{"datetime":123},{"datetime":"invalid"},{"datetime":"2099-01-01"},{"datetime":"2099-02-30T12:00"},{"datetime":"2099-01-01T12:00:00"},{"datetime":"2000-01-01T12:00"}]:
            compare("PATCH","reboot",data,"ok")
        for stamp in ("2099-1-2T3:4","2099-03-29T02:30","2099-10-25T02:30"):
            compare("PATCH","reboot",{"datetime":stamp},"ok",agent_tz="Europe/Berlin")
        for zone in ("Pacific/Honolulu","Asia/Tokyo","Europe/Berlin"):
            for delta in (-timedelta(hours=1),timedelta(hours=1)):
                stamp=(datetime.now(ZoneInfo(zone))+delta).strftime("%Y-%m-%dT%H:%M")
                compare("PATCH","reboot",{"datetime":stamp},"ok",agent_tz=zone)
                compare("PATCH","reboot",{"datetime":stamp},"ok",agent_tz="",default_tz=zone)

        compare("PATCH","reboot",future,"ok",agent_tz=None,default_tz="Europe/Berlin")
        setup();before=mutation_state()
        with responder(subject,["ok"]) as peer:actual=go_request("PATCH",f"/agents/{subject}/reboot/",{"datetime":"9999-12-31T23:59"})
        assert actual==(400,"Invalid date"),actual
        assert peer.messages==[] and mutation_state()==before
        count+=1

        # Instant commands report unavailable for any non-ok; schedules reject malformed replies.
        for method,action,data in [("POST","reboot",{}),("POST","shutdown",{}),("PATCH","reboot",future)]:
            for reply in (b"\xc1",{},["ok"],True):
                setup();before=mutation_state()
                with responder(subject,[reply]) as peer:actual=go_request(method,f"/agents/{subject}/{action}/",data)
                assert actual[0]==(502 if method=="PATCH" else 400),(method,reply,actual)
                assert len(peer.messages)==1,"power command retried"
                assert mutation_state()==before,"failed command changed database"
                count+=1

        # An acknowledged remote task cannot be recalled on a DB failure; do not retry publication.
        setup();before=mutation_state()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction ADD CONSTRAINT power_contract_reject CHECK (action_type IS DISTINCT FROM 'schedreboot') NOT VALID")
        try:
            with responder(subject,["ok"]) as peer:actual=go_request("PATCH",f"/agents/{subject}/reboot/",future)
            assert actual[0]==500,actual
            assert len(peer.messages)==1 and peer.messages[0]["func"]=="schedtask"
            assert mutation_state()==before,"failed pending insertion changed DB"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction DROP CONSTRAINT power_contract_reject")
        print(f"Agent power contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();seed()
