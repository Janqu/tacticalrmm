"""Synchronous collector contracts: only disposable schema and local NATS peer."""
import copy
import hashlib
import json
import queue
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    import psycopg
    from psycopg import sql
    from accounts.models import Role, User
    from agents.models import Agent, AgentCustomField, AgentHistory
    from clients.models import Client, Site, ClientCustomField, SiteCustomField
    from core.models import CustomField
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.test import APIClient
    from scripts.models import Script

    subject, other = "script-collector-agent-31", "script-collector-agent-32"
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    command={"script":31,"output":"collector","args":[],"env_vars":[],"timeout":10,"run_as_user":False,"custom_field":301,"save_all_output":False}
    bindings={"agent":AgentCustomField,"site":SiteCustomField,"client":ClientCustomField}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema=cursor.fetchone()[0]
    assert schema.startswith("go_contract_")
    options=connection.get_connection_params();options["connect_timeout"]=2
    count=0

    def setup(model="agent",kind="text",existing=True,scope="all"):
        Agent.objects.all().delete();CustomField.objects.filter(pk__in=[301,302]).delete();Script.objects.filter(pk=31).delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Collector ü",site_id=31),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        Script.objects.bulk_create([Script(id=31,name="Collector fixture",shell="powershell",script_body="fixture only")])
        Script.objects.filter(pk=31).update(created_time=fixed,modified_time=fixed)
        CustomField.objects.bulk_create([
            CustomField(id=301,model=model,type=kind,name="Collector",options=["choice"],default_value_string="default is not copied",default_value_bool=True,default_values_multiple=["default"]),
            CustomField(id=302,model=model,type="text",name="Unrelated"),
        ])
        CustomField.objects.filter(pk__in=[301,302]).update(created_time=fixed,modified_time=fixed)
        field_model=bindings[model]
        values=[field_model(id=32,field_id=301,**{model+"_id":32},string_value="other",bool_value=True,multiple_value=["other"]),field_model(id=33,field_id=302,**{model+"_id":31},string_value="unrelated")]
        if existing:values.append(field_model(id=31,field_id=301,**{model+"_id":31},string_value="old",bool_value=True,multiple_value=["keep","columns"]))
        field_model.objects.bulk_create(values)
        with connection.cursor() as cursor:
            for table in ("agents_agenthistory",field_model._meta.db_table):
                cursor.execute("SELECT setval(pg_get_serial_sequence(%s,'id'),100,false)",[table])
        Role.objects.filter(pk=1).update(can_run_scripts=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(31)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def values_state():
        return {model._meta.db_table:list(model.objects.order_by("id").values()) for model in (CustomField,AgentCustomField,SiteCustomField,ClientCustomField)}

    def state(auth=True):
        histories=list(AgentHistory.objects.order_by("id").values())
        for row in histories:
            assert abs((row["time"]-datetime.now(timezone.utc)).total_seconds())<15
            row["time"]="<now>"
        return {"base":{k:v for k,v in snapshot().items() if auth or k!="tokens"},"history":histories,"fields":values_state()}

    def assert_committed(payload):
        with psycopg.connect(**options) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql.SQL("SELECT type,script_id,custom_field_id FROM {}.agents_agenthistory WHERE id=%s").format(sql.Identifier(schema)),[payload["id"]])
                assert cursor.fetchone()==("script_run",31,None),"synchronous collector history must be committed, without callback collector flag"
                cursor.execute(sql.SQL("SELECT count(*) FROM {}.logs_auditlog WHERE action='execute_script'").format(sql.Identifier(schema)))
                assert cursor.fetchone()[0]==1

    def compare(model="agent",kind="text",reply="  first\n last ü \n ",*,whole=False,existing=True,user=1,scope="all",target=subject):
        nonlocal count
        data={**command,"save_all_output":whole}
        setup(model,kind,existing,scope);calls=[]
        async def reference(*args,**kwargs):
            assert kwargs=={"timeout":13,"wait":True},kwargs
            payload=copy.deepcopy(args[0]);calls.append(payload);assert_committed(payload)
            return reply
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        path=f"/agents/{target}/runscript/"
        with patch.object(Agent,"nats_cmd",new=AsyncMock(side_effect=reference)),patch("celery.app.task.Task.apply_async") as jobs:
            response=client.post(path,data,format="json")
        jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(model,kind,existing,scope)
        def receive(payload):assert_committed(payload);return reply
        with responder(target,[receive]) as peer:actual=go_request("POST",path,data,user_id=user)
        assert actual==expected,(model,kind,reply,whole,user,scope,target,expected,actual)
        assert peer.messages==calls,("payload/retry",peer.messages,calls)
        assert state()==expected_state,("collector state mismatch",model,kind,whole,existing,expected_state,state())
        count+=1

    try:
        for model in bindings:
            for kind in ("text","number","single","datetime","multiple","checkbox"):
                for existing in (False,True):
                    for whole in (False,True):compare(model,kind,whole=whole,existing=existing)
            for reply in ("", "false", "0", "  \n ", " a,, b, ", "x\r\n y \r\n", "\u001c x \u001f"):
                compare(model,"checkbox",reply)
                compare(model,"multiple",reply,whole=True)
            compare(model,"text"," \n\t\u001c\u001f ")
        for user,scope in ((2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"all"),(6,"all")):
            for target in (subject,other):compare(user=user,scope=scope,target=target)
        # Site-scoped permission to run the agent retains source behavior when
        # the collector targets its parent client, without extra edit permission.
        compare("client",user=2,scope="site")
        for model in bindings:
            for reply,status in (("timeout",400),("natsdown",400),(b"\xc1",502),(b"\xc0",502),({},502),(["line"],502),(True,502)):
                setup(model,existing=False);before=values_state()
                with responder(subject,[reply]) as peer:actual=go_request("POST",f"/agents/{subject}/runscript/",command)
                assert actual[0]==status and len(peer.messages)==1,(reply,actual)
                assert values_state()==before and AgentHistory.objects.count()==1
                count+=1
        for changes,status in (({"custom_field":999},404),({"custom_field":True},400),({"save_all_output":"false"},400)):
            setup();before=state(auth=False)
            with responder(subject,["output"]) as peer:actual=go_request("POST",f"/agents/{subject}/runscript/",{**command,**changes})
            assert actual[0]==status and not peer.messages,(changes,actual)
            assert state(auth=False)==before
            count+=1
        # Concurrent edits are external committed changes; the late collector
        # must not write to a deleted or differently typed target.
        for change,status in (("delete",404),("type",409),("model",409)):
            setup(existing=False)
            def changed(payload):
                assert_committed(payload)
                with psycopg.connect(**options) as conn:
                    with conn.cursor() as cursor:
                        if change=="delete":
                            cursor.execute(sql.SQL("DELETE FROM {}.agents_agentcustomfield WHERE field_id=301").format(sql.Identifier(schema)))
                            cursor.execute(sql.SQL("DELETE FROM {}.core_customfield WHERE id=301").format(sql.Identifier(schema)))
                        else:
                            cursor.execute(sql.SQL("UPDATE {}.core_customfield SET {}=%s WHERE id=301").format(sql.Identifier(schema),sql.Identifier(change)),["checkbox" if change=="type" else "site"])
                return "output"
            with responder(subject,[changed]) as peer:actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==status and len(peer.messages)==1,(change,actual)
            assert not AgentCustomField.objects.filter(agent_id=31,field_id=301).exists()
            assert not SiteCustomField.objects.filter(field_id=301).exists()
            assert AgentHistory.objects.count()==1 and AuditLog.objects.filter(action="execute_script").count()==1
            count+=1
        # A target agent/site ID alone does not capture its parent-client scope.
        # Moving the site during execution invalidates both collector targets.
        for model in ("agent","site"):
            setup(model,existing=False);before=values_state()
            def moved(payload):
                assert_committed(payload)
                with psycopg.connect(**options) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(sql.SQL("UPDATE {}.clients_site SET client_id=32 WHERE id=31").format(sql.Identifier(schema)))
                return "must not save"
            with responder(subject,[moved]) as peer:actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==409 and len(peer.messages)==1,(model,actual)
            assert values_state()==before,"parent-client move must prevent field writes"
            assert Site.objects.get(pk=31).client_id==32,"external site move was lost"
            assert AgentHistory.objects.count()==1 and AuditLog.objects.filter(action="execute_script").count()==1
            count+=1
        for model in ("site","client"):
            field_model=bindings[model]
            setup(model)
            field_model.objects.bulk_create([field_model(id=34,field_id=301,**{model+"_id":31},string_value="duplicate")])
            before=state(auth=False)
            with responder(subject,["must not execute"]) as peer:
                actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==409 and not peer.messages,(model,actual)
            assert state(auth=False)==before,"duplicate values must reject before history/audit/dispatch"
            count+=1

        # The site/client value tables have no uniqueness constraint. Two
        # different agents share the same absent target: both execute, then the
        # short persistence transaction must serialize create-or-update.
        for model in ("site","client"):
            setup(model,existing=False)
            Agent.objects.filter(pk=32).update(site_id=31)
            barrier=threading.Barrier(2,timeout=5)
            results=queue.Queue()
            def concurrent_reply(payload,agent_pk,text):
                with psycopg.connect(**options) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(sql.SQL("SELECT agent_id,type,script_id FROM {}.agents_agenthistory WHERE id=%s").format(sql.Identifier(schema)),[payload["id"]])
                        assert cursor.fetchone()==(agent_pk,"script_run",31),"concurrent history not committed"
                barrier.wait()
                return text
            def execute(target):
                try:results.put((target,go_request("POST",f"/agents/{target}/runscript/",command),None))
                except Exception as error:results.put((target,None,error))
            with responder(subject,[lambda payload:concurrent_reply(payload,31,"first output")]) as first_peer, responder(other,[lambda payload:concurrent_reply(payload,32,"second output")]) as second_peer:
                workers=[threading.Thread(target=execute,args=(target,),daemon=True) for target in (subject,other)]
                for worker in workers:worker.start()
                for worker in workers:worker.join(timeout=20)
                assert all(not worker.is_alive() for worker in workers),"concurrent collector did not finish within bound"
                actual=[results.get(timeout=1) for _ in workers]
            expected={subject:(200,"first output"),other:(200,"second output")}
            assert all(error is None and response==expected[target] for target,response,error in actual),(model,actual)
            assert len(first_peer.messages)==len(second_peer.messages)==1,"concurrent execution retried"
            assert first_peer.messages[0]["id"]!=second_peer.messages[0]["id"]
            stored=bindings[model].objects.filter(field_id=301,**{model+"_id":31})
            assert stored.count()==1,"simultaneous collectors created duplicate target values"
            assert stored.get().string_value in ("first output","second output")
            assert AgentHistory.objects.count()==2 and AuditLog.objects.filter(action="execute_script").count()==2
            assert bindings[model].objects.get(pk=32).string_value=="other"
            assert bindings[model].objects.get(pk=33).string_value=="unrelated"
            count+=1
        for model,field_model in bindings.items():
            for existing in (False,True):
                setup(model,existing=existing);before=values_state()
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL("ALTER TABLE {} ADD CONSTRAINT collector_reject CHECK (string_value IS DISTINCT FROM 'reject') NOT VALID").format(sql.Identifier(field_model._meta.db_table)))
                try:
                    with responder(subject,["reject"]) as peer:actual=go_request("POST",f"/agents/{subject}/runscript/",command)
                    assert actual[0]==500 and len(peer.messages)==1,actual
                    assert values_state()==before,"new/updated value must roll back atomically"
                    assert AgentHistory.objects.count()==1 and AuditLog.objects.filter(action="execute_script").count()==1
                    count+=1
                finally:
                    with connection.cursor() as cursor:cursor.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT collector_reject").format(sql.Identifier(field_model._meta.db_table)))
        print(f"Script collector contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();CustomField.objects.filter(pk__in=[301,302]).delete();Script.objects.filter(pk=31).delete();seed()
