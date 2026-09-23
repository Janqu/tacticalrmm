"""Collector history callbacks: source parity plus atomic and concurrent writes."""
import hashlib
import json
import queue
import threading
from datetime import datetime, timezone
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from accounts.models import User
    from agents.models import Agent, AgentCustomField, AgentHistory, Note
    from clients.models import Client, Site, ClientCustomField, SiteCustomField
    from core.models import CustomField
    from django.db import connection
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from scripts.models import Script
    from psycopg import sql

    subject,other="collector-callback-agent-31","collector-callback-agent-32"
    tokens={pk:hashlib.sha1(f"collector-callback-{pk}".encode()).hexdigest() for pk in (31,32,33,34)}
    good={"Authorization":"Token "+tokens[31]}
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    bindings={"agent":AgentCustomField,"site":SiteCustomField,"client":ClientCustomField}
    count=0

    def setup(model="agent",kind="text",whole=False,existing=True,deleted=False,note=False,history_type="script_run"):
        Token.objects.all().delete();Agent.objects.all().delete();CustomField.objects.filter(pk=301).delete();Script.objects.filter(pk=31).delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="A",site_id=31),Agent(id=32,agent_id=other,hostname="B",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=pk,username=f"collector-callback-{pk}",agent_id=pk if pk in (31,32) else None,is_active=pk!=33,date_joined=fixed) for pk in tokens])
        User.objects.filter(pk__in=tokens).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.bulk_create([Token(key=value,user_id=pk,created=fixed) for pk,value in tokens.items()])
        Token.objects.update(created=fixed)
        Script.objects.bulk_create([Script(id=31,name="Collector",shell="powershell",script_body="fixture only")])
        Script.objects.filter(pk=31).update(created_time=fixed,modified_time=fixed)
        CustomField.objects.bulk_create([CustomField(id=301,model=model,type=kind,name="Collector",default_value_string="do not copy",default_value_bool=True,default_values_multiple=["do not copy"])])
        CustomField.objects.filter(pk=301).update(created_time=fixed,modified_time=fixed)
        field_model=bindings[model]
        field_model.objects.bulk_create([field_model(id=32,field_id=301,**{model+"_id":32},string_value="other",bool_value=True,multiple_value=["other"])])
        if existing:field_model.objects.bulk_create([field_model(id=31,field_id=301,**{model+"_id":31},string_value="old",bool_value=True,multiple_value=["keep"] )])
        AgentHistory.objects.bulk_create([
            AgentHistory(id=31,agent_id=31,type=history_type,script_id=None if deleted else 31,custom_field_id=301,collector_all_output=whole,save_to_agent_note=note,results="keep",script_results={"stdout":"old"}),
            AgentHistory(id=32,agent_id=32,type="script_run",script_id=31,custom_field_id=301,collector_all_output=whole,script_results={"stdout":"other"}),
        ])
        AgentHistory.objects.update(time=fixed)
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence(%s,'id'),100,false)",[field_model._meta.db_table])

    def state():
        return {"base":snapshot(),**{model._meta.db_table:list(model.objects.order_by("id").values()) for model in (AgentHistory,CustomField,AgentCustomField,SiteCustomField,ClientCustomField,Note)}}

    def body(stdout):
        return {"results":"  accompanying text  ","script_results":{"stdout":stdout,"stderr":" keep ","retcode":1,"execution_time":0.25,"extra":[18446744073709551615,None]}}

    def compare(stdout=" first\n last ü \n ",*,model="agent",kind="text",whole=False,existing=True,deleted=False,auth=None,pk=31,method="PATCH"):
        nonlocal count
        auth=good if auth is None else auth
        setup(model,kind,whole,existing,deleted)
        path=f"/api/v3/{pk}/{subject}/histresult/"
        client=APIClient();client.credentials(**{"HTTP_"+key.upper().replace("-","_"):value for key,value in auth.items()})
        with patch.object(Agent,"nats_cmd") as bus,patch("celery.app.task.Task.apply_async") as jobs:
            response=client.generic(method,path,json.dumps(body(stdout)),content_type="application/json")
        bus.assert_not_called();jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(model,kind,whole,existing,deleted)
        actual=go_request(method,path,body(stdout),headers=auth)
        if auth=={"Authorization":"Token "+tokens[34]}:
            assert expected==(404,{"detail":"No AgentHistory matches the given query."}),expected
            expected=(404,{"detail":"No Agent matches the given query."})
        assert actual==expected,(model,kind,whole,existing,method,pk,expected,actual)
        assert state()==expected_state,("collector callback state",model,kind,whole,existing)
        count+=1

    def rejected(payload,status=400,*,target=subject,**options):
        nonlocal count
        setup(**options);before=state()
        actual=go_request("PATCH",f"/api/v3/31/{target}/histresult/",payload,headers=good)
        assert actual[0]==status and state()==before,(payload,status,actual)
        count+=1

    try:
        for model in bindings:
            for kind in ("text","number","single","datetime","multiple","checkbox"):
                for existing in (False,True):
                    for whole in (False,True):compare(model=model,kind=kind,whole=whole,existing=existing)
            for stdout in ("", "false", "0", " \n\u001c\u001f ", " a,, b, ", "\u001c x \u001f"):
                compare(stdout,model=model,kind="checkbox")
                compare(stdout,model=model,kind="multiple",whole=True)
        compare(deleted=True)
        for auth in ({},{"Authorization":"Token invalid"},{"Authorization":"Token "+tokens[33]},{"Authorization":"Token "+tokens[34]},{"X-API-KEY":"valid-api-key"}):compare(auth=auth)
        for pk in (0,32,999):compare(pk=pk)
        for method in ("GET","HEAD","POST","PUT","DELETE"):compare(method=method)
        rejected(body("new"),404,target=other)
        rejected(body("new"),501,note=True)
        rejected(body("new"),501,history_type="task_run")
        for payload in ({}, {"results":"missing incoming stdout"}, {"script_results":None}, {"script_results":{}}, {"script_results":[]}, {"script_results":{"stdout":None}}, {"script_results":{"stdout":True}}, {"script_results":{"stdout":42}}, {"script_results":{"stdout":[]}}, {"script_results":{"stdout":"bad\x00value"}}):rejected(payload,existing=False)
        for field,value in (("agent",32),("custom_field",None),("collector_all_output",True),("save_to_agent_note",True),("type","cmd_run"),("script",None)):
            rejected({**body("new"),field:value})
        for model,field_model in bindings.items():
            setup(model,existing=False)
            path=f"/api/v3/31/{subject}/histresult/"
            assert go_request("PATCH",path,body("once"),headers=good)==(200,"ok")
            before=state()
            assert go_request("PATCH",path,body("once"),headers=good)==(200,"ok") and state()==before
            assert field_model.objects.filter(field_id=301,**{model+"_id":31}).count()==1
            count+=1
            for existing in (False,True):
                setup(model,existing=existing);before=state()
                with connection.cursor() as cursor:cursor.execute(sql.SQL("ALTER TABLE {} ADD CONSTRAINT collector_callback_reject CHECK (string_value IS DISTINCT FROM 'reject') NOT VALID").format(sql.Identifier(field_model._meta.db_table)))
                try:
                    actual=go_request("PATCH",path,body("reject"),headers=good)
                    assert actual[0]==500 and state()==before,"failed field persistence must roll back history and value together"
                    count+=1
                finally:
                    with connection.cursor() as cursor:cursor.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT collector_callback_reject").format(sql.Identifier(field_model._meta.db_table)))
            setup(model,existing=False);before=state()
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE agents_agenthistory ADD CONSTRAINT collector_history_reject CHECK ((script_results->>'stdout') IS DISTINCT FROM 'reject-history') NOT VALID")
            try:
                actual=go_request("PATCH",path,body("reject-history"),headers=good)
                assert actual[0]==500 and state()==before,"history update failure must roll back the newly collected field value"
                count+=1
            finally:
                with connection.cursor() as cursor:cursor.execute("ALTER TABLE agents_agenthistory DROP CONSTRAINT collector_history_reject")
        for model in ("site","client"):
            setup(model,existing=False);Agent.objects.filter(pk=32).update(site_id=31)
            barrier=threading.Barrier(3,timeout=5);results=queue.Queue()
            def worker(pk,target,stdout):
                try:
                    barrier.wait()
                    results.put((pk,go_request("PATCH",f"/api/v3/{pk}/{target}/histresult/",body(stdout),headers={"Authorization":"Token "+tokens[pk]}),None))
                except Exception as error:results.put((pk,None,error))
            threads=[threading.Thread(target=worker,args=(pk,target,stdout),daemon=True) for pk,target,stdout in ((31,subject,"first"),(32,other,"second"))]
            for thread in threads:thread.start()
            barrier.wait()
            for thread in threads:thread.join(timeout=20)
            assert all(not thread.is_alive() for thread in threads),"concurrent callbacks exceeded bound"
            actual=[results.get(timeout=1) for _ in threads]
            assert all(response==(200,"ok") and error is None for _,response,error in actual),actual
            stored=bindings[model].objects.filter(field_id=301,**{model+"_id":31})
            assert stored.count()==1 and stored.get().string_value in ("first","second")
            assert AgentHistory.objects.get(pk=31).script_results["stdout"]=="first"
            assert AgentHistory.objects.get(pk=32).script_results["stdout"]=="second"
            assert AgentHistory.objects.count()==2 and not Note.objects.exists()
            count+=1
        # Concurrent delivery for the SAME history must leave history and field
        # agreeing on the winning output, with one value row rather than two.
        setup("site",existing=False)
        barrier=threading.Barrier(3,timeout=5);results=queue.Queue()
        def replay(stdout):
            try:
                barrier.wait()
                results.put((go_request("PATCH",f"/api/v3/31/{subject}/histresult/",body(stdout),headers=good),None))
            except Exception as error:results.put((None,error))
        threads=[threading.Thread(target=replay,args=(stdout,),daemon=True) for stdout in ("first","second")]
        for thread in threads:thread.start()
        barrier.wait()
        for thread in threads:thread.join(timeout=20)
        assert all(not thread.is_alive() for thread in threads),"concurrent replay exceeded bound"
        actual=[results.get(timeout=1) for _ in threads]
        assert all(response==(200,"ok") and error is None for response,error in actual),actual
        stored=SiteCustomField.objects.filter(field_id=301,site_id=31)
        assert stored.count()==1
        assert stored.get().string_value==AgentHistory.objects.get(pk=31).script_results["stdout"]
        assert AgentHistory.objects.count()==2 and not Note.objects.exists()
        count+=1
        print(f"Collector callback contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();CustomField.objects.filter(pk=301).delete();Script.objects.filter(pk=31).delete();seed()
