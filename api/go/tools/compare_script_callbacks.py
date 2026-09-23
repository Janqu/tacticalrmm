"""Plain script history callbacks with DRF agent tokens; no agent execution."""
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from accounts.models import User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.db import connection
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from scripts.models import Script

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    subject, other = "script-callback-agent-0031", "script-callback-agent-0032"
    tokens = {pk: hashlib.sha1(f"script-callback-{pk}".encode()).hexdigest() for pk in (31,32,33,34)}
    headers = {"Authorization": "Token " + tokens[31]}
    output = {"script_results": {"stdout": " ü\n", "stderr": "", "retcode": 0, "execution_time": "0.1234", "id": 31}}
    count = 0

    def setup(deleted=False, kind="script_run", **flags):
        Token.objects.all().delete(); Agent.objects.all().delete(); Script.objects.all().delete(); seed()
        Client.objects.bulk_create([Client(id=31,name="A")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="A",site_id=31),Agent(id=32,agent_id=other,hostname="B",site_id=31)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=pk,username=f"callback-script-{pk}",agent_id=pk if pk in (31,32) else None,is_active=pk!=33,date_joined=fixed) for pk in tokens])
        User.objects.filter(pk__in=tokens).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.bulk_create([Token(key=token,user_id=pk,created=fixed) for pk,token in tokens.items()])
        Token.objects.update(created=fixed)
        Script.objects.bulk_create([Script(id=31,name="Fixture",shell="powershell",script_body="fixture only")])
        Script.objects.update(created_time=fixed,modified_time=fixed)
        AgentHistory.objects.bulk_create([
            AgentHistory(id=31,agent_id=31,type=kind,script_id=None if deleted else 31,results="keep",script_results={"old":True},**flags),
            AgentHistory(id=32,agent_id=32,type="script_run",script_id=31,script_results={"other":True}),
        ])
        AgentHistory.objects.update(time=fixed)

    def state():
        return {"base":snapshot(), "history":list(AgentHistory.objects.order_by("id").values()), "agents":list(Agent.objects.order_by("id").values()), "scripts":list(Script.objects.order_by("id").values()), "agent_tokens":list(Token.objects.order_by("key").values())}

    def compare(body, *, deleted=False, method="PATCH", pk=31, auth=None, collector_all_output=False):
        nonlocal count
        auth=headers if auth is None else auth
        path=f"/api/v3/{pk}/{subject}/histresult/"
        setup(deleted,collector_all_output=collector_all_output)
        client=APIClient();client.credentials(**{"HTTP_"+key.upper().replace("-","_"):value for key,value in auth.items()})
        with patch.object(Agent,"nats_cmd") as bus,patch("celery.app.task.Task.apply_async") as jobs:
            response=client.generic(method,path,json.dumps(body),content_type="application/json")
        bus.assert_not_called();jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(deleted,collector_all_output=collector_all_output)
        actual=go_request(method,path,body,headers=auth)
        if auth=={"Authorization":"Token "+tokens[34]}:
            assert expected==(404,{"detail":"No AgentHistory matches the given query."}),expected
            expected=(404,{"detail":"No Agent matches the given query."})
        assert actual==expected,(method,pk,deleted,body,expected,actual)
        assert state()==expected_state,("script callback state mismatch",body)
        count+=1

    def rejected(body, status=400, *, target=subject, **options):
        nonlocal count
        setup(**options);before=state()
        actual=go_request("PATCH",f"/api/v3/31/{target}/histresult/",body,headers=headers)
        assert actual[0]==status,(status,actual)
        assert state()==before,"rejected callback changed state"
        count+=1

    try:
        for deleted in (False,True):
            for body in (output, {}, {"script_results":None}, {"script_results":[]}, {"script_results":"  text  "}, {"script_results":True}, {"script_results":18446744073709551615}, {"script_results":{"number":18446744073709551615,"nested":[{},None,False]}}, {"results":"  text\n ",**output}, {"results":None}, {"results":12}, {"results":False}):
                compare(body,deleted=deleted)
        for pk in (0,32,999): compare(output,pk=pk)
        for auth in ({},{"Authorization":"Token invalid"},{"Authorization":"Token "+tokens[32]},{"Authorization":"Token "+tokens[33]},{"Authorization":"Token "+tokens[34]},{"X-API-KEY":"valid-api-key"}):
            if auth=={"Authorization":"Token "+tokens[32]}:
                # Go's explicit token-agent-URL check precedes history ownership.
                setup();before=state()
                actual=go_request("PATCH",f"/api/v3/31/{subject}/histresult/",output,headers=auth)
                assert actual==(404,{"detail":"No Agent matches the given query."}) and state()==before
                count+=1
            else: compare(output,auth=auth)
        for method in ("GET","HEAD","POST","PUT","DELETE"):compare(output,method=method)
        for field,value in (("agent",32),("script",None),("type","cmd_run"),("username","other"),("custom_field",None),("save_to_agent_note",True),("collector_all_output",True),("time",fixed.isoformat())):
            rejected({**output,field:value})
        rejected(output,status=404,target=other)
        rejected(output,status=501,kind="task_run")
        rejected(output,status=501,save_to_agent_note=True)
        compare(output,collector_all_output=True)
        # fasthttp rejects an oversized declared length before reading the body.
        # Sending megabytes here instead can race its close and yield BrokenPipe
        # in urllib instead of exposing the HTTP 413 response being tested.
        setup();before=state()
        actual=go_request("PATCH",f"/api/v3/31/{subject}/histresult/",None,headers={**headers,"Content-Type":"application/json","Content-Length":str(4*1024*1024+1)})
        assert actual[0]==413 and state()==before,actual
        count+=1
        # Well below the global cap: no source >10 MiB truncation is requested.
        compare({"script_results":{"stdout":"x"*(1024*1024),"stderr":"keep","retcode":0}})
        setup();path=f"/api/v3/31/{subject}/histresult/"
        assert go_request("PATCH",path,output,headers=headers)==(200,"ok")
        before=state()
        assert go_request("PATCH",path,output,headers=headers)==(200,"ok") and state()==before
        count+=1
        setup();before=state()
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE agents_agenthistory ADD CONSTRAINT script_callback_reject CHECK (script_results IS DISTINCT FROM '{\"reject\":true}'::jsonb) NOT VALID")
        try:
            actual=go_request("PATCH",path,{"results":"also rollback","script_results":{"reject":True}},headers=headers)
            assert actual[0]==500 and state()==before,actual
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE agents_agenthistory DROP CONSTRAINT script_callback_reject")
        print(f"Script callback contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();Script.objects.all().delete();seed()
