"""Forget-mode script publication: committed state, callbacks, and no retries."""
import copy
import hashlib
import json
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    import psycopg
    from psycopg import sql
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.conf import settings
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from scripts.models import Script

    subject, other = "async-script-agent-000031", "async-script-agent-000032"
    token = hashlib.sha1(b"async-script-callback-fixture").hexdigest()
    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    command = {"script":31,"output":"forget","args":[],"env_vars":[],"timeout":10,"run_as_user":False}
    callback_value = {"stdout":"completed ü","stderr":"","retcode":0,"execution_time":0.125,"id":100}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema = cursor.fetchone()[0]
    assert schema.startswith("go_contract_")
    options = connection.get_connection_params();options["connect_timeout"] = 2
    count = 0

    def setup(scope="all", shell="powershell", override=False):
        Token.objects.all().delete();Agent.objects.all().delete();Script.objects.filter(pk=31).delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Async ü",site_id=31),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        Script.objects.bulk_create([Script(id=31,name="Async script",shell=shell,script_body="fixture code ü",run_as_user=override,args=["stored ignored"],env_vars=["STORED=ignored"])])
        Script.objects.filter(pk=31).update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=31,username="async-callback",agent_id=31,date_joined=fixed)])
        User.objects.filter(pk=31).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.create(key=token,user_id=31)
        Token.objects.update(created=fixed)
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence('agents_agenthistory','id'),100,false)")
        Role.objects.filter(pk=1).update(can_run_scripts=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state(auth=True):
        histories=list(AgentHistory.objects.order_by("id").values())
        for row in histories:
            assert abs((row["time"]-datetime.now(timezone.utc)).total_seconds())<15
            row["time"]="<now>"
        return {"base":{key:value for key,value in snapshot().items() if auth or key!="tokens"},"history":histories}

    def compare(data=None, *, user=1, scope="all", target=subject, shell="powershell", override=False, callback=False, subscribe=True):
        nonlocal count
        data=copy.deepcopy(command if data is None else data)
        setup(scope,shell,override)
        calls=[];received=threading.Event()
        def receive(payload, go=False):
            assert payload=={"func":"runscript","timeout":int(data["timeout"])+3,"script_args":data["args"] or [],"payload":{"code":"fixture code ü","shell":shell},"run_as_user":override or data["run_as_user"],"env_vars":data["env_vars"] or [],"nushell_enable_config":settings.NUSHELL_ENABLE_CONFIG,"deno_default_permissions":settings.DENO_DEFAULT_PERMISSIONS,"id":100},payload
            with psycopg.connect(**options) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql.SQL("SELECT agent_id,type,script_id,script_results FROM {}.agents_agenthistory WHERE id=100").format(sql.Identifier(schema)))
                    assert cursor.fetchone()==(31 if target==subject else 32,"script_run",31,None),"history not committed before publication"
                    cursor.execute(sql.SQL("SELECT count(*) FROM {}.logs_auditlog WHERE action='execute_script'").format(sql.Identifier(schema)))
                    assert cursor.fetchone()[0]==1,"audit not committed before publication"
                    if callback and not go:
                        cursor.execute(sql.SQL("UPDATE {}.agents_agenthistory SET script_results=%s::jsonb WHERE id=100").format(sql.Identifier(schema)),[json.dumps(callback_value)])
            if callback and go:
                callback_path=f"/api/v3/100/{target}/histresult/"
                for _ in range(2):
                    result=go_request("PATCH",callback_path,{"script_results":callback_value},headers={"Authorization":"Token "+token})
                    assert result==(200,"ok"),result
            received.set()
            return None # A plain publication has no reply subject or required ack payload.
        async def reference(*args,**kwargs):
            assert kwargs=={"wait":False},kwargs
            payload=copy.deepcopy(args[0]);calls.append(payload)
            receive(payload)
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        path=f"/agents/{target}/runscript/"
        with patch.object(Agent,"nats_cmd",new=AsyncMock(side_effect=reference)),patch("celery.app.task.Task.apply_async") as jobs:
            response=client.post(path,data,format="json")
        jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(scope,shell,override);received.clear()
        if subscribe:
            with responder(target,[lambda payload:receive(payload,go=True)]) as peer:
                actual=go_request("POST",path,data,user_id=user)
                # Broker flush may complete before the subscriber handles PUB;
                # keep it alive until callbacks finish, then compare DB state.
                if calls:assert received.wait(5),"subscriber/callback did not finish"
            assert peer.messages==calls,("unexpected publication/retry",peer.messages,calls)
        else:
            actual=go_request("POST",path,data,user_id=user)
        assert actual==expected,(data,user,scope,target,expected,actual)
        assert state()==expected_state,("async state mismatch",expected_state,state())
        if calls:
            assert AgentHistory.objects.count()==1 and AuditLog.objects.filter(action="execute_script").count()==1
            assert AgentHistory.objects.get(pk=100).script_results==(callback_value if callback else None)
        count+=1

    try:
        for user,scope in ((1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")):
            for target in (subject,other,"async-script-missing-9999"):compare(user=user,scope=scope,target=target)
        for shell in ("powershell","cmd","bash","python","nu","deno"):
            compare({**command,"args":["--literal","ü"],"env_vars":["A=B","UNICODE=ü"]},shell=shell)
        for changes in ({"timeout":1},{"timeout":180},{"timeout":"10"},{"run_as_user":True},{"args":None,"env_vars":None}):compare({**command,**changes})
        compare(override=True)
        compare(callback=True)
        compare(subscribe=False) # HTTP success does not imply any agent received or completed the work.
        compare({**command,"script":999})
        for changes,status in [({"output":mode},501) for mode in ("email","unknown-mode")]+[({"run_on_server":True},501),({"timeout":0},400),({"timeout":181},400),({"run_as_user":"false"},400)]:
            setup();before=state(auth=False)
            with responder(subject,[None]) as peer:
                result=go_request("POST",f"/agents/{subject}/runscript/",{**command,**changes})
            assert result[0]==status and not peer.messages,(changes,result)
            assert state(auth=False)==before
            count+=1
        # Invalid literal subject is definitely unsent, but audit/history remain
        # committed to record the attempted execution. Never forge completion.
        setup();bad_subject="async-script-invalid..agent-31"
        Agent.objects.filter(pk=31).update(agent_id=bad_subject)
        from urllib.parse import quote
        result=go_request("POST",f"/agents/{quote(bad_subject,safe='')}/runscript/",command)
        assert result==(503,"Unable to publish the script execution request."),result
        assert AgentHistory.objects.count()==1 and AgentHistory.objects.get(pk=100).script_results is None
        assert AuditLog.objects.filter(action="execute_script").count()==1
        count+=1
        print(f"Asynchronous script execution contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();Script.objects.filter(pk=31).delete();seed()
