"""Synchronous script output saved as an agent note; isolated broker only."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    import psycopg
    from psycopg import sql
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory, Note
    from clients.models import Client, Site
    from django.conf import settings
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.test import APIClient
    from scripts.models import Script

    subject, other = "script-notes-agent-000031", "script-notes-agent-000032"
    fixed = datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    command = {"script":31,"output":"note","args":[],"env_vars":[],"timeout":10,"run_as_user":False}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema=cursor.fetchone()[0]
    assert schema.startswith("go_contract_")
    options=connection.get_connection_params();options["connect_timeout"]=2
    count=0

    def setup(scope="all",override=False):
        Agent.objects.all().delete();Script.objects.filter(pk=31).delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Note ü",site_id=31),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        Script.objects.bulk_create([Script(id=31,name="Note script",shell="powershell",script_body="fixture only",run_as_user=override)])
        Script.objects.filter(pk=31).update(created_time=fixed,modified_time=fixed)
        Note.objects.bulk_create([Note(id=31,agent_id=31,user_id=1,note="keep own"),Note(id=32,agent_id=32,user_id=None,note="keep other")])
        Note.objects.update(entry_time=fixed)
        with connection.cursor() as cursor:
            for table in ("agents_agenthistory","agents_note"):
                cursor.execute("SELECT setval(pg_get_serial_sequence(%s,'id'),100,false)",[table])
        Role.objects.filter(pk=1).update(can_run_scripts=scope!="denied",can_manage_notes=False)
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state(auth=True):
        history=list(AgentHistory.objects.order_by("id").values())
        notes=list(Note.objects.order_by("id").values())
        for rows,field in ((history,"time"),(notes,"entry_time")):
            for row in rows:
                if row["id"]>=100:
                    assert abs((row[field]-datetime.now(timezone.utc)).total_seconds())<15
                    row[field]="<now>"
        return {"base":{key:value for key,value in snapshot().items() if auth or key!="tokens"},"history":history,"notes":notes}

    def unchanged_notes():
        assert list(Note.objects.order_by("id").values_list("id","agent_id","user_id","note","entry_time"))==[(31,31,1,"keep own",fixed),(32,32,None,"keep other",fixed)],"failed execution changed existing notes"

    def compare(reply="  output ü\nsecond line\n  ", *, data=None,user=1,scope="all",target=subject,override=False):
        nonlocal count
        data=copy.deepcopy(command if data is None else data)
        setup(scope,override);calls=[]
        def receive(payload, go=False):
            assert payload=={"func":"runscript","timeout":int(data["timeout"])+3,"script_args":data["args"] or [],"payload":{"code":"fixture only","shell":"powershell"},"run_as_user":override or data["run_as_user"],"env_vars":data["env_vars"] or [],"nushell_enable_config":settings.NUSHELL_ENABLE_CONFIG,"deno_default_permissions":settings.DENO_DEFAULT_PERMISSIONS,"id":100},payload
            with psycopg.connect(**options) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql.SQL("SELECT agent_id,type,script_id FROM {}.agents_agenthistory WHERE id=100").format(sql.Identifier(schema)))
                    assert cursor.fetchone()==(31 if target==subject else 32,"script_run",31)
                    cursor.execute(sql.SQL("SELECT count(*) FROM {}.logs_auditlog WHERE action='execute_script'").format(sql.Identifier(schema)))
                    assert cursor.fetchone()[0]==1
                    cursor.execute(sql.SQL("SELECT count(*) FROM {}.agents_note WHERE id>=100").format(sql.Identifier(schema)))
                    assert cursor.fetchone()[0]==0,"note created before output received"
            return b"\xc0" if go and reply is None else reply
        async def reference(*args,**kwargs):
            assert kwargs=={"timeout":int(data["timeout"])+3,"wait":True},kwargs
            payload=copy.deepcopy(args[0]);calls.append(payload)
            return receive(payload)
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        path=f"/agents/{target}/runscript/"
        with patch.object(Agent,"nats_cmd",new=AsyncMock(side_effect=reference)),patch("celery.app.task.Task.apply_async") as jobs:
            response=client.post(path,data,format="json")
        jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(scope,override)
        with responder(target,[lambda payload:receive(payload,go=True)]) as peer:
            actual=go_request("POST",path,data,user_id=user)
        assert actual==expected,(reply,user,scope,target,expected,actual)
        assert peer.messages==calls,("payload/retry",peer.messages,calls)
        assert state()==expected_state,("note state mismatch",expected_state,state())
        if calls:
            note=Note.objects.get(pk=100)
            assert note.note==reply and note.user_id==user and note.agent_id==(31 if target==subject else 32)
            assert Note.objects.count()==3 and AgentHistory.objects.count()==1
        count+=1

    try:
        for user,scope in ((1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")):
            for target in (subject,other,"script-notes-missing-9999"):compare(user=user,scope=scope,target=target)
        for reply in (None, "", " ", "\n", "<script>literal text</script>", "emoji 😀\r\nsecond line", "x"*(1024*1024-256)):
            compare(reply)
        for changes in ({"timeout":1},{"timeout":180},{"timeout":"10"},{"run_as_user":True},{"args":["literal"],"env_vars":["A=B"]}):compare(data={**command,**changes})
        compare(override=True)
        compare(data={**command,"script":999})
        # Django writes timeout/natsdown as notes. Go deliberately rejects these
        # transport sentinels, malformed wire and non-text/non-null replies without notes.
        for reply,status in (("timeout",400),("natsdown",400),(b"\xc1",502),({},502),(["line"],502),(True,502),(42,502)):
            setup()
            with responder(subject,[reply]) as peer:
                actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==status,(reply,actual)
            assert len(peer.messages)==1 and Note.objects.count()==2
            assert AgentHistory.objects.filter(pk=100,type="script_run").exists()
            assert AuditLog.objects.filter(action="execute_script").count()==1
            unchanged_notes()
            count+=1
        # Broker with no subscriber yields a failure, never a note/completion.
        setup()
        actual=go_request("POST",f"/agents/{subject}/runscript/",command)
        assert actual[0]==400 and Note.objects.count()==2 and AgentHistory.objects.filter(pk=100).exists(),actual
        unchanged_notes()
        count+=1
        # Note insertion fails after the one remote execution: retain committed
        # history/audit and existing notes. The command must never be resent.
        setup()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE agents_note ADD CONSTRAINT script_note_reject CHECK (id<100) NOT VALID")
        try:
            with responder(subject,["executed output"]) as peer:
                actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==500 and len(peer.messages)==1,actual
            assert Note.objects.count()==2 and AgentHistory.objects.filter(pk=100).exists()
            assert AuditLog.objects.filter(action="execute_script").count()==1
            unchanged_notes()
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE agents_note DROP CONSTRAINT script_note_reject")
        print(f"Script note contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();Script.objects.filter(pk=31).delete();seed()
