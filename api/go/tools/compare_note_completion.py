"""Go note_async extension and replay-safe, atomic agent-note completion."""
import hashlib
import json
import queue
import threading
from datetime import datetime, timezone
from unittest.mock import patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    import psycopg
    from psycopg import sql
    from accounts.models import User
    from agents.models import Agent, AgentHistory, Note
    from clients.models import Client, Site
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from scripts.models import Script

    subject,other="note-completion-agent-031","note-completion-agent-032"
    token={pk:hashlib.sha1(f"note-completion-{pk}".encode()).hexdigest() for pk in (31,32)}
    good={"Authorization":"Token "+token[31]}
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    command={"script":31,"output":"note_async","args":[],"env_vars":[],"timeout":10,"run_as_user":False}
    payload={"results":"  extra text  ","script_results":{"stdout":" output ü\n ","stderr":"","retcode":0,"execution_time":1,"id":100}}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema=cursor.fetchone()[0]
    assert schema.startswith("go_contract_")
    options=connection.get_connection_params();options["connect_timeout"]=2
    count=0

    def setup(history=False,marker=True):
        with connection.cursor() as cursor:cursor.execute("DELETE FROM go_script_note_completion")
        Token.objects.all().delete();Agent.objects.all().delete();Script.objects.filter(pk=31).delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Note completion ü",site_id=31),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=pk,username=f"note-agent-{pk}",agent_id=pk,date_joined=fixed) for pk in token])
        User.objects.filter(pk__in=token).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.bulk_create([Token(key=value,user_id=pk,created=fixed) for pk,value in token.items()])
        Token.objects.update(created=fixed)
        Script.objects.bulk_create([Script(id=31,name="Note completion",shell="powershell",script_body="fixture only")])
        Script.objects.filter(pk=31).update(created_time=fixed,modified_time=fixed)
        Note.objects.bulk_create([Note(id=31,agent_id=32,user_id=None,note="untouched")])
        Note.objects.update(entry_time=fixed)
        with connection.cursor() as cursor:
            for table in ("agents_agenthistory","agents_note"):
                cursor.execute("SELECT setval(pg_get_serial_sequence(%s,'id'),100,false)",[table])
        if history:
            AgentHistory.objects.bulk_create([AgentHistory(id=100,agent_id=31,type="script_run",script_id=31,username="admin",save_to_agent_note=True)])
            AgentHistory.objects.update(time=fixed)
            if marker:
                with connection.cursor() as cursor:cursor.execute("INSERT INTO go_script_note_completion (history_id,agent_id) VALUES (100,31)")

    def markers():
        with connection.cursor() as cursor:
            cursor.execute("SELECT history_id,agent_id,payload_identity,note_id FROM go_script_note_completion ORDER BY history_id")
            return cursor.fetchall()

    def domain():
        result={"base":snapshot()}
        for model in (AgentHistory,Note):
            rows=list(model.objects.order_by("id").values())
            for row in rows:
                field="time" if model is AgentHistory else "entry_time"
                if row[field]!=fixed:
                    assert abs((row[field]-datetime.now(timezone.utc)).total_seconds())<15
                    row[field]="<now>"
            result[model._meta.db_table]=rows
        return result

    def state():return domain(),markers()
    def callback(body=payload,*,target=subject,auth=None):
        return go_request("PATCH",f"/api/v3/100/{target}/histresult/",body,headers=good if auth is None else auth)

    def assert_completed(body=payload):
        row=markers()
        assert len(row)==1 and row[0][0:2]==(100,31) and row[0][2] is not None and row[0][3] is not None,row
        note=Note.objects.get(pk=row[0][3])
        assert note.user_id==31 and note.agent_id==31,"author must be the token-authenticated agent user, not initiating admin"
        assert note.note==body["script_results"]["stdout"]
        assert Note.objects.count()==2 and AgentHistory.objects.count()==1

    try:
        # First completion agrees with Django's note callback, which creates a
        # note as request.user after saving history. Replay is deliberately safer.
        for stdout in (" output ü\n ","",None):
            body={**payload,"script_results":{**payload["script_results"],"stdout":stdout}}
            setup(history=True)
            client=APIClient();client.credentials(HTTP_AUTHORIZATION=good["Authorization"])
            with patch.object(Agent,"nats_cmd") as bus,patch("celery.app.task.Task.apply_async") as jobs:
                response=client.patch(f"/api/v3/100/{subject}/histresult/",body,format="json")
            bus.assert_not_called();jobs.assert_not_called()
            expected=response.status_code,json.loads(response.content) if response.content else None
            expected_domain=domain()
            setup(history=True)
            assert callback(body)==expected
            assert domain()==expected_domain
            assert_completed(body)
            before=state()
            assert callback(body)==(200,"ok") and state()==before
            count+=1

        # Verify the actual extension producer and callback over a real local
        # broker. No response message is sent to a plain publication.
        setup();finished=threading.Event()
        def receive(message):
            assert message["func"]=="runscript" and message["id"]==100 and message["timeout"]==13,message
            assert message["payload"]=={"code":"fixture only","shell":"powershell"}
            with psycopg.connect(**options) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql.SQL("SELECT h.save_to_agent_note,m.agent_id,m.payload_identity,m.note_id FROM {}.agents_agenthistory h JOIN {}.go_script_note_completion m ON m.history_id=h.id WHERE h.id=100").format(sql.Identifier(schema),sql.Identifier(schema)))
                    assert cursor.fetchone()==(True,31,None,None),"history and pending completion must commit before publication"
                    cursor.execute(sql.SQL("SELECT count(*) FROM {}.logs_auditlog WHERE action='execute_script'").format(sql.Identifier(schema)))
                    assert cursor.fetchone()[0]==1
            assert callback()==(200,"ok")
            assert callback()==(200,"ok")
            finished.set()
            return None
        with responder(subject,[receive]) as peer:
            actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert finished.wait(5),"callback did not finish"
        assert actual==(200,"Note completion will now be run on Note completion ü") and len(peer.messages)==1,actual
        assert_completed();count+=1
        setup()
        assert go_request("POST",f"/agents/{subject}/runscript/",command)==(200,"Note completion will now be run on Note completion ü")
        assert markers()==[(100,31,None,None)] and Note.objects.count()==1
        assert AgentHistory.objects.get(pk=100).script_results is None
        count+=1
        setup()
        with responder(subject,[None]) as peer:
            actual=go_request("POST",f"/agents/{subject}/runscript/",command,user_id=2)
        assert actual[0]==403 and not peer.messages
        assert not markers() and not AgentHistory.objects.exists() and not AuditLog.objects.exists() and Note.objects.count()==1
        count+=1

        setup(history=True)
        assert callback()==(200,"ok")
        before=state()
        reordered={"script_results":{"id":100,"execution_time":1.0,"retcode":0,"stderr":"","stdout":" output ü\n "},"results":"  extra text  "}
        assert callback(reordered)==(200,"ok") and state()==before,"JSONB identity ignores key order/numeric representation"
        assert callback({**payload,"results":None})[0]==409 and state()==before
        assert callback({"script_results":payload["script_results"]})[0]==409 and state()==before,"omitted is distinct from null/present"
        Note.objects.filter(pk=markers()[0][3]).delete()
        after_delete=state()
        assert callback()==(200,"ok") and state()==after_delete,"deleted completed note must not be recreated"
        count+=1
        setup(history=True)
        absent={"script_results":payload["script_results"]}
        assert callback(absent)==(200,"ok")
        before=state()
        assert callback({**absent,"results":None})[0]==409 and state()==before
        count+=1

        for body in ({}, {"script_results":None}, {"script_results":{}}, {"script_results":{"stdout":True}}, {"script_results":{"stdout":[]}}, {"script_results":{"stdout":"bad\x00value"}}, {**payload,"agent":32}):
            setup(history=True);before=state()
            actual=callback(body)
            assert actual[0]==400 and state()==before,("malformed completion",body,actual)
            count+=1
        setup(history=True,marker=False);before=state()
        assert callback()[0]==501 and state()==before
        count+=1
        setup(history=True);AgentHistory.objects.filter(pk=100).update(agent_id=32)
        before=state()
        actual=callback(target=other,auth={"Authorization":"Token "+token[32]})
        assert actual[0]==409 and state()==before,("captured agent identity must block reassigned history",actual)
        count+=1

        setup(history=True)
        barrier=threading.Barrier(3,timeout=5);results=queue.Queue()
        def complete():
            try:barrier.wait();results.put((callback(),None))
            except Exception as error:results.put((None,error))
        threads=[threading.Thread(target=complete,daemon=True) for _ in range(2)]
        for thread in threads:thread.start()
        barrier.wait()
        for thread in threads:thread.join(timeout=20)
        assert all(not thread.is_alive() for thread in threads)
        actual=[results.get(timeout=1) for _ in threads]
        assert all(response==(200,"ok") and error is None for response,error in actual),actual
        assert_completed();count+=1

        for table,condition in (("agents_note","id<100"),("agents_agenthistory","script_results IS NULL"),("go_script_note_completion","payload_identity IS NULL")):
            setup(history=True);before=state()
            with connection.cursor() as cursor:cursor.execute(sql.SQL("ALTER TABLE {} ADD CONSTRAINT note_completion_reject CHECK ({}) NOT VALID").format(sql.Identifier(table),sql.SQL(condition)))
            try:
                assert callback()[0]==500 and state()==before,"failed completion partially committed history/note/marker"
                count+=1
            finally:
                with connection.cursor() as cursor:cursor.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT note_completion_reject").format(sql.Identifier(table)))
        # Marker insertion belongs to the same pre-publication transaction as
        # history and audit. Failure must not leave an untracked execution.
        setup();before=domain()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE go_script_note_completion ADD CONSTRAINT note_marker_insert_reject CHECK (false) NOT VALID")
        try:
            with responder(subject,[None]) as peer:
                actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==500 and not peer.messages,actual
            after=domain()
            # Knox may prune expired tokens during authentication; domain writes
            # and all other security state must still match the initial state.
            before["base"].pop("tokens",None);after["base"].pop("tokens",None)
            assert after==before and markers()==[],"failed marker creation partially committed audit/history"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE go_script_note_completion DROP CONSTRAINT note_marker_insert_reject")

        # Missing migration is a controlled 501, not an implicit non-idempotent
        # fallback. Rename preserves rows and is restored even on assertion error.
        setup(history=True)
        AgentHistory.objects.bulk_create([AgentHistory(id=101,agent_id=31,type="script_run",script_id=31,username="legacy",save_to_agent_note=True)])
        AgentHistory.objects.filter(pk=101).update(time=fixed)
        before=state()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE go_script_note_completion RENAME TO note_completion_temporarily_unavailable")
        try:
            with responder(subject,[None]) as peer:
                actual=go_request("POST",f"/agents/{subject}/runscript/",command)
            assert actual[0]==501 and not peer.messages,actual
            assert callback()[0]==501
            assert go_request("PATCH",f"/api/v3/101/{subject}/histresult/",payload,headers=good)[0]==501
            after=domain()
            before[0]["base"].pop("tokens",None);after["base"].pop("tokens",None)
            assert after==before[0],"missing migration changed history, notes or audits"
            with connection.cursor() as cursor:
                cursor.execute("SELECT history_id,agent_id,payload_identity,note_id FROM note_completion_temporarily_unavailable ORDER BY history_id")
                assert cursor.fetchall()==before[1],"unavailable completion rows changed"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE note_completion_temporarily_unavailable RENAME TO go_script_note_completion")
        setup(history=True)
        with connection.cursor() as cursor:cursor.execute("DELETE FROM agents_agenthistory WHERE id=100")
        assert markers()==[],"history deletion must cascade its completion marker"
        count+=1
        print(f"Note completion contracts: {count} comparisons passed")
        return count
    finally:
        with connection.cursor() as cursor:cursor.execute("DELETE FROM go_script_note_completion")
        Token.objects.all().delete();Agent.objects.all().delete();Script.objects.filter(pk=31).delete();seed()
