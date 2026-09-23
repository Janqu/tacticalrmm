"""DB-only pending resolution contracts. Root supplies an isolated schema/CLI."""
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from unittest.mock import patch


def run(seed, snapshot, job_binary, dsn):
    from agents.models import Agent
    from clients.models import Client, Site
    from core.tasks import resolve_pending_actions
    from django.db import connection
    from django.test import override_settings
    from logs.models import PendingAction

    parsed=urlparse(dsn)
    assert parsed.hostname in ("localhost","127.0.0.1","::1"),"jobs tests require a loopback DB"
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema=cursor.fetchone()[0]
    assert schema.startswith("go_contract_"),"jobs tests require an isolated contract schema"
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    now=datetime(2025,1,2,12,0,0,tzinfo=timezone.utc)
    lock=0x54524D4D50454E44
    count=0

    def setup(rows):
        Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="Job fixture")])
        Site.objects.bulk_create([Site(id=31,name="Job fixture",client_id=31)])
        for offset,row in enumerate(rows):
            pk=31+offset
            agent=Agent(id=pk,agent_id=f"scheduled-job-agent-{pk}",hostname=f"Host {pk}",site_id=31,version=row.get("version","2.10.0"),last_seen=row.get("last_seen",now),offline_time=row.get("offline_time",4),overdue_time=row.get("overdue_time",30))
            Agent.objects.bulk_create([agent])
            PendingAction.objects.bulk_create([PendingAction(id=pk,agent_id=pk,action_type=row.get("action_type","agentupdate"),status=row.get("status","pending"),details={"keep":pk})])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        PendingAction.objects.update(entry_time=fixed)

    def state():
        return {"base":snapshot(),"agents":list(Agent.objects.order_by("id").values()),"pending":list(PendingAction.objects.order_by("id").values())}

    def command(latest="2.10.0",dry=False):
        args=[str(job_binary),"--job","resolve-pending-actions","--latest-agent-version",latest,"--now",now.isoformat()]
        if dry:args.append("--dry-run")
        env=os.environ.copy();env["DATABASE_URL"]=dsn
        result=subprocess.run(args,env=env,capture_output=True,text=True,timeout=40)
        return result.returncode,json.loads(result.stdout) if result.stdout else None,result.stderr

    def compare(rows,latest="2.10.0",dry=False):
        nonlocal count
        setup(rows);before=state()
        with override_settings(LATEST_AGENT_VER=latest),patch("django.utils.timezone.now",return_value=now),patch.object(Agent,"nats_cmd") as nats,patch("celery.app.task.Task.apply_async") as tasks:
            resolve_pending_actions()
        nats.assert_not_called();tasks.assert_not_called()
        expected=state()
        eligible=sum(a["status"]!=b["status"] for a,b in zip(before["pending"],expected["pending"]))
        selected=sum(row.get("status","pending")=="pending" and row.get("action_type","agentupdate")=="agentupdate" for row in rows)
        setup(rows);before=state()
        code,report,error=command(latest,dry)
        assert code==0,("job failed",error)
        assert report=={"job":"resolve-pending-actions","selected":selected,"eligible":eligible,"updated":0 if dry else eligible,"dry_run":dry,"already_running":False},report
        assert state()==(before if dry else expected),"pending job changed unexpected DB state"
        if not dry:
            code,again,error=command(latest)
            assert code==0 and again["updated"]==0,(again,error)
            assert state()==expected,"repeated job changed completed data"
        count+=1

    try:
        basic=[{}, {"version":"2.9.0"}, {"last_seen":None}, {"last_seen":now-timedelta(minutes=4)}, {"last_seen":now-timedelta(minutes=4,microseconds=1)}, {"last_seen":now-timedelta(minutes=30)}, {"last_seen":now-timedelta(minutes=30,microseconds=1)}, {"last_seen":now+timedelta(days=1)}, {"status":"completed"}, {"action_type":"chocoinstall"}, {"offline_time":30,"overdue_time":4,"last_seen":now-timedelta(minutes=5)}, {"offline_time":0,"overdue_time":0,"last_seen":now-timedelta(microseconds=1)}]
        compare([]);compare(basic);compare(basic,dry=True)
        for latest,versions in [
            ("2.10.0",["v02.010","0!2.10.0.0","2.10a0","2.10.post0","2.10.dev0","2.10+local","2.10.0.1"]),
            ("2.10a0",["2.10alpha","2.10-a_00","2.10b0"]),
            ("2.10b1",["2.10beta01","2.10b1"]),
            ("2.10rc1",["2.10c01","2.10pre1","2.10preview1"]),
            ("2.10.post1",["2.10rev1","2.10r01","2.10-1","2.10post"]),
            ("2.10.dev0",["2.10dev","2.10.dev00","2.10.dev1"]),
            ("1!2.10+ABC.1.xyz",["001!2.010.0+abc-001_xyz","1!2.10+ABC.1.XYZ","2.10+abc.1.xyz"]),
        ]:compare([{"version":v} for v in versions],latest)
        # Invalid versions anywhere abort before completing even earlier eligible rows.
        for invalid in ("invalid","٢.١٠","2.10rc١"):
            for dry in (False,True):
                rows=[{}, {"version":invalid}]
                setup(rows);before=state()
                with override_settings(LATEST_AGENT_VER="2.10.0"),patch("django.utils.timezone.now",return_value=now):
                    try:resolve_pending_actions()
                    except Exception:pass
                    else:raise AssertionError("Django unexpectedly accepted invalid version")
                assert state()==before
                code,report,error=command(dry=dry)
                assert code!=0 and report is None and "invalid agent version" in error
                assert state()==before,"invalid version partially completed actions"
                count+=1
        setup([{}]);before=state()
        code,report,error=command("invalid")
        assert code!=0 and report is None and state()==before
        count+=1
        # Pending update version comparison short-circuits the agent status property.
        compare([{"version":"2.9.0","offline_time":2147483647}])
        setup([{}, {"offline_time":2147483647}]);before=state()
        code,report,error=command()
        assert code!=0 and report is None and state()==before
        count+=1
        # An existing owner blocks this run immediately, without touching domain state.
        setup([{}]);before=state()
        with connection.cursor() as cursor:cursor.execute("SELECT pg_advisory_lock(%s)",[lock])
        try:
            code,report,error=command()
            assert code==0 and report["already_running"] and report["updated"]==0,(report,error)
            assert state()==before
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("SELECT pg_advisory_unlock(%s)",[lock])
        # Force failure on one target; the entire batch must remain pending.
        setup([{},{}]);before=state()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction ADD CONSTRAINT scheduled_job_reject CHECK (id <> 32 OR status <> 'completed') NOT VALID")
        try:
            code,report,error=command()
            assert code!=0 and report is None and state()==before,"failed batch did not roll back"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction DROP CONSTRAINT scheduled_job_reject")
        # Lock timeout/cancellation is also a no-write failure. A second connection owns the row.
        setup([{}]);before=state()
        import psycopg
        params=connection.get_connection_params()
        with psycopg.connect(**params) as blocker:
            with blocker.cursor() as cursor:
                cursor.execute("SELECT set_config('search_path', %s, false)",[schema])
                cursor.execute("SELECT id FROM logs_pendingaction WHERE id=31 FOR UPDATE")
                code,report,error=command()
                assert code!=0 and report is None and state()==before,"locked row caused partial writes"
        count+=1
        print(f"Scheduled pending job contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();seed()
