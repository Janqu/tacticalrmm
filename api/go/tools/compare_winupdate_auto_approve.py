"""Auto-approve Windows updates job contracts against Django's Celery task."""
import json
import os
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from unittest.mock import AsyncMock, patch


def run(seed, snapshot, job_binary, dsn, nats_url=None):
    from agents.models import Agent
    from clients.models import Client, Site
    from django.db import connection
    from django.test import override_settings
    from packaging import version as pyver
    from tacticalrmm.constants import AGENT_STATUS_ONLINE
    from winupdate.models import WinUpdate, WinUpdatePolicy
    from winupdate.tasks import auto_approve_updates_task
    from nats_fixture import responder

    parsed=urlparse(dsn)
    assert parsed.hostname in ("localhost","127.0.0.1","::1"),"auto-approve tests require a loopback DB"
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema=cursor.fetchone()[0]
    assert schema.startswith("go_contract_"),"auto-approve tests require an isolated contract schema"
    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    now=datetime(2025,1,2,12,0,0,tzinfo=timezone.utc)
    lock=0x54524D4D41555044
    count=0

    def setup(rows):
        Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="Approve fixture")])
        Site.objects.bulk_create([Site(id=31,name="Approve fixture",client_id=31)])
        agents=[];policies=[];updates=[]
        for offset,row in enumerate(rows):
            pk=31+offset
            agents.append(Agent(id=pk,agent_id=row.get("agent_id",f"auto-approve-agent-{pk:06d}"),hostname=f"Host {pk}",site_id=31,version=row.get("version","1.3.0"),last_seen=row.get("last_seen",now),offline_time=row.get("offline_time",4),overdue_time=row.get("overdue_time",30),plat=row.get("plat","windows")))
            if not row.get("missing_policy"):
                policies.append(WinUpdatePolicy(id=pk,agent_id=pk,critical=row.get("critical","approve"),important="inherit",moderate="inherit",low="inherit",other="inherit"))
            for index,update in enumerate(row.get("updates",[{"guid":f"g-{pk}","severity":"Critical","action":"ignore"}])):
                updates.append(WinUpdate(id=pk*10+index,agent_id=pk,guid=update.get("guid",f"g-{pk}-{index}"),kb=update.get("kb",f"KB{pk}{index}"),severity=update.get("severity","Critical"),action=update.get("action","ignore"),installed=update.get("installed",False),title=update.get("title","Update (Version 2.0)")))
        Agent.objects.bulk_create(agents);Agent.objects.update(created_time=fixed,modified_time=fixed)
        if policies:
            WinUpdatePolicy.objects.bulk_create(policies);WinUpdatePolicy.objects.update(created_time=fixed,modified_time=fixed)
        if updates:
            WinUpdate.objects.bulk_create(updates)
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdate','id'),1000,false)")
            cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdatepolicy','id'),1000,false)")

    def state():
        return {"base":snapshot(),"agents":list(Agent.objects.order_by("id").values()),"policies":list(WinUpdatePolicy.objects.order_by("id").values()),"updates":list(WinUpdate.objects.order_by("id").values())}

    def online_agent_ids():
        with patch("django.utils.timezone.now",return_value=now):
            return [agent.agent_id for agent in Agent.objects.order_by("id") if agent.status==AGENT_STATUS_ONLINE and pyver.parse(agent.version)>=pyver.parse("1.3.0")]

    def command(*,dry=False,disabled=False,scan_pause_ms=0):
        args=[str(job_binary),"--job","auto-approve-win-updates","--now",now.isoformat(),"--scan-pause",f"{scan_pause_ms}ms"]
        if dry:args.append("--dry-run")
        env=os.environ.copy();env["DATABASE_URL"]=dsn;env["TRMM_WINUPDATE_APPROVE_SCAN_PAUSE_MS"]=str(scan_pause_ms)
        if disabled:env["TRMM_DISABLE_APPROVE_UPDATES_TASK"]="true"
        else:env.pop("TRMM_DISABLE_APPROVE_UPDATES_TASK",None)
        if nats_url and not dry and not disabled:
            env["NATS_URL"]=nats_url;env["NATS_USER"]="tacticalrmm";env["NATS_PASSWORD"]="trmm-test-only"
        else:
            env.pop("NATS_URL",None);env.pop("NATS_USER",None);env.pop("NATS_PASSWORD",None)
        result=subprocess.run(args,env=env,capture_output=True,text=True,timeout=60)
        return result.returncode,json.loads(result.stdout) if result.stdout else None,result.stderr

    def compare(rows,*,dry=False):
        nonlocal count
        setup(rows)
        fake=AsyncMock(return_value=None)
        with override_settings(TRMM_DISABLE_APPROVE_UPDATES_TASK=False),patch("django.utils.timezone.now",return_value=now),patch.object(Agent,"nats_cmd",fake),patch("celery.app.task.Task.apply_async") as tasks,patch("winupdate.tasks.time.sleep") as sleeper:
            auto_approve_updates_task()
        tasks.assert_not_called()
        expected_messages=[]
        for call in fake.call_args_list:
            assert call.args==({"func":"getwinupdates"},) and call.kwargs=={"wait":False},call
            expected_messages.append(call.args[0])
        if len(expected_messages)>40:
            assert sleeper.call_count==((len(expected_messages)-1)//40)
        expected=state()
        setup(rows)
        online=online_agent_ids()
        setup(rows);before=state()
        if dry or not online:
            code,report,error=command(dry=dry,scan_pause_ms=0)
            assert code==0,error
            assert report["job"]=="auto-approve-win-updates"
            assert report["selected"]==len(rows) and report["approved"]==len(rows)
            assert report["scan_eligible"]==len(online) and report["published"]==0
            assert report["dry_run"]==dry and not report["disabled"] and not report["already_running"]
            assert state()==(before if dry else expected),"auto-approve DB mismatch"
            count+=1
            return
        if not nats_url:
            raise AssertionError("publish cases require --nats-url")
        if len(online)==1:
            seen=threading.Event()
            def peer_received(payload):
                seen.set();return None
            with responder(online[0],[peer_received]) as peer:
                code,report,error=command(scan_pause_ms=0)
                assert code==0,error
                if expected_messages:assert seen.wait(5)
                assert peer.messages==expected_messages,(peer.messages,expected_messages)
        else:
            code,report,error=command(scan_pause_ms=0)
            assert code==0,error
        assert report["published"]==len(expected_messages)==len(online),report
        assert report["scan_eligible"]==len(online) and report["selected"]==len(rows),report
        assert state()==expected,"auto-approve publish DB mismatch"
        count+=1

    try:
        compare([])
        compare([{}])
        compare([{}],dry=True)
        compare([{"version":"1.2.9"}])
        compare([{"last_seen":None}])
        compare([{"last_seen":now-timedelta(minutes=5)}])
        compare([{"critical":"approve","updates":[{"guid":"a","severity":"Critical","action":"ignore"},{"guid":"b","severity":"Important","action":"ignore"},{"guid":None,"severity":"Critical","action":"nothing"}]}])
        compare([{"updates":[{"guid":"old","kb":"KB1","title":"Update (Version 1.0)","installed":True},{"guid":"new","kb":"KB1","title":"Update (Version 2.0)","installed":True},{"guid":"pending","severity":"Critical","action":"ignore"}]}])
        setup([{}]);before=state()
        code,report,error=command(disabled=True)
        assert code==0 and report["disabled"] and report["selected"]==0 and state()==before,(report,error)
        count+=1
        setup([{}]);before=state()
        with connection.cursor() as cursor:cursor.execute("SELECT pg_advisory_lock(%s)",[lock])
        try:
            code,report,error=command(dry=True)
            assert code==0 and report["already_running"] and report["selected"]==0,(report,error)
            assert state()==before
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("SELECT pg_advisory_unlock(%s)",[lock])
        setup([{"version":"1.3.0"},{"version":"not-a-version"}])
        with patch("django.utils.timezone.now",return_value=now),patch.object(Agent,"nats_cmd") as nats:
            try:auto_approve_updates_task()
            except Exception:pass
            else:raise AssertionError("Django accepted invalid version")
            nats.assert_not_called()
        expected=state()
        setup([{"version":"1.3.0"},{"version":"not-a-version"}])
        code,report,error=command(scan_pause_ms=0)
        assert code!=0 and "invalid agent version" in error,error
        assert state()==expected,"invalid version left divergent approval state"
        count+=1
        if nats_url:
            compare([{"agent_id":"auto-approve-online-000031"},{"agent_id":"auto-approve-online-000032"}])
        print(f"Windows auto-approve job contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();seed()
