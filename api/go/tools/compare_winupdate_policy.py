"""Effective patch policy and approval helpers through an isolated Go test bridge."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch


def run(seed, snapshot, dsn):
    from agents.models import Agent
    from automation.models import Policy
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from django.db import connection
    from tacticalrmm.middleware import request_local
    from winupdate.models import WinUpdate, WinUpdatePolicy
    from winupdate.serializers import WinUpdatePolicySerializer

    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    subject="winupdate-policy-agent-31"
    count=0
    debug={"url":"/contract/policy/","method":"POST","view_class":"PolicyContract","view_func":"PolicyContract","view_args":[],"view_kwargs":{},"ip":"127.0.0.1"}
    directory=Path(__file__).resolve().parents[1]

    def setup(scenario):
        request_local.username=None;request_local.debug_info={}
        Agent.objects.all().delete();Policy.objects.all().delete();seed()
        Policy.objects.bulk_create([Policy(id=pk,name=f"Policy {pk}",active=True,enforced=pk==31) for pk in range(31,36)])
        Client.objects.bulk_create([Client(id=31,name="winupdate-policy-client-31",server_policy_id=33)])
        Site.objects.bulk_create([Site(id=31,name="winupdate-policy-site-31",client_id=31,server_policy_id=32)])
        CoreSettings.objects.update(server_policy_id=34,workstation_policy_id=35)
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Policy agent",site_id=31,policy_id=31)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        WinUpdatePolicy.objects.bulk_create([
            WinUpdatePolicy(id=31,agent_id=31),
            *[WinUpdatePolicy(id=10+pk,policy_id=pk,critical="approve",important="ignore",moderate="manual",low="approve",other="approve",run_time_frequency="monthly",run_time_hour=pk-30,run_time_days=[1,4],run_time_day=pk-20,reboot_after_install="required",reprocess_failed=True,reprocess_failed_times=pk-28,email_if_fail=True) for pk in range(31,36)],
        ])
        WinUpdatePolicy.objects.update(created_time=fixed,modified_time=fixed)
        WinUpdate.objects.bulk_create([
            WinUpdate(id=31+i,agent_id=31,guid=None if i==7 else "duplicate" if i in (0,1) else f"guid-{i}",severity=severity,action="ignore" if i%2 else "inherit",installed=False)
            for i,severity in enumerate(["Critical","Critical","Important","Moderate","Low","","Other",None,"critical"])
        ]+[WinUpdate(id=60,agent_id=31,guid="installed",severity="Critical",action="ignore",installed=True),WinUpdate(id=61,agent_id=31,guid="already",severity="Critical",action="approve"),WinUpdate(id=62,agent_id=31,guid=None,severity="Important",action="approve")])
        if scenario=="missing":WinUpdatePolicy.objects.filter(agent_id=31).delete()
        elif scenario=="missing_no_parent":WinUpdatePolicy.objects.filter(agent_id=31).delete();Agent.objects.update(policy_id=None,block_policy_inheritance=True)
        elif scenario=="no_parent":Agent.objects.update(policy_id=None,block_policy_inheritance=True)
        elif scenario=="site":WinUpdatePolicy.objects.filter(policy_id=31).delete()
        elif scenario=="client":WinUpdatePolicy.objects.filter(policy_id__in=[31,32]).delete()
        elif scenario=="default":WinUpdatePolicy.objects.filter(policy_id__in=[31,32,33]).delete()
        elif scenario=="inactive":Policy.objects.filter(pk=31).update(active=False)
        elif scenario=="excluded_agent":Policy.objects.get(pk=31).excluded_agents.add(31)
        elif scenario=="excluded_site":Policy.objects.get(pk=31).excluded_sites.add(31)
        elif scenario=="excluded_client":Policy.objects.get(pk=31).excluded_clients.add(31)
        elif scenario=="block_agent":Agent.objects.update(policy_id=None,block_policy_inheritance=True)
        elif scenario=="block_site":Agent.objects.update(policy_id=None);Site.objects.update(server_policy_id=None,block_policy_inheritance=True)
        elif scenario=="block_client":Agent.objects.update(policy_id=None);Site.objects.update(server_policy_id=None);Client.objects.update(server_policy_id=None,block_policy_inheritance=True)
        elif scenario=="workstation":Agent.objects.update(policy_id=None,monitoring_type="workstation")
        elif scenario=="override":WinUpdatePolicy.objects.filter(pk=31).update(critical="manual",important="approve",moderate="approve",other="ignore",run_time_frequency="daily",run_time_hour=22,run_time_days=[0,6],run_time_day=29,reboot_after_install="never",reprocess_failed_inherit=False,reprocess_failed=False,reprocess_failed_times=1,email_if_fail=False)
        elif scenario=="inherit_schedule":WinUpdatePolicy.objects.filter(pk=31).update(run_time_hour=22,run_time_days=None,run_time_day=29,reprocess_failed=False,email_if_fail=False)
        elif scenario=="duplicate_agent":WinUpdatePolicy.objects.bulk_create([WinUpdatePolicy(id=32,agent_id=31,critical="manual")]);WinUpdatePolicy.objects.filter(pk=32).update(created_time=fixed,modified_time=fixed)
        elif scenario=="duplicate_parent":WinUpdatePolicy.objects.bulk_create([WinUpdatePolicy(id=80,policy_id=31,critical="manual")]);WinUpdatePolicy.objects.filter(pk=80).update(created_time=fixed,modified_time=fixed)
        elif scenario=="all_manual":WinUpdatePolicy.objects.filter(pk=31).update(critical="manual",important="manual",moderate="manual",low="manual",other="manual")
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdatepolicy','id'),100,false)")
        cache.clear()

    def normalize(value):
        if isinstance(value,dict):
            out={}
            for key,item in value.items():
                if key in ("created_time","modified_time") and item is not None:
                    stamp=datetime.fromisoformat(item.replace("Z","+00:00")) if isinstance(item,str) else item
                    if stamp==fixed:item="fixed timestamp"
                    else:
                        assert abs((stamp-datetime.now(timezone.utc)).total_seconds())<10,"unexpected policy timestamp"
                        item="current timestamp"
                out[key]=normalize(item)
            return out
        if isinstance(value,list):return [normalize(item) for item in value]
        return value

    def state():
        return normalize({"base":snapshot(),"policies":list(WinUpdatePolicy.objects.order_by("id").values()),"updates":list(WinUpdate.objects.order_by("id").values()),"agents":list(Agent.objects.order_by("id").values())})

    try:
        with tempfile.TemporaryDirectory(prefix="trmm-update-policy-") as temporary:
            binary=Path(temporary)/"policy.test";source=Path(temporary)/"input.json";output=Path(temporary)/"output.json"
            subprocess.run(["go","test","-c","./internal/httpapi","-o",str(binary)],cwd=directory,check=True,timeout=120)
            def bridge(actor=None,approve=False,rollback=False):
                source.write_text(json.dumps({"AgentID":subject,"Actor":actor,"Approve":approve,"Rollback":rollback}))
                env=dict(os.environ,TRMM_WINUPDATE_POLICY_DSN=dsn,TRMM_WINUPDATE_POLICY_INPUT=str(source),TRMM_WINUPDATE_POLICY_OUTPUT=str(output))
                subprocess.run([str(binary),"-test.run=^TestWinUpdatePolicyContract$","-test.count=1"],cwd=directory,env=env,check=True,capture_output=True,timeout=40)
                return normalize(json.loads(output.read_text()))
            scenarios=["baseline","missing","missing_no_parent","no_parent","site","client","default","inactive","excluded_agent","excluded_site","excluded_client","block_agent","block_site","block_client","workstation","override","inherit_schedule","duplicate_agent","duplicate_parent","all_manual"]
            for scenario in scenarios:
                for approve in (False,True):
                    setup(scenario)
                    agent=Agent.objects.get(pk=31)
                    with patch.object(Agent,"nats_cmd") as commands,patch("celery.app.task.Task.apply_async") as tasks:
                        policy=normalize(dict(WinUpdatePolicySerializer(agent.get_patch_policy()).data))
                        before_actions=dict(WinUpdate.objects.values_list("id","action"))
                        if approve:agent.approve_updates()
                        changed=sum(action!=before_actions[pk] for pk,action in WinUpdate.objects.values_list("id","action"))
                        guids=agent.get_approved_update_guids()
                    commands.assert_not_called();tasks.assert_not_called()
                    expected_state=state()
                    setup(scenario);actual=bridge(approve=approve)
                    assert actual["policy"]==policy,(scenario,approve,"effective policy",policy,actual)
                    # Source values_list has no ordering; compare exact multiset preserving nulls/duplicates.
                    assert sorted(actual["guids"],key=lambda x:(x is not None,x or ""))==sorted(guids,key=lambda x:(x is not None,x or "")),(scenario,"GUIDs")
                    if approve:assert actual["changed"]==changed,(scenario,changed,actual)
                    assert state()==expected_state,(scenario,approve,"policy/approval state")
                    count+=1
            setup("missing")
            request_local.username="operator";request_local.debug_info=debug
            policy=normalize(dict(WinUpdatePolicySerializer(Agent.objects.get(pk=31).get_patch_policy()).data));expected_state=state()
            setup("missing");actual=bridge(actor={"Username":"operator","DebugInfo":debug})
            assert actual["policy"]==policy and state()==expected_state,"implicit create audit mismatch"
            count+=1
            setup("missing");before=state()
            assert bridge(actor={"Username":"operator","DebugInfo":debug},approve=True,rollback=True)=={"error":True}
            assert state()==before,"rollback retained implicit policy/audit/approvals"
            count+=1
        print(f"Windows update policy contracts: {count} comparisons passed")
        return count
    finally:
        request_local.username=None;request_local.debug_info={}
        Agent.objects.all().delete();Policy.objects.all().delete();seed()
