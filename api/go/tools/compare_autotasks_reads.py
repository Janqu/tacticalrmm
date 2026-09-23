"""Read-only task and policy-result contracts; never execute a task."""
import hashlib
import json
from datetime import datetime, timezone


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from agents.models import Agent
    from alerts.models import AlertTemplate
    from automation.models import Policy
    from autotasks.models import AutomatedTask, TaskResult
    from checks.models import Check
    from clients.models import Client, Site
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from scripts.models import Script

    fixed = datetime(2024, 1, 2, 13, 4, 5, 123400, tzinfo=timezone.utc)
    models = [AutomatedTask, TaskResult, Check, Script, AlertTemplate, Policy, Agent]

    def cleanup():
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        AutomatedTask.objects.all().delete()
        Script.objects.all().delete()
        AlertTemplate.objects.all().delete()

    def setup(scope):
        cleanup()
        seed()
        AlertTemplate.objects.bulk_create([AlertTemplate(id=31, name="Task notifications", task_always_alert=True, task_always_email=True)])
        Policy.objects.bulk_create([Policy(id=31, name="Tasks"), Policy(id=32, name="Empty")])
        Client.objects.bulk_create([Client(id=31, name="Allowed"), Client(id=32, name="Other")])
        Site.objects.bulk_create([Site(id=31, client_id=31, name="Allowed"), Site(id=32, client_id=32, name="Other")])
        Agent.objects.bulk_create([
            Agent(id=31, agent_id="task-contract-agent-00031", hostname="Zulu", site_id=31, alert_template_id=31),
            Agent(id=32, agent_id="task-contract-agent-00032", hostname="Alpha", site_id=32),
        ])
        Script.objects.bulk_create([Script(id=31, name="Repair")])
        kinds = ["diskspace", "ping", "cpuload", "memory", "winsvc", "script", "eventlog"]
        Check.objects.bulk_create([
            Check(id=31+i, agent_id=31, check_type=kind, name="Probe", script_id=31 if kind=="script" else None,
                  disk="C:", warning_threshold=20, error_threshold=10, svc_display_name="Spooler")
            for i, kind in enumerate(kinds)
        ])
        tasks = []
        schedules = ["manual", "checkfailure", "runonce", "daily", "weekly", "monthly", "monthlydow", "onboarding", "scheduled"]
        for i, kind in enumerate(schedules):
            tasks.append(AutomatedTask(
                id=31+i, name=f"Task {kind}", win_task_name=f"contract-task-{i}", task_type=kind,
                agent_id=31 if i%3==0 else 32 if i%3==1 else None,
                policy_id=31 if i%3==2 else None, assigned_check_id=31+i if i<len(kinds) else None,
                actions=[{"type":"cmd", "command":"whoami", "shell":"cmd", "timeout":10}],
                run_time_date=fixed, expire_date=fixed, daily_interval=1, weekly_interval=1,
                run_time_bit_weekdays=127, monthly_days_of_month=4294967295,
                monthly_months_of_year=4095, monthly_weeks_of_month=31, enabled=i!=3,
                task_supported_platforms=["windows", "linux"] if i%2 else ["windows"],
            ))
        tasks += [AutomatedTask(id=45, name="Unassigned", win_task_name="contract-unassigned"),
                  AutomatedTask(id=46, name="Every three days", win_task_name="contract-three-days", task_type="daily", run_time_date=fixed, daily_interval=3),
                  AutomatedTask(id=47, name="Weekly quirk", win_task_name="contract-weekly", task_type="weekly", run_time_date=fixed, weekly_interval=2,run_time_bit_weekdays=10),
                  AutomatedTask(id=48, name="Last day", win_task_name="contract-last", task_type="monthly",run_time_date=fixed,monthly_months_of_year=3,monthly_days_of_month=2147483648),
                  AutomatedTask(id=49, name="Mixed days", win_task_name="contract-mixed", task_type="monthly",run_time_date=fixed,monthly_months_of_year=5,monthly_days_of_month=2147483651)]
        AutomatedTask.objects.bulk_create(tasks)
        TaskResult.objects.bulk_create([
            TaskResult(id=31, task_id=33, agent_id=31, status="passing", sync_status="synced", stdout="one\n", retcode=0,last_run=fixed, locked_at=fixed,run_status="running"),
            TaskResult(id=32, task_id=33, agent_id=32, status="failing", stderr="other site", retcode=2147483648),
            TaskResult(id=33, task_id=31, agent_id=31, status="pending"),
        ])
        for model in (AutomatedTask, Check, Script, AlertTemplate, Policy, Agent):
            model.objects.update(created_time=fixed, modified_time=fixed)
        Role.objects.filter(pk=1).update(can_list_autotasks=scope!="denied", can_manage_autotasks=scope=="manage",
                                        can_list_automation_policies=scope!="denied", can_manage_automation_policies=scope=="manage")
        role=Role.objects.get(pk=1)
        role.can_view_clients.clear(); role.can_view_sites.clear()
        if scope=="client": role.can_view_clients.add(31)
        if scope=="site": role.can_view_sites.add(32)
        cache.clear()

    def canon(result):
        status, body=result
        # These querysets have no Meta.ordering, so compare membership, not plan order.
        if isinstance(body,list): body=sorted(body,key=lambda row:row["id"])
        return status,body

    def state():
        return {model._meta.db_table:list(model.objects.order_by("id").values()) for model in models}

    paths=["/tasks/", "/tasks/31/", "/tasks/32/", "/tasks/33/", "/tasks/45/", "/tasks/999/", "/tasks/0/",
           "/automation/policies/31/tasks/", "/automation/policies/32/tasks/", "/automation/policies/999/tasks/", "/automation/policies/0/tasks/",
           "/automation/tasks/33/status/", "/automation/tasks/33/run/", "/automation/tasks/999/status/"]
    count=0
    try:
        for user,scope in [(1,"client"),(2,"client"),(2,"site"),(2,"unscoped"),(2,"manage"),(2,"denied"),(3,"unscoped"),(4,"unscoped"),(5,"client"),(6,"manage")]:
            for method in ("GET","HEAD"):
                for path in paths:
                    setup(scope)
                    client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
                    before=state()
                    response=client.generic(method,path)
                    expected=canon((response.status_code,json.loads(response.content) if response.content else None))
                    expected_base=snapshot()
                    assert state()==before,"Django task read changed DB"
                    setup(scope)
                    before=state()
                    actual=canon(go_request(method,path,user_id=user))
                    assert actual==expected,(method,path,user,scope,expected,actual)
                    assert state()==before,"Go task read changed DB"
                    assert snapshot()==expected_base,(method,path,user,scope,"auth state mismatch")
                    count+=1
        print(f"AutoTask read contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
