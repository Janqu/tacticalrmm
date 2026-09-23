"""Audit/debug query contracts using actual Django views and isolated fixtures."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

A1 = "go-logs-agent-one-00000001"
A2 = "go-logs-agent-two-00000002"


def run(seed, go_request, snapshot):
    from accounts.models import APIKey, Role, User
    from agents.models import Agent
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from knox.models import AuthToken
    from logs.models import AuditLog, DebugLog
    from rest_framework.test import APIClient

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)

    def cleanup():
        DebugLog.objects.all().delete()
        AuditLog.objects.all().delete()
        Agent.objects.all().delete()

    def setup(scope="all", zone="UTC"):
        cleanup()
        seed()
        CoreSettings.objects.update(default_time_zone=zone)
        Client.objects.bulk_create([Client(id=91, name="Other")])
        Site.objects.bulk_create([Site(id=91, name="Other site", client_id=91)])
        Agent.objects.bulk_create([
            Agent(id=91, hostname="One", agent_id=A1, site_id=1),
            Agent(id=92, hostname="Two", agent_id=A2, site_id=91),
        ])
        for model in (Client, Site):
            model.objects.update(created_time=fixed, modified_time=fixed)
        AuditLog.objects.bulk_create([
            AuditLog(id=91, username="anna", agent="old hostname", agent_id=A1, action="modify", object_type="agent",
                     before_value={"data":[None,True,9007199254740993]}, after_value={"text":"Grüße"}, debug_info={"ip":"192.0.2.1","method":"PUT"}),
            AuditLog(id=92, username="bob", agent="Two", agent_id=A2, action="add", object_type="check", debug_info={}),
            AuditLog(id=93, username="system", agent=None, agent_id=None, action="delete", object_type="role", debug_info={"ip":None}),
            AuditLog(id=94, username="anna", agent="Deleted", agent_id="deleted-agent", action="modify", object_type="agent", before_value=[1,"two"], after_value="text", debug_info=None),
            AuditLog(id=95, username="bob", agent="", agent_id="", action="add", object_type="site", before_value=42, after_value=True, debug_info=[]),
            AuditLog(id=96, username="anna", agent="One", agent_id=A1, action="modify", object_type="task", message=None),
            AuditLog(id=97, username="bob", agent="Two", agent_id=A2, action="delete", object_type="task", message="future"),
        ])
        now = datetime.now(timezone.utc)
        times = {91: fixed, 92: fixed.replace(month=7), 93: now-timedelta(hours=6),
                 94: fixed+timedelta(seconds=3), 95: fixed+timedelta(seconds=4),
                 96: now-timedelta(hours=2), 97: now+timedelta(days=1)}
        for pk, value in times.items(): AuditLog.objects.filter(pk=pk).update(entry_time=value)
        DebugLog.objects.bulk_create([
            DebugLog(id=91, agent_id=91, log_type="system_issues", log_level="error", message="Grüße"),
            DebugLog(id=92, agent_id=92, log_type="scripting", log_level="info", message="other"),
            DebugLog(id=93, agent=None, log_type="system_issues", log_level="warning", message=None),
            DebugLog(id=94, agent_id=91, log_type="scripting", log_level="info", message="script"),
        ])
        for pk in range(91,95): DebugLog.objects.filter(pk=pk).update(entry_time=fixed+timedelta(seconds=pk))
        Role.objects.filter(pk=1).update(can_view_auditlogs=scope != "denied", can_view_debuglogs=scope != "denied")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client","both"}: role.can_view_clients.add(91)
        if scope in {"site","both"}: role.can_view_sites.add(1)
        if scope == "installer": User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        # The parent snapshot intentionally rejects historic audit timestamps
        # and scalar JSON. These fixtures need both; retain the same mutation
        # guard through direct ORM values, never print credentials on mismatch.
        return tuple(list(model.objects.order_by(model._meta.pk.name).values())
                     for model in (AuditLog,DebugLog,AuthToken,APIKey,User,Role,Client,Site,CoreSettings))

    def request(path, body, uid=1):
        client=APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        with patch("celery.app.task.Task.apply_async") as tasks, patch("agents.push.send_push_to_all") as push:
            response=client.patch(path,body,format="json")
            tasks.assert_not_called()
            push.assert_not_called()
        return response.status_code, json.loads(response.content) if response.content and response.status_code < 500 else None

    def audit(**changes):
        return {"pagination":{"sortBy":"entry_time","descending":True,"rowsPerPage":3,"page":1},**changes}

    bodies=[audit(),audit(agentFilter=[A1]),audit(clientFilter=[91]),audit(agentFilter=[],clientFilter="ignored"),
            audit(agentFilter=[None,"deleted-agent",""]),audit(userFilter=["anna"]),audit(actionFilter=["add","delete"]),
            audit(objectFilter=["task"]),audit(clientFilter=[]),audit(userFilter=[]),audit(timeFilter=1),audit(timeFilter=0.25),
            audit(timeFilter=0),audit(timeFilter=-1),audit(timeFilter=True),
            audit(clientFilter=[1,91],userFilter=["anna"],actionFilter=["modify"],objectFilter=["agent","task"])]
    for page in (2,99,0,-1,"bad",None,2.9,"2",False):
        item=audit();item["pagination"]["page"]=page;bodies.append(item)
    for sort in ("id","username","agent","agent_id","action","object_type","message","before_value","after_value","debug_info"):
        item=audit();item["pagination"].update(sortBy=sort,descending=False,rowsPerPage=50);bodies.append(item)
    debug=[{}, {"agentFilter":A1},{"agentFilter":A2},{"agentFilter":None},{"logTypeFilter":"scripting"},
           {"logLevelFilter":"info"},{"logLevelFilter":None},{"logTypeFilter":"unknown"},
           {"agentFilter":A1,"logTypeFilter":"scripting","logLevelFilter":"info"}]
    def normalized(response, request_body):
        status, body=response
        if not isinstance(body,dict) or "audit_logs" not in body: return response
        # Django has no tie breaker. Normalize only equal-key groups; sorting
        # direction and page membership remain fully checked.
        field=request_body["pagination"]["sortBy"]
        rows=body["audit_logs"]
        ordered=[]
        start=0
        while start<len(rows):
            end=start+1
            while end<len(rows) and rows[end].get(field)==rows[start].get(field): end+=1
            ordered.extend(sorted(rows[start:end],key=lambda row:row["id"]))
            start=end
        return status,{**body,"audit_logs":ordered}

    count=0
    try:
        for scope,uid in [("all",1),("all",5),("all",2),("site",2),("client",2),("both",2),
                          ("denied",2),("all",3),("all",4),("installer",6)]:
            setup(scope)
            for path,values in [("/logs/audit/",bodies),("/logs/debug/",debug)]:
                for body in values:
                    expected=request(path,body,uid)
                    expected_state=state()
                    actual=go_request("PATCH",path,body,user_id=uid)
                    assert normalized(actual,body)==normalized(expected,body),(scope,uid,path,body,expected,actual)
                    assert state()==expected_state,(scope,path,"unexpected database change")
                    count+=1
        for zone in ("Europe/Berlin","America/New_York"):
            setup(zone=zone)
            for path,body in [("/logs/audit/",audit()),("/logs/debug/",{})]:
                expected=request(path,body)
                assert go_request("PATCH",path,body)==expected,(zone,path)
                count+=1
        setup()
        # More than 1000 records verifies the fixed debug cap and descending
        # order independently of request pagination (which debug ignores).
        DebugLog.objects.bulk_create([DebugLog(id=1000+i,agent_id=91,message=str(i)) for i in range(1003)])
        for i in range(1003): DebugLog.objects.filter(pk=1000+i).update(entry_time=fixed+timedelta(days=1,seconds=i))
        expected=request("/logs/debug/",{})
        actual=go_request("PATCH","/logs/debug/",{})
        assert actual==expected and len(actual[1])==1000,"debug cap/order mismatch"
        count+=1
        invalid=[("/logs/audit/",{}),("/logs/audit/",{"pagination":[]}),
                 *[("/logs/audit/",{"pagination":{**audit()["pagination"],"sortBy":sort}}) for sort in ("entry_time;DROP TABLE logs_auditlog","debug_info__ip","-id",None)],
                 *[("/logs/audit/",{"pagination":{**audit()["pagination"],"rowsPerPage":size}}) for size in (0,-1,None,"bad")],
                 ("/logs/audit/",audit(timeFilter="1")),("/logs/audit/",audit(timeFilter=10**50)),
                 ("/logs/audit/",audit(clientFilter="1")),("/logs/audit/",audit(agentFilter=None)),
                 ("/logs/audit/",audit(userFilter=[{}])),("/logs/debug/",{"agentFilter":[]})]
        # Prime authentication cleanup before checking rejected reads.
        go_request("PATCH","/logs/debug/",{})
        before=state()
        for path,body in invalid:
            assert go_request("PATCH",path,body)[0]==400,(path,body)
            assert state()==before,"invalid log query changed state"
            count+=1
        print(f"Log query contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
