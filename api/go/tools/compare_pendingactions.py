"""Pending-action reads, expiry hook, and safe local cancellations."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

A1="go-pending-agent-one-00001"
A2="go-pending-agent-two-00002"
MISSING="go-pending-agent-missing-0"


def run(seed, go_request, snapshot, redis_url=None):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.test import APIClient

    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)

    def cleanup():
        PendingAction.objects.all().delete()
        Agent.objects.all().delete()

    def setup(scope="all"):
        cleanup();seed()
        CoreSettings.objects.update(default_time_zone="America/New_York")
        Client.objects.bulk_create([Client(id=101,name="Other")])
        Site.objects.bulk_create([Site(id=101,name="Other",client_id=101)])
        Agent.objects.bulk_create([
            Agent(id=101,agent_id=A1,hostname="One",site_id=1,time_zone="Pacific/Kiritimati"),
            Agent(id=102,agent_id=A2,hostname="Two",site_id=101,time_zone=None),
        ])
        now=datetime.now(timezone.utc)
        entries=[
            PendingAction(id=101,agent_id=101,action_type="runcmd",details={"cmd":"whoami"}),
            PendingAction(id=102,agent_id=101,action_type="runscript",details=None),
            PendingAction(id=103,agent_id=101,action_type="schedreboot",status="completed",
                          details={"time":(now+timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),"taskname":"reboot"}),
            PendingAction(id=104,agent_id=102,action_type="schedreboot",status="completed",
                          details={"time":(now-timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),"taskname":"future-reboot"}),
            PendingAction(id=105,agent_id=101,action_type="agentupdate",details={"version":"2.10.0"}),
            PendingAction(id=106,agent_id=101,action_type="chocoinstall",details={"name":"Firefox"}),
            PendingAction(id=107,agent_id=101,action_type="runpatchscan",details={}),
            PendingAction(id=108,agent_id=102,action_type="runpatchinstall",details={}),
            PendingAction(id=109,agent_id=101,action_type=None,status="completed",details=None),
            PendingAction(id=110,agent_id=101,action_type="unknown",details=[]),
            PendingAction(id=111,agent_id=101,action_type="schedreboot",status="completed",details={"time":"not parsed when completed"}),
        ]
        PendingAction.objects.bulk_create(entries)
        PendingAction.objects.filter(pk__in=[103,104]).update(status="pending")
        PendingAction.objects.update(entry_time=fixed)
        Role.objects.filter(pk=1).update(can_list_pendingactions=scope not in {"denied","head"},
                                         can_manage_pendingactions=scope not in {"denied","readonly"})
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope in {"site","head"}:role.can_view_sites.add(1)
        if scope=="client":role.can_view_clients.add(101)
        if scope=="installer":User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def rows():
        # values() deliberately avoids PendingAction.post_init changing status.
        return list(PendingAction.objects.order_by("id").values())

    def mutation_state():
        return rows(),{key:value for key,value in snapshot().items() if key!="tokens"}

    def reference(method,path,uid):
        client=APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        with patch.object(Agent,"nats_cmd",new_callable=AsyncMock) as nats,patch("celery.app.task.Task.apply_async") as tasks:
            response=client.generic(method,path)
            nats.assert_not_awaited();tasks.assert_not_called()
        return response.status_code,json.loads(response.content) if response.content and response.status_code<500 else None

    def normalize(response):
        status,body=response
        if isinstance(body,list):body=sorted(body,key=lambda row:row["id"])
        return status,body

    count=0
    try:
        for scope,uid in [("all",1),("all",5),("all",2),("site",2),("client",2),("readonly",2),
                          ("head",2),("denied",2),("all",3),("all",4),("installer",6)]:
            for method in ("GET","HEAD"):
                for path in ("/logs/pendingactions/",f"/agents/{A1}/pendingactions/",f"/agents/{A2}/pendingactions/",f"/agents/{MISSING}/pendingactions/"):
                    setup(scope)
                    original=rows()
                    expected=reference(method,path,uid)
                    expected_rows,expected_auth=rows(),snapshot()
                    # Restore statuses only: timestamps and expiry wall times
                    # stay identical across the two implementations.
                    for row in original:PendingAction.objects.filter(pk=row["id"]).update(status=row["status"])
                    actual=go_request(method,path,user_id=uid)
                    scope_denied=method=="HEAD" and (scope=="installer" and path.startswith("/agents/") or
                        scope in {"site","head"} and path==f"/agents/{A2}/pendingactions/" or
                        scope=="client" and path==f"/agents/{A1}/pendingactions/")
                    if scope_denied and expected[0] in {200,404}:
                        assert actual[0]==403,(scope,path,actual)
                        assert rows()==original,"unauthorized HEAD changed status"
                    else:
                        assert normalize(actual)==normalize(expected),(scope,uid,method,path,expected,actual)
                        assert rows()==expected_rows,(scope,method,path,"expiry mismatch",expected_rows,rows())
                    assert snapshot()==expected_auth,"unexpected auth/audit change"
                    count+=1
        for scope,uid in [("all",1),("all",5),("all",2),("site",2),("client",2),("readonly",2),("denied",2),("all",3),("installer",6)]:
            for pk in (101,105,106,108,109,110,999,0):
                setup(scope)
                path=f"/logs/pendingactions/{pk}/"
                expected=reference("DELETE",path,uid)
                expected_rows,expected_auth=rows(),snapshot()
                setup(scope)
                actual=go_request("DELETE",path,user_id=uid)
                # Fresh scheduler walltimes are irrelevant to non-scheduled
                # deletes; normalize only the two fixture-generated strings.
                actual_rows=rows()
                for data in (actual_rows,expected_rows):
                    for row in data:
                        if row["id"] in {103,104}:row["details"]["time"]="fixture walltime"
                assert actual==expected,(scope,pk,expected,actual)
                assert actual_rows==expected_rows,(scope,pk,"delete changed wrong rows")
                assert snapshot()==expected_auth,"unexpected delete audit/auth change"
                count+=1
        for pk in (103,104,111):
            setup()
            before=mutation_state()
            result=go_request("DELETE",f"/logs/pendingactions/{pk}/")
            assert result[0]==501,(pk,result)
            assert mutation_state()==before,"unsupported scheduled cancellation changed status/rows"
            count+=1
        setup("client")
        before=mutation_state()
        assert go_request("DELETE","/logs/pendingactions/103/",user_id=2)[0]==403
        assert mutation_state()==before,"unauthorized scheduled cancellation expired another site's action"
        count+=1
        for corrupt in ("timezone","details","delete-details"):
            setup()
            if corrupt=="timezone":Agent.objects.filter(pk=102).update(time_zone="Invalid/Timezone")
            else:PendingAction.objects.filter(pk=105).update(details={})
            before=mutation_state()
            path="/logs/pendingactions/" if corrupt!="delete-details" else "/logs/pendingactions/105/"
            result=go_request("GET" if corrupt!="delete-details" else "DELETE",path)
            assert result[0]==500,(corrupt,result)
            assert mutation_state()==before,(corrupt,"partial expiry/delete leaked on error")
            count+=1
        # Late DB constraint failure must preserve the row and all metadata.
        setup()
        before=mutation_state()
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE go_pending_delete_block (action_id bigint REFERENCES logs_pendingaction(id))")
            cursor.execute("INSERT INTO go_pending_delete_block VALUES (101)")
        try:
            assert go_request("DELETE","/logs/pendingactions/101/")[0]==500
            assert mutation_state()==before,"failed cancellation leaked writes"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("DROP TABLE go_pending_delete_block")
        print(f"Pending action contracts: {count} comparisons passed")
        return count
    finally:
        cleanup();seed()
