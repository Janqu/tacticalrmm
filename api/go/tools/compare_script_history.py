"""Script history reads, including deliberate cross-client scope enforcement."""
import hashlib
import json
from datetime import datetime
from urllib.parse import urlencode
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from scripts.models import Script
    from rest_framework.test import APIClient

    count = 0
    def setup(scope="all"):
        Agent.objects.all().delete()
        Script.objects.all().delete()
        seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id="history-contract-agent-31",hostname="A",site_id=31),Agent(id=32,agent_id="history-contract-agent-32",hostname="B",site_id=32)])
        Script.objects.bulk_create([Script(id=31,name="Ä Script",shell="powershell"),Script(id=32,name="Other",shell="powershell")])
        AgentHistory.objects.bulk_create([
            AgentHistory(id=31,agent_id=31,type="script_run",script_id=31,username="first",script_results={"retcode":0,"stdout":"Ä", "large":18446744073709551615}),
            AgentHistory(id=32,agent_id=32,type="script_run",script_id=31,username="other",script_results=[False,None]),
            AgentHistory(id=33,agent_id=31,type="script_run",script_id=None,username="deleted",script_results=None),
            AgentHistory(id=34,agent_id=32,type="script_run",script_id=32,username="latest",script_results="scalar"),
            AgentHistory(id=35,agent_id=31,type="cmd_run",script_id=31,username="exclude"),
        ])
        for pk,stamp in [(31,"2025-01-01T00:00:00+00:00"),(32,"2025-01-02T00:00:00+00:00"),(33,"2025-01-03T00:00:00+00:00"),(34,"2025-01-03T00:00:00.000001+00:00"),(35,"2025-01-04T00:00:00+00:00")]:
            AgentHistory.objects.filter(pk=pk).update(time=datetime.fromisoformat(stamp))
        Role.objects.filter(pk=1).update(can_list_agent_history=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        if scope=="both":role.can_view_clients.add(31);role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        return [list(m.objects.order_by("id").values()) for m in (Agent,AgentHistory,Script)]

    def compare(method="GET",user=1,scope="all",query=()):
        nonlocal count
        path="/agents/scripthistory/"+("?"+urlencode(query) if query else "")
        setup(scope);before=state()
        client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        with patch.object(Agent,"nats_cmd") as commands, patch("celery.app.task.Task.apply_async") as jobs:
            response=client.generic(method,path)
            expected=response.status_code,json.loads(response.content) if response.content else None
            if method=="GET" and user==2 and scope in ("client","site") and expected[0]==200:
                # Source leaks all tenants. Compute authorized rows before applying the requested limit.
                unbounded=[(key,value) for key,value in query if key!="limit"]
                all_rows=client.get("/agents/scripthistory/?"+urlencode(unbounded)).json()
                filtered=[row for row in all_rows if row["agent"]==(31 if scope=="client" else 32)]
                limit=dict(query).get("limit")
                if limit:filtered=filtered[:int(limit)]
                expected=200,filtered
        commands.assert_not_called();jobs.assert_not_called()
        assert state()==before
        expected_base=snapshot()
        setup(scope);before=state()
        actual=go_request(method,path,user_id=user)
        assert actual==expected,(method,user,scope,query,expected,actual)
        assert state()==before,"History read mutated data"
        assert snapshot()==expected_base,"History auth/audit mismatch"
        count+=1

    try:
        for method in ("GET","HEAD"):
            for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"both"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"all")]:
                compare(method,user,scope)
        for query in [
            [("limit",value)] for value in ("0","1","2"," +002 ","1_0","١٢","")
        ] + [
            [("scriptname","Ä Script")],[("scriptname","ä script")],[("scriptname","missing")],
            [("scriptname","Other"),("scriptname","Ä Script")],
            [("start","invalid")],[("end","invalid")],
            [("start","2025-01-01"),("end","2025-01-02")],
            [("start","2025-01-03T00:00:00Z"),("end","2025-01-01T00:00:00Z")],
            [("start","2025-01-01T01:00:00+01:00"),("end","2025-01-02T01:00:00+01:00")],
            [("page","99"),("page_size","1"),("ordering","username")],
            [("limit","1"),("limit","3")],
        ]:
            compare(query=query)
        for scope in ("client","site"):
            compare(user=2,scope=scope,query=[("limit","1")])
            compare(user=2,scope=scope,query=[("scriptname","Ä Script"),("limit","1")])
        # Invalid ranges/limits become actionable400 instead of Django's uncaught500.
        for query in [[("limit",value)] for value in ("bad","-1","1.5","1__0","99999999999999999999999999999")] + [[("start","invalid"),("end","2025-01-01")],[("start","2025-01-01"),("end","invalid")],[("start","9999-12-31"),("end","9999-12-31")]]:
            setup();before=state()
            actual=go_request("GET","/agents/scripthistory/?"+urlencode(query))
            assert actual[0]==400,(query,actual)
            assert state()==before
            count+=1
        print(f"Script history contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete();Script.objects.all().delete();seed()
