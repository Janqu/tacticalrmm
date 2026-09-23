"""Completion branches without reboot; reboot branches are explicit atomic501."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdate, WinUpdatePolicy
    from automation.models import Policy
    from logs.models import DebugLog

    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    subject="update-scan-agent-000031"
    other="update-scan-agent-000032"
    missing="update-scan-agent-missing"
    token={pk:hashlib.sha1(f"isolated-winupdate-agent-{pk}".encode()).hexdigest() for pk in (31,32,33,34)}
    headers={"Authorization":"Token "+token[31]}
    count=0
    new={"guid":"new","kb_article_ids":["100"],"title":"  Unicode Ä update  ","description":None,"severity":"Important","categories":["Security",None],"category_ids":[],"more_info_urls":["https://example.invalid/a"],"support_url":None,"revision_number":3,"downloaded":False,"installed":False}

    def setup(scope="all",platform="windows"):
        Token.objects.all().delete();Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31),Site(id=32,name="B",client_id=32)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="Scan fixture",site_id=31,plat=platform),Agent(id=32,agent_id=other,hostname="Other",site_id=32)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=pk,username=f"scan-callback-{pk}",agent_id=pk if pk in (31,32) else None,is_active=pk!=33,date_joined=fixed) for pk in token])
        User.objects.filter(pk__in=token).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.bulk_create([Token(key=value,user_id=pk) for pk,value in token.items()]);Token.objects.update(created=fixed)
        WinUpdate.objects.bulk_create([
            WinUpdate(id=31,agent_id=31,guid="known",kb="KB31",title="earlier duplicate",action="ignore",installed=True,result="success",date_installed=fixed),
            WinUpdate(id=32,agent_id=31,guid="known",kb="KB32",title="highest duplicate",action="approve",result="failed"),
            WinUpdate(id=33,agent_id=31,guid="stale",kb="KB33"),
            WinUpdate(id=34,agent_id=31,guid="installed",kb="KB34",installed=True),
            WinUpdate(id=35,agent_id=31,guid=None,kb=None),
            WinUpdate(id=36,agent_id=32,guid="known",kb="KB36"),
            WinUpdate(id=41,agent_id=31,guid="oldversion",kb="KB41",title="Update (Version 1.0)",installed=True),
            WinUpdate(id=42,agent_id=31,guid="newversion",kb="KB41",title="Update (Version 2.0)",installed=True),
        ])
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdate','id'),100,false)")
        Role.objects.filter(pk=1).update(can_manage_winupdates=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state():
        return {"base":snapshot(),"agents":list(Agent.objects.order_by("id").values()),"history":list(AgentHistory.objects.order_by("id").values()),"pending":list(PendingAction.objects.order_by("id").values()),"updates":list(WinUpdate.objects.order_by("id").values()),"agent_tokens":list(Token.objects.order_by("key").values())}

    def client_for(auth):
        client=APIClient();client.credentials(**{"HTTP_"+k.upper().replace("-","_"):v for k,v in auth.items()});return client

    base_setup=setup
    base_state=state
    def setup_completion(parent="never",own="inherit",missing=False):
        Policy.objects.filter(pk=31).delete()
        base_setup()
        Policy.objects.bulk_create([Policy(id=31,name="completion-contract-policy",active=True)])
        Agent.objects.filter(pk=31).update(policy_id=31)
        WinUpdatePolicy.objects.bulk_create([WinUpdatePolicy(id=41,policy_id=31,reboot_after_install=parent)])
        if not missing:WinUpdatePolicy.objects.bulk_create([WinUpdatePolicy(id=31,agent_id=31,reboot_after_install=own)])
        WinUpdatePolicy.objects.update(created_time=fixed,modified_time=fixed)
        with connection.cursor() as cursor:cursor.execute("SELECT setval(pg_get_serial_sequence('winupdate_winupdatepolicy','id'),100,false)")
        cache.clear()

    def state():
        result=base_state()
        result["policies"]=list(WinUpdatePolicy.objects.order_by("id").values())
        result["debug_logs"]=list(DebugLog.objects.order_by("id").values())
        for row in result["policies"]:
            for key in ("created_time","modified_time"):
                stamp=row[key]
                if stamp is not None and stamp!=fixed:
                    assert abs((stamp-datetime.now(timezone.utc)).total_seconds())<10,"unexpected policy timestamp"
                    row[key]="current policy timestamp"
        return result

    def compare(needs,parent="never",own="inherit",missing=False,auth=None,repeat=False):
        nonlocal count
        auth=headers if auth is None else auth
        body={"needs_reboot":needs,"agent_id":"ignored-input-agent","agent":32}
        setup_completion(parent,own,missing)
        with patch.object(Agent,"nats_cmd",new=AsyncMock()) as commands,patch("celery.app.task.Task.apply_async") as jobs:
            response=client_for(auth).put("/api/v3/winupdates/",body,format="json")
            if repeat:response=client_for(auth).put("/api/v3/winupdates/",body,format="json")
        commands.assert_not_called();jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup_completion(parent,own,missing)
        actual=go_request("PUT","/api/v3/winupdates/",body,headers=auth)
        if repeat:actual=go_request("PUT","/api/v3/winupdates/",body,headers=auth)
        assert actual==expected,(needs,parent,own,missing,expected,actual)
        assert state()==expected_state,(needs,parent,own,missing,"completion DB state")
        count+=1

    def rejected_reboot(needs,parent,own="inherit",missing=False):
        nonlocal count
        setup_completion(parent,own,missing)
        body={"needs_reboot":needs}
        # Confirm this is actually a source reboot branch, with transport mocked out.
        fake=AsyncMock(return_value=None)
        with patch.object(Agent,"nats_cmd",fake):
            response=client_for(headers).put("/api/v3/winupdates/",body,format="json")
        assert response.status_code==200
        fake.assert_awaited_once_with({"func":"rebootnow"},wait=False)
        setup_completion(parent,own,missing);before=state()
        actual=go_request("PUT","/api/v3/winupdates/",body,headers=headers)
        assert actual==(501,{"detail":"Windows update completion requiring a reboot is not implemented."}),actual
        assert state()==before,"reboot rejection retained needs_reboot, policy creation, logs or prune"
        count+=1

    try:
        for parent in ("never","inherit","unknown"):
            for needs in (False,True):compare(needs,parent)
        compare(False,"required")
        compare(True,"always",own="never")
        compare(False,"always",own="required")
        compare(True,"required",own="never")
        compare(True,"never",missing=True)
        compare(False,"required",missing=True)
        compare(True,"never",repeat=True)
        for auth in ({},{"Authorization":"Token invalid"},{"Authorization":"Token "+token[33]},{"Authorization":"Token "+token[34]},{"Authorization":"Token "+hashlib.sha256(b"contract-user-1").hexdigest()},{"X-API-KEY":"valid-api-key"},{"Authorization":"Token "+token[32]}):compare(True,auth=auth)
        for needs,parent,own,missing in [(False,"always","inherit",False),(True,"always","inherit",False),(True,"required","inherit",False),(True,"never","always",False),(True,"always","inherit",True),(True,"required","inherit",True)]:
            rejected_reboot(needs,parent,own,missing)
        for body in ({},[],*[{'needs_reboot':value} for value in (None,"true",0,1,[],{})]):
            setup_completion(missing=True);before=state()
            actual=go_request("PUT","/api/v3/winupdates/",body,headers=headers)
            assert actual[0]==400 and state()==before,(body,actual)
            count+=1
        # After default-policy creation, failed agent UPDATE or cleanup rolls everything back.
        for fail_cleanup in (False,True):
            setup_completion(missing=True);before=state()
            with connection.cursor() as cursor:
                if fail_cleanup:
                    cursor.execute("CREATE FUNCTION completion_reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated completion cleanup failure'; END $$")
                    cursor.execute("CREATE TRIGGER completion_reject_delete BEFORE DELETE ON winupdate_winupdate FOR EACH ROW EXECUTE FUNCTION completion_reject_delete()")
                else:cursor.execute("ALTER TABLE agents_agent ADD CONSTRAINT completion_reject_reboot CHECK (NOT needs_reboot) NOT VALID")
            try:
                actual=go_request("PUT","/api/v3/winupdates/",{"needs_reboot":True},headers=headers)
                assert actual[0]==500 and state()==before,(actual,"completion rollback")
                count+=1
            finally:
                with connection.cursor() as cursor:
                    if fail_cleanup:
                        cursor.execute("DROP TRIGGER completion_reject_delete ON winupdate_winupdate")
                        cursor.execute("DROP FUNCTION completion_reject_delete()")
                    else:cursor.execute("ALTER TABLE agents_agent DROP CONSTRAINT completion_reject_reboot")
        print(f"Windows completion contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();Policy.objects.filter(pk=31).delete();seed()
