"""Per-GUID Windows installation result callbacks; no remote operations."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdate

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

    def normalized_state():
        result=state()
        for row in result["updates"]:
            stamp=row["date_installed"]
            if stamp is not None and stamp!=fixed:
                assert abs((stamp-datetime.now(timezone.utc)).total_seconds())<10,"unexpected installation timestamp"
                row["date_installed"]="current installation timestamp"
        return result

    def compare(data,*,auth=None,repeat=False,installed=False):
        nonlocal count
        auth=headers if auth is None else auth
        setup()
        if installed:WinUpdate.objects.filter(pk=32).update(installed=True,downloaded=True,result="success",date_installed=fixed)
        with patch.object(Agent,"nats_cmd") as commands,patch("celery.app.task.Task.apply_async") as jobs:
            response=client_for(auth).patch("/api/v3/winupdates/",data,format="json")
            if repeat:response=client_for(auth).patch("/api/v3/winupdates/",data,format="json")
        commands.assert_not_called();jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=normalized_state()
        setup()
        if installed:WinUpdate.objects.filter(pk=32).update(installed=True,downloaded=True,result="success",date_installed=fixed)
        actual=go_request("PATCH","/api/v3/winupdates/",data,headers=auth)
        if repeat:actual=go_request("PATCH","/api/v3/winupdates/",data,headers=auth)
        assert actual==expected,(data,expected,actual)
        assert normalized_state()==expected_state,(data,"installation callback DB state")
        count+=1

    def reject(data,status=400,method="PATCH"):
        nonlocal count
        setup();before=state()
        actual=go_request(method,"/api/v3/winupdates/",data,headers=headers)
        assert actual[0]==status,(data,actual)
        assert state()==before,"Rejected result callback changed state"
        count+=1

    try:
        for success in (False,True):
            compare({"guid":"known","success":success})
            compare({"guid":"known","success":success},repeat=True)
            compare({"guid":"known","success":success},installed=True)
            compare({"guid":None,"success":success})
            compare({"guid":"oldversion","success":success}) # superseded row can be removed after reporting success
            compare({"guid":"known","success":success,"agent":32,"installed":False,"result":"injected","date_installed":"2000-01-01"})
        for auth in ({}, {"Authorization":"Token invalid"},{"Authorization":"Token "+token[33]},{"Authorization":"Token "+token[34]},{"Authorization":"Token "+hashlib.sha256(b"contract-user-1").hexdigest()},{"X-API-KEY":"valid-api-key"},{"Authorization":"tOkEn   "+token[31]},{"Authorization":"Token "+token[32]}):
            compare({"guid":"known","success":True},auth=auth)
        for data in ({},[],{"success":True},{"guid":[]},*[{'guid':'known','success':value} for value in (None,"true",1,0,[],{})],{"guid":"known"}):reject(data)
        reject({"guid":"missing","success":True},404)
        # The highest GUID row changes, then a cleanup failure must roll it back too.
        for fail_cleanup in (False,True):
            setup();before=state()
            with connection.cursor() as cursor:
                if fail_cleanup:
                    cursor.execute("CREATE FUNCTION winupdate_result_reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated result cleanup failure'; END $$")
                    cursor.execute("CREATE TRIGGER winupdate_result_reject_delete BEFORE DELETE ON winupdate_winupdate FOR EACH ROW EXECUTE FUNCTION winupdate_result_reject_delete()")
                else:
                    cursor.execute("ALTER TABLE winupdate_winupdate ADD CONSTRAINT winupdate_result_reject CHECK (result <> 'success') NOT VALID")
            try:
                actual=go_request("PATCH","/api/v3/winupdates/",{"guid":"known","success":True},headers=headers)
                assert actual[0]==500 and state()==before,(actual,"result transaction failed to roll back")
                count+=1
            finally:
                with connection.cursor() as cursor:
                    if fail_cleanup:
                        cursor.execute("DROP TRIGGER winupdate_result_reject_delete ON winupdate_winupdate")
                        cursor.execute("DROP FUNCTION winupdate_result_reject_delete()")
                    else:cursor.execute("ALTER TABLE winupdate_winupdate DROP CONSTRAINT winupdate_result_reject")
        print(f"Windows update result contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();seed()
