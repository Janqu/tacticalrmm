"""Agent DRF-token Chocolatey callbacks; no broker or real agents are involved."""
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from accounts.models import User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient

    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    subject="callback-contract-agent-31"
    other="callback-contract-agent-32"
    tokens={pk:hashlib.sha1(f"isolated-callback-user-{pk}".encode()).hexdigest() for pk in (31,32,33,34)}
    good={"Authorization":"Token "+tokens[31]}
    count=0
    default_details=object()

    def setup(*,details=default_details,action_type="chocoinstall",status="pending"):
        Token.objects.all().delete();Agent.objects.all().delete();seed()
        Client.objects.bulk_create([Client(id=31,name="A")])
        Site.objects.bulk_create([Site(id=31,name="A",client_id=31)])
        Agent.objects.bulk_create([Agent(id=31,agent_id=subject,hostname="A",site_id=31),Agent(id=32,agent_id=other,hostname="B",site_id=31)])
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        User.objects.bulk_create([User(id=pk,username=f"callback-user-{pk}",agent_id=pk if pk in (31,32) else None,is_active=pk!=33,date_joined=fixed) for pk in tokens])
        User.objects.filter(pk__in=tokens).update(created_time=fixed,modified_time=fixed,date_joined=fixed)
        Token.objects.bulk_create([Token(key=value,user_id=pk,created=fixed) for pk,value in tokens.items()])
        Token.objects.update(created=fixed)
        if details is default_details:details={"name":"7zip","output":None,"installed":False,"extra":{"keep":18446744073709551615}}
        PendingAction.objects.bulk_create([PendingAction(id=31,agent_id=31,action_type=action_type,status=status,details=details),PendingAction(id=32,agent_id=32,action_type="chocoinstall",details={"name":"other"})])
        PendingAction.objects.update(entry_time=fixed)
        cache.clear()

    def state():
        return {"base":snapshot(),"agents":list(Agent.objects.order_by("id").values()),"history":list(AgentHistory.objects.order_by("id").values()),"pending":list(PendingAction.objects.order_by("id").values()),"agent_tokens":list(Token.objects.order_by("key").values())}

    def compare(results="Install of 7zip was successful; installed",*,headers=None,method="PATCH",pk=31,target=subject,status="pending",repeat=False):
        nonlocal count
        headers=good if headers is None else headers
        path=f"/api/v4/{target}/{pk}/chocoresult/"
        body={"results":results}
        setup(status=status)
        client=APIClient();client.credentials(**{"HTTP_"+key.upper().replace("-","_"):value for key,value in headers.items()})
        with patch.object(Agent,"nats_cmd") as commands,patch("celery.app.task.Task.apply_async") as jobs:
            response=client.generic(method,path,json.dumps(body),content_type="application/json")
            if repeat:response=client.generic(method,path,json.dumps(body),content_type="application/json")
        commands.assert_not_called();jobs.assert_not_called()
        expected=response.status_code,json.loads(response.content) if response.content else None
        expected_state=state()
        setup(status=status)
        actual=go_request(method,path,body,headers=headers)
        if repeat:actual=go_request(method,path,body,headers=headers)
        assert actual==expected,(method,headers,pk,target,expected,actual)
        actual_state=state()
        differences=[]
        for table,expected_rows in expected_state.items():
            actual_rows=actual_state[table]
            if actual_rows==expected_rows:continue
            if isinstance(expected_rows,list) and isinstance(actual_rows,list) and len(expected_rows)==len(actual_rows):
                fields=sorted({field for left,right in zip(expected_rows,actual_rows) for field in set(left)|set(right) if left.get(field)!=right.get(field)})
                differences.append((table,fields))
            elif isinstance(expected_rows,dict) and isinstance(actual_rows,dict):
                differences.append((table,[key for key in expected_rows if expected_rows[key]!=actual_rows.get(key)]))
            else:differences.append((table,"row count or shape"))
        assert not differences,(method,pk,target,"callback database differences",differences)
        count+=1

    def safe_failure(body,*,details=default_details,action_type="chocoinstall",target=subject,status=400):
        nonlocal count
        setup(details=details,action_type=action_type);before=state()
        actual=go_request("PATCH",f"/api/v4/{target}/31/chocoresult/",body,headers=good)
        assert actual[0]==status,(body,details,target,actual)
        assert state()==before,"Rejected callback mutated state"
        count+=1

    try:
        for output in ("Install of 7zip was successful; installed","7ZIP ALREADY INSTALLED --FORCE REINSTALL","install of 7zip was successful","installed install of other was successful","failed", "", "Ä output\ninstall OF 7ZiP was SUCCESSFUL and installed", "reinstalled 7zip was install of successful"):
            compare(output)
        compare(repeat=True)
        compare(status="completed")
        for headers in ({}, {"Authorization":""},{"Authorization":"Bearer "+tokens[31]},{"Authorization":"Token"},{"Authorization":"Token a b"},{"Authorization":"Token invalid"},{"Authorization":"tOkEn "+tokens[31]},{"Authorization":"Token   "+tokens[31]},{"Authorization":"Token\t"+tokens[31]},{"Authorization":"Token é"},{"Authorization":"Token "+tokens[33]},{"Authorization":"Token "+tokens[34]},{"Authorization":"Token "+hashlib.sha256(b"contract-user-1").hexdigest()},{"X-API-KEY":"valid-api-key"}):
            compare(headers=headers)
        compare(pk=32)
        compare(pk=999)
        compare(pk=0)
        compare(target=other,pk=32,headers={"Authorization":"Token "+tokens[32]})
        for method in ("GET","HEAD","POST","DELETE"):
            compare(method=method)
            compare(method=method,headers={})
        # Source ignores URL agentid and action type; reject these rather than allowing unrelated writes.
        safe_failure({"results":"ok"},target=other,status=404)
        safe_failure({"results":"ok"},target="missing",status=404)
        safe_failure({"results":"ok"},action_type="runcmd",status=404)
        for body in ({}, {"results":None}, {"results":False}, {"results":1}, {"results":[]}, {"results":{}}, []):
            safe_failure(body)
        for details in (None, {}, {"name":""}, {"name":"   "}, {"name":None}, {"name":False}, {"name":1}, {"name":[]}, [], "invalid"):
            safe_failure({"results":"ok"},details=details)
        # A failed SQL update must retain every field, including the original pending status.
        setup();before=state()
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE logs_pendingaction ADD CONSTRAINT callback_contract_reject CHECK (status <> 'completed') NOT VALID")
        try:
            actual=go_request("PATCH",f"/api/v4/{subject}/31/chocoresult/",{"results":"installed install of 7zip was successful"},headers=good)
            assert actual[0]==500,actual
            assert state()==before,"SQL failure partially changed the callback row"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE logs_pendingaction DROP CONSTRAINT callback_contract_reject")
        print(f"Agent callback contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete();Agent.objects.all().delete();seed()
