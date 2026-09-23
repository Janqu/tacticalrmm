"""Bulk patch reset parity, including all-or-nothing failure guarantees."""
import hashlib
import json
from datetime import datetime, timezone


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from agents.models import Agent
    from automation.models import Policy
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdatePolicy

    fixed=datetime(2024,1,2,3,4,5,123400,tzinfo=timezone.utc)
    path="/automation/patchpolicy/reset/"

    def cleanup():
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        WinUpdatePolicy.objects.all().delete()

    def setup(scope="all",broken=None):
        cleanup();seed()
        Client.objects.bulk_create([Client(id=31,name="A"),Client(id=32,name="B")])
        Site.objects.bulk_create([Site(id=31,name="A1",client_id=31),Site(id=32,name="A2",client_id=31),Site(id=33,name="B1",client_id=32)])
        Agent.objects.bulk_create([Agent(id=i,agent_id=f"patch-reset-contract-{i}",hostname=f"Host {i}",site_id=i,plat="linux" if i==32 else "windows") for i in (31,32,33)])
        Policy.objects.bulk_create([Policy(id=31,name="Inherited")])
        WinUpdatePolicy.objects.bulk_create([
            WinUpdatePolicy(id=i,agent_id=i,critical="approve",important="manual",moderate="approve",low="manual",other="approve",run_time_frequency="weekly",reboot_after_install="always",reprocess_failed_inherit=False,run_time_hour=12,run_time_days=[0,6],run_time_day=20,reprocess_failed=True,reprocess_failed_times=8,email_if_fail=True,created_by="importer",modified_by="old-editor")
            for i in (31,32,33)
        ]+[WinUpdatePolicy(id=40,policy_id=31,critical="approve")])
        WinUpdatePolicy.objects.update(created_time=fixed,modified_time=fixed)
        Agent.objects.update(created_time=fixed,modified_time=fixed)
        Policy.objects.update(created_time=fixed,modified_time=fixed)
        if broken=="missing":WinUpdatePolicy.objects.filter(pk=33).delete()
        if broken=="duplicate":
            WinUpdatePolicy.objects.bulk_create([WinUpdatePolicy(id=34,agent_id=33)])
            WinUpdatePolicy.objects.filter(pk=34).update(created_time=fixed,modified_time=fixed)
        if broken=="noop":
            WinUpdatePolicy.objects.filter(agent_id__isnull=False).update(critical="inherit",important="inherit",moderate="inherit",low="inherit",other="inherit",run_time_frequency="inherit",reboot_after_install="inherit",reprocess_failed_inherit=True)
        Role.objects.filter(pk=1).update(can_manage_automation_policies=scope!="denied")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        if scope=="combined":role.can_view_clients.add(32);role.can_view_sites.add(31)
        cache.clear()

    def state():
        return {"policies":list(WinUpdatePolicy.objects.order_by("id").values()),"agents":list(Agent.objects.order_by("id").values()),"base":snapshot()}

    def mutation_state(value):
        return {**value,"base":{key:item for key,item in value["base"].items() if key!="tokens"}}

    count=0
    try:
        for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"combined"),(2,"denied"),(3,"all"),(4,"all"),(5,"site"),(6,"all")]:
            for data in [{},{"client":31},{"site":32},{"client":32},{"site":33},{"client":31,"site":33},{"client":999},{"site":999},{"client":None},{"site":None}]:
                setup(scope)
                client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
                response=client.post(path,data,format="json")
                expected=(response.status_code,json.loads(response.content))
                expected_state=state()
                setup(scope);before=state()
                actual=go_request("POST",path,data,user_id=user)
                assert actual==expected,(data,user,scope,expected,actual)
                assert state()==expected_state,(data,user,scope,"state",expected_state,state())
                if actual[0]>=400:assert mutation_state(state())==mutation_state(before),"failed reset changed DB"
                count+=1
        for data in [{"client":"31"},{"site":"32"},{"client":True},{"site":31.9}]:
            setup()
            client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(b"contract-user-1").hexdigest())
            response=client.post(path,data,format="json");expected=(response.status_code,json.loads(response.content));expected_state=state()
            setup();actual=go_request("POST",path,data)
            assert actual==expected,(data,expected,actual)
            assert state()==expected_state,(data,"state")
            count+=1
        # Reject malformed selectors as 400 rather than Django's uncaught 500.
        for data in ({"client":"not-an-id"},{"site":{}},{"client":[]},{"site":"31.5"}):
            setup();before=state()
            response=go_request("POST",path,data)
            assert response[0]==400,response
            assert mutation_state(state())==mutation_state(before),"invalid selector changed DB"
            count+=1
        # Missing/ambiguous later rows must not leave earlier agents reset.
        for broken in ("missing","duplicate"):
            setup(broken=broken);before=state()
            response=go_request("POST",path,{})
            assert response[0]==500,response
            assert mutation_state(state())==mutation_state(before),(broken,"partial reset")
            count+=1
        setup(broken="noop");before=state()
        assert go_request("POST",path,{})[0]==200
        assert mutation_state(state())==mutation_state(before),"no-op reset created audit or changed metadata"
        count+=1
        setup();before=state()
        with connection.cursor() as cursor:cursor.execute("ALTER TABLE winupdate_winupdatepolicy ADD CONSTRAINT patch_reset_contract_reject CHECK (id <> 33 OR critical <> 'inherit') NOT VALID")
        try:
            assert go_request("POST",path,{})[0]==500
            assert mutation_state(state())==mutation_state(before),"late DB failure partially committed reset"
            count+=1
        finally:
            with connection.cursor() as cursor:cursor.execute("ALTER TABLE winupdate_winupdatepolicy DROP CONSTRAINT patch_reset_contract_reject")
        print(f"Patch policy reset contracts: {count} comparisons passed")
        return count
    finally:
        cleanup();seed()
