"""Software/cached catalog reads; no agent jobs or software changes."""
import hashlib
import json


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from agents.models import Agent
    from clients.models import Client, Site
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from software.models import ChocoSoftware, InstalledSoftware

    def cleanup():
        Agent.objects.all().delete();ChocoSoftware.objects.all().delete()

    def setup(scope, catalog="normal"):
        cleanup();seed()
        Client.objects.bulk_create([Client(id=31,name="Allowed"),Client(id=32,name="Other")])
        Site.objects.bulk_create([Site(id=31,name="Allowed",client_id=31),Site(id=32,name="Other",client_id=32)])
        Agent.objects.bulk_create([Agent(id=i,agent_id=f"software-contract-agent-{i}",hostname=f"Host {i}",site_id=31 if i==31 else 32) for i in (31,32,33,34)])
        InstalledSoftware.objects.bulk_create([
            InstalledSoftware(id=31,agent_id=31,software=[{"name":"Äpp", "size":18446744073709551615},None,True]),
            InstalledSoftware(id=32,agent_id=32,software={"unexpected":"dictionary", "number":9007199254740993}),
            InstalledSoftware(id=33,agent_id=33,software="first duplicate"),
            InstalledSoftware(id=34,agent_id=33,software=False),
        ])
        if catalog!="empty":
            ChocoSoftware.objects.bulk_create([ChocoSoftware(id=32,chocos=[{"name":"newer pk","version":"2"}]),ChocoSoftware(id=31,chocos={"name":"last inserted older pk"})])
        if catalog=="scalar":ChocoSoftware.objects.filter(id=32).update(chocos=False)
        Role.objects.filter(pk=1).update(can_list_software=scope!="denied",can_manage_software=scope=="manage")
        role=Role.objects.get(pk=1);role.can_view_clients.clear();role.can_view_sites.clear()
        if scope=="client":role.can_view_clients.add(31)
        if scope=="site":role.can_view_sites.add(32)
        cache.clear()

    def state():
        return list(InstalledSoftware.objects.order_by("id").values()),list(ChocoSoftware.objects.order_by("id").values("id","chocos"))

    def canon(result):
        status,body=result
        if isinstance(body,list) and all(isinstance(row,dict) and "id" in row for row in body):body=sorted(body,key=lambda row:row["id"])
        return status,body

    paths=["/software/","/software/software-contract-agent-31/","/software/software-contract-agent-32/","/software/software-contract-agent-33/","/software/software-contract-agent-34/","/software/software-contract-missing-99/","/software/chocos/"]
    count=0
    try:
        for user,scope in [(1,"all"),(2,"all"),(2,"client"),(2,"site"),(2,"manage"),(2,"denied"),(3,"all"),(4,"all"),(5,"client"),(6,"manage")]:
            for method in ("GET","HEAD"):
                for path in paths:
                    setup(scope);before=state()
                    client=APIClient();client.raise_request_exception=False
                    client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
                    response=client.generic(method,path)
                    expected=canon((response.status_code,json.loads(response.content) if response.content else None))
                    expected_base=snapshot()
                    assert state()==before,"Django software read changed data"
                    setup(scope);before=state()
                    actual=canon(go_request(method,path,user_id=user))
                    if method=="HEAD" and path=="/software/" and expected[0]==500:
                        # Source SoftwarePerms incorrectly reads nonexistent agent_id on global HEAD.
                        assert actual==(200,None),(method,path,user,scope,actual)
                    else:assert actual==expected,(method,path,user,scope,expected,actual)
                    assert state()==before,"Go software read changed data"
                    assert snapshot()==expected_base,(method,path,user,scope,"auth state")
                    count+=1
        for catalog in ("empty","scalar"):
            setup("denied",catalog)
            client=APIClient();client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(b"contract-user-3").hexdigest())
            response=client.get("/software/chocos/");expected=(response.status_code,json.loads(response.content))
            setup("denied",catalog);before=state()
            assert go_request("GET","/software/chocos/",user_id=3)==expected
            assert state()==before
            count+=1
        print(f"Software read contracts: {count} comparisons passed")
        return count
    finally:
        cleanup();seed()
