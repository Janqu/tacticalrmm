"""Agent release metadata and hostname projection, without remote calls."""
import hashlib
import json


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from agents.models import Agent
    from clients.models import Client, Site
    from django.conf import settings
    from django.core.cache import cache
    from rest_framework.test import APIClient

    def setup(scope):
        Agent.objects.all().delete()
        seed()
        Client.objects.bulk_create([Client(id=31, name="Kunde Ä"), Client(id=32, name="Other")])
        Site.objects.bulk_create([Site(id=31, name="Standort", client_id=31), Site(id=32, name="Other", client_id=32)])
        if scope != "empty":
            Agent.objects.bulk_create([Agent(id=i, agent_id=f"version-contract-agent-{i}", hostname=f"Host {i}", site_id=i, version="0.1") for i in (31,32)])
        Role.objects.filter(pk=1).update(can_list_agents=scope != "denied", can_edit_agent=True)
        role=Role.objects.get(pk=1)
        role.can_view_clients.clear();role.can_view_sites.clear()
        if scope == "client": role.can_view_clients.add(31)
        if scope == "site": role.can_view_sites.add(32)
        cache.clear()

    def normalized(result):
        status, body = result
        if status == 200:
            assert body["versions"] == [settings.LATEST_AGENT_VER]
            body["agents"].sort(key=lambda row: row["id"])
        return status, body

    count=0
    try:
        for user in (1,2,3,4,5,6):
            for scope in ("all","client","site","denied","empty"):
                setup(scope)
                before=list(Agent.objects.order_by("id").values())
                client=APIClient()
                client.credentials(HTTP_AUTHORIZATION="Token "+hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
                response=client.get("/agents/versions/")
                expected=normalized((response.status_code,json.loads(response.content)))
                expected_state=snapshot()
                assert list(Agent.objects.order_by("id").values()) == before
                setup(scope)
                before=list(Agent.objects.order_by("id").values())
                actual=normalized(go_request("GET","/agents/versions/",user_id=user))
                assert actual == expected,(user,scope,expected,actual)
                assert snapshot() == expected_state
                assert list(Agent.objects.order_by("id").values()) == before
                count+=1
        setup("all")
        assert go_request("HEAD","/agents/versions/")[0] == 405
        count+=1
        print(f"Agent version contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        seed()
