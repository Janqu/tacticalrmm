"""Services read contracts using mocked Django and a real isolated NATS peer."""
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from nats_fixture import responder


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from agents.models import Agent
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from rest_framework.test import APIClient

    subject = "go-service-agent-one-0001"
    prior = [{"name": "cached", "status": "stopped"}]
    path = f"/services/{subject}/"
    detail_path = path + "Spooler/"

    def cleanup():
        Agent.objects.all().delete()

    def setup(scope="all", platform="windows"):
        cleanup()
        seed()
        Client.objects.bulk_create([Client(id=101, name="Service other")])
        Site.objects.bulk_create([Site(id=101, name="Service other", client_id=101)])
        Agent.objects.bulk_create([Agent(id=101, agent_id=subject, hostname="Service fixture",
                                        site_id=101, services=prior, plat=platform)])
        Agent.objects.update(created_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
                             modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc))
        Role.objects.filter(pk=1).update(can_manage_winsvcs=scope != "denied")
        if scope == "all":
            role = Role.objects.get(pk=1)
            role.can_view_clients.clear()
            role.can_view_sites.clear()
        cache.clear()

    def state(auth=True):
        values = snapshot()
        if not auth:
            values = {key: value for key, value in values.items() if key != "tokens"}
        return list(Agent.objects.order_by("id").values()), values

    def reference(method, url, reply, uid):
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        with patch.object(Agent, "nats_cmd", new_callable=AsyncMock, return_value=reply) as request, \
                patch("celery.app.task.Task.apply_async") as tasks:
            result = client.generic(method, url)
            tasks.assert_not_called()
        body = json.loads(result.content) if result.content and result.status_code < 500 else None
        return (result.status_code, body), request.await_args_list

    count = 0
    try:
        replies = [[], [{"name": "Spooler", "status": "running", "display_name": "Print Spooler"}],
                   {"name": "Spooler", "start_type": "Automatic"}, "timeout", "natsdown", "other error", False, 12]
        for method in ("GET", "HEAD"):
            for detail in (False, True):
                for reply in replies:
                    setup()
                    url = detail_path if detail else path
                    expected, calls = reference(method, url, reply, 1)
                    expected_state = state()
                    setup()
                    payload = {"func": "winsvcdetail", "payload": {"name": "Spooler"}} if detail else {"func": "winservices"}
                    with responder(subject, [reply]) as peer:
                        actual = go_request(method, url)
                    assert actual == expected, (method, detail, reply, expected, actual)
                    assert state() == expected_state, "services cache or unrelated agent state differs"
                    assert peer.messages == [payload] * len(calls), "service read payload or attempt count differs"
                    if calls:
                        if detail:
                            assert calls[0].args == (payload,) and calls[0].kwargs == {"timeout": 10}
                        else:
                            assert calls[0].args == () and calls[0].kwargs == {"data": payload, "timeout": 10}
                    count += 1

        for scope, uid in [("all", 2), ("denied", 2), ("scoped", 2), ("all", 3), ("all", 4), ("all", 6)]:
            for method in ("GET", "HEAD"):
                for url in (path, detail_path, "/services/go-service-missing-000001/"):
                    setup(scope)
                    expected, calls = reference(method, url, [], uid)
                    expected_state = state()
                    setup(scope)
                    with responder(subject, [[]]) as peer:
                        actual = go_request(method, url, user_id=uid)
                    assert actual == expected, (scope, uid, method, url, expected, actual)
                    assert len(peer.messages) == len(calls)
                    assert state() == expected_state, "permission path changed services"
                    count += 1

        for url in (path, detail_path):
            for reply, status in [(b"\xc1", 502), (None, 400)]:
                setup()
                before = state(False)
                with responder(subject, [reply]) as peer:
                    result = go_request("GET", url)
                assert result[0] == status, (url, result)
                assert len(peer.messages) == 1
                assert state(False) == before, "failed service read changed cached services"
                count += 1
            setup()
            before = state(False)
            assert go_request("GET", url) == (400, "Unable to contact the agent")
            assert state(False) == before
            count += 1

        for name in ("Print Spooler", "Dienst-Ä", "name%literal", "name+plus"):
            setup()
            url = path + quote(name, safe="") + "/"
            expected, calls = reference("GET", url, {"name": name}, 1)
            expected_state = state()
            setup()
            with responder(subject, [{"name": name}]) as peer:
                actual = go_request("GET", url)
            assert actual == expected, (name, expected, actual)
            assert peer.messages == [{"func": "winsvcdetail", "payload": {"name": name}}]
            assert state() == expected_state
            count += 1

        # No platform restriction exists on source reads, including POSIX.
        setup(platform="linux")
        with responder(subject, [[]]) as peer:
            assert go_request("GET", path) == (200, [])
        assert peer.messages == [{"func": "winservices"}]
        count += 1

        setup()
        before = state(False)
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE agents_agent ADD CONSTRAINT go_service_write_block CHECK (services IS DISTINCT FROM '\"blocked\"'::jsonb)")
        try:
            with responder(subject, ["blocked"]) as peer:
                assert go_request("GET", path)[0] == 500
            assert peer.messages == [{"func": "winservices"}]
            assert state(False) == before, "failed cache write changed agent data"
            count += 1
        finally:
            with connection.cursor() as cursor:
                cursor.execute("ALTER TABLE agents_agent DROP CONSTRAINT go_service_write_block")
        print(f"Service read contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
