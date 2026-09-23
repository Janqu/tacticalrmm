"""Read-only event log contracts using isolated broker responses."""
import copy
import hashlib
import json
import struct
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from nats_fixture import responder


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from logs.models import PendingAction
    from rest_framework.test import APIClient

    subject = "eventlog-contract-agent-001"
    missing = "eventlog-contract-missing-0"
    fixed = datetime(2024, 1, 2, tzinfo=timezone.utc)

    def setup(scope="all", platform="windows"):
        Agent.objects.all().delete()
        seed()
        Client.objects.bulk_create([Client(id=31, name="Event logs")])
        Site.objects.bulk_create([Site(id=31, name="Event logs", client_id=31)])
        Agent.objects.bulk_create([Agent(id=31, agent_id=subject, hostname="Event fixture", site_id=31, plat=platform)])
        Agent.objects.update(created_time=fixed, modified_time=fixed)
        Role.objects.filter(pk=1).update(can_view_eventlogs=scope != "denied")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope == "client": role.can_view_clients.add(1)
        if scope == "site": role.can_view_sites.add(1)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state(auth=True):
        auth_state = snapshot()
        if not auth:
            auth_state = {key: value for key, value in auth_state.items() if key != "tokens"}
        return {model._meta.db_table: list(model.objects.order_by("id").values())
                for model in (Agent, AgentHistory, PendingAction)}, auth_state

    count = 0

    def compare(name="Application", days="7", reply=None, *, method="GET", scope="all", uid=1, target=subject, platform="windows"):
        nonlocal count
        setup(scope, platform)
        url = f"/agents/{target}/eventlog/{quote(name, safe='')}/{days}/"
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{uid}".encode()).hexdigest())
        with patch.object(Agent, "nats_cmd", new_callable=AsyncMock, return_value=reply) as request, \
                patch("celery.app.task.Task.apply_async") as tasks:
            result = client.generic(method, url)
            tasks.assert_not_called()
            calls = [(copy.deepcopy(call.args), copy.deepcopy(call.kwargs))
                     for call in request.await_args_list]
        expected = result.status_code, json.loads(result.content) if result.content and result.status_code < 500 else None
        expected_state = state()
        setup(scope, platform)
        wire = b"\xc0" if reply is None else reply
        with responder(subject, [wire]) as peer:
            actual = go_request(method, url, user_id=uid)
        assert actual == expected, (method, name, days, uid, scope, expected, actual)
        assert state() == expected_state, "event log read changed database state"
        assert len(peer.messages) == len(calls), "event log dispatch count differs"
        if calls:
            timeout = 180 if name == "Security" else 30
            payload = {"func": "eventlog", "timeout": timeout, "payload": {"logname": name, "days": str(int(days))}}
            assert peer.messages == [payload], "event log wire payload differs"
            assert calls[0] == ((payload,), {"timeout": timeout + 2}), calls[0]
        count += 1

    try:
        for name in ("Application", "System", "Security", "security", "Custom Ä name", "Literal%Name", "Plus+Name"):
            for days in ("0", "0007", "18446744073709551616000"):
                compare(name, days, [{"eventID": 123, "message": "event ü", "type": "Information"}])
        for reply in ([], {}, "timeout", "natsdown", "other error", False, 42, None):
            compare(reply=reply)
        for uid, scope in [(1, "all"), (2, "all"), (2, "denied"), (2, "client"), (2, "site"),
                           (3, "all"), (4, "all"), (5, "all"), (6, "all")]:
            for method in ("GET", "HEAD"):
                for target in (subject, missing):
                    compare(reply=[], uid=uid, scope=scope, method=method, target=target)
        for days in ("-1", "+1", "1.0", "abc"):
            setup()
            before = state(False)
            with responder(subject, [[]]) as peer:
                actual = go_request("GET", f"/agents/{subject}/eventlog/Application/{days}/")
            assert actual[0] == 404, actual
            assert not peer.messages
            assert state(False) == before
            count += 1
        for platform in ("linux", "darwin"):
            compare(reply=[], platform=platform)
        for wire in (b"\xc1", b"\xcb" + struct.pack(">d", float("nan"))):
            setup()
            before = state(False)
            with responder(subject, [wire]) as peer:
                actual = go_request("GET", f"/agents/{subject}/eventlog/Application/7/")
            assert actual[0] == 502, actual
            assert peer.messages == [{"func": "eventlog", "timeout": 30, "payload": {"logname": "Application", "days": "7"}}]
            assert state(False) == before
            count += 1
        setup()
        before = state(False)
        assert go_request("GET", f"/agents/{subject}/eventlog/Security/1/") == (400, "Unable to contact the agent")
        assert state(False) == before
        count += 1
        print(f"Event log contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        seed()
