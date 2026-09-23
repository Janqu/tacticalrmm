"""Scheduled cancellation contracts against the isolated real NATS broker."""
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from agents.models import Agent
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.test import APIClient

    subject = "go-pending-nats-agent-0001"
    path = "/logs/pendingactions/101/"
    payload = {"func": "delschedtask", "schedtaskpayload": {"name": "scheduled-reboot"}}

    def cleanup():
        PendingAction.objects.all().delete()
        Agent.objects.all().delete()

    def setup(expired=False):
        cleanup()
        seed()
        Client.objects.bulk_create([Client(id=101, name="Other")])
        Site.objects.bulk_create([Site(id=101, name="Other", client_id=101)])
        Agent.objects.bulk_create([Agent(id=101, agent_id=subject, hostname="NATS fixture", site_id=101, time_zone="UTC")])
        PendingAction.objects.bulk_create([PendingAction(
            id=101, agent_id=101, action_type="schedreboot", status="completed",
            details={"time": "2000-01-01 00:00:00" if expired else "2099-01-01 00:00:00", "taskname": "scheduled-reboot"},
        )])
        PendingAction.objects.filter(pk=101).update(status="pending", entry_time=datetime(2024, 1, 2, tzinfo=timezone.utc))
        cache.clear()

    def state(auth=True):
        values = snapshot()
        if not auth:
            values = {key: value for key, value in values.items() if key != "tokens"}
        return list(PendingAction.objects.order_by("id").values()), values

    def reference(reply):
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(b"contract-user-1").hexdigest())
        with patch.object(Agent, "nats_cmd", new_callable=AsyncMock, return_value=reply) as request:
            result = client.delete(path)
            request.assert_awaited_once_with(payload, timeout=10)
        return result.status_code, json.loads(result.content)

    count = 0
    try:
        for reply in ("ok", "agent refused", "timeout", "natsdown", ""):
            setup()
            expected = reference(reply)
            expected_state = state()
            setup()
            with responder(subject, [reply]) as peer:
                actual = go_request("DELETE", path)
            assert actual == expected, (reply, expected, actual)
            assert state() == expected_state, "scheduled cancellation state differs"
            assert peer.messages == [payload], "cancellation payload or attempt count differs"
            count += 1

        # Unsafe or undecodable acknowledgments never authorize deletion.
        for reply, code, body in [(b"\xc1", 502, None), ({"ok": True}, 502, None),
                                  (True, 502, None), (None, 400, "timeout")]:
            setup(expired=True)
            before = state(False)
            with responder(subject, [reply]) as peer:
                actual = go_request("DELETE", path)
            assert actual[0] == code, (repr(reply), actual)
            if body is not None:
                assert actual[1] == body, actual
            assert state(False) == before, "failed cancellation expired or removed its row"
            assert peer.messages == [payload], "failed command was retried"
            count += 1

        # No subscriber must fail without changing the row.
        setup(expired=True)
        before = state(False)
        assert go_request("DELETE", path) == (400, "timeout")
        assert state(False) == before
        count += 1

        for uid, managed in [(2, False), (2, True), (3, False), (4, False)]:
            setup(expired=True)
            Role.objects.filter(pk=1).update(can_manage_pendingactions=managed)
            before = state(False)
            with responder(subject, ["ok"]) as peer:
                result = go_request("DELETE", path, user_id=uid)
            assert result[0] in {401, 403}, (uid, managed, result)
            assert not peer.messages, "unauthorized cancellation contacted an agent"
            assert state(False) == before
            count += 1

        for details in ({}, None, [], {"taskname": None}, {"taskname": []}, {"taskname": ""}, {"taskname": " \t "}):
            setup(expired=True)
            PendingAction.objects.filter(pk=101).update(details=details)
            before = state(False)
            with responder(subject, ["ok"]) as peer:
                result = go_request("DELETE", path)
            assert result[0] == 400, (details, result)
            assert not peer.messages
            assert state(False) == before
            count += 1

        setup()
        PendingAction.objects.filter(pk=101).update(details={"time": "2099-01-01 00:00:00", "taskname": " actual task "})
        with responder(subject, ["ok"]) as peer:
            assert go_request("DELETE", path)[0] == 200
        assert peer.messages == [{"func": "delschedtask", "schedtaskpayload": {"name": " actual task "}}]
        count += 1

        # Remote acknowledgment cannot be rolled back; local deletion still is
        # atomic, and a DB failure must never trigger another remote command.
        setup()
        before = state(False)
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE go_pending_nats_block (action_id bigint REFERENCES logs_pendingaction(id))")
            cursor.execute("INSERT INTO go_pending_nats_block VALUES (101)")
        try:
            with responder(subject, ["ok"]) as peer:
                assert go_request("DELETE", path)[0] == 500
            assert peer.messages == [payload]
            assert state(False) == before
            count += 1
        finally:
            with connection.cursor() as cursor:
                cursor.execute("DROP TABLE go_pending_nats_block")
        print(f"Pending NATS contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
