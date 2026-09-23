"""Raw-command and history callback contracts; isolated DB and loopback broker only."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from nats_fixture import responder


def run(seed, go_request, snapshot):
    import psycopg
    from psycopg import sql
    from accounts.models import Role, User
    from agents.models import Agent, AgentHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient

    subject = "rawcmd-contract-agent-0031"
    other = "rawcmd-contract-agent-0032"
    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    tokens = {pk: hashlib.sha1(f"rawcmd-agent-user-{pk}".encode()).hexdigest() for pk in (31, 32, 33, 34)}
    good = {"Authorization": "Token " + tokens[31]}
    command = {"cmd": "echo Grüße\nwhoami", "shell": "cmd", "timeout": 10, "run_as_user": False}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema = cursor.fetchone()[0]
    assert schema.startswith("go_contract_"), "only disposable contract schemas are allowed"
    connect_options = connection.get_connection_params()
    connect_options["connect_timeout"] = 2
    count = 0

    def setup(scope="all", history_type="cmd_run"):
        Token.objects.all().delete(); Agent.objects.all().delete(); seed()
        Client.objects.bulk_create([Client(id=31, name="A"), Client(id=32, name="B")])
        Site.objects.bulk_create([Site(id=31, name="A", client_id=31), Site(id=32, name="B", client_id=32)])
        Agent.objects.bulk_create([
            Agent(id=31, agent_id=subject, hostname="Command ü", site_id=31),
            Agent(id=32, agent_id=other, hostname="Other", site_id=32),
        ])
        Agent.objects.update(created_time=fixed, modified_time=fixed)
        User.objects.bulk_create([User(id=pk, username=f"rawcmd-user-{pk}", agent_id=pk if pk in (31, 32) else None, is_active=pk != 33, date_joined=fixed) for pk in tokens])
        User.objects.filter(pk__in=tokens).update(created_time=fixed, modified_time=fixed, date_joined=fixed)
        Token.objects.bulk_create([Token(key=token, user_id=pk, created=fixed) for pk, token in tokens.items()])
        Token.objects.update(created=fixed)
        AgentHistory.objects.bulk_create([
            AgentHistory(id=31, agent_id=31, type=history_type, command="existing", results="before"),
            AgentHistory(id=32, agent_id=32, type="cmd_run", command="other", results="untouched"),
        ])
        AgentHistory.objects.update(time=fixed)
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence('agents_agenthistory','id'),100,false)")
        Role.objects.filter(pk=1).update(can_send_cmd=scope != "denied")
        role = Role.objects.get(pk=1); role.can_view_clients.clear(); role.can_view_sites.clear()
        if scope == "client": role.can_view_clients.add(31)
        if scope == "site": role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state(auth=True):
        histories = list(AgentHistory.objects.order_by("id").values())
        for row in histories:
            if row["id"] >= 100:
                assert abs((row["time"] - datetime.now(timezone.utc)).total_seconds()) < 10
                row["time"] = "<now>"
        return {
            "base": {key: value for key, value in snapshot().items() if auth or key != "tokens"},
            "history": histories,
            "agents": list(Agent.objects.order_by("id").values()),
            "agent_tokens": list(Token.objects.order_by("key").values()),
        }

    def client_for(headers):
        client = APIClient()
        client.credentials(**{"HTTP_" + key.upper().replace("-", "_"): value for key, value in headers.items()})
        return client

    def reference_request(method, path, data, headers):
        response = client_for(headers).generic(method, path, json.dumps(data), content_type="application/json")
        return response.status_code, json.loads(response.content) if response.content else None

    def committed(payload, target, data, username):
        with psycopg.connect(**connect_options) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql.SQL("SELECT agent_id,type,command,username,results FROM {}.agents_agenthistory WHERE id=%s").format(sql.Identifier(schema)), [payload["id"]])
                row = cursor.fetchone()
        assert row == (31 if target == subject else 32, "cmd_run", data["cmd"], username[:50], None), ("history not committed before command", row)
        shell = data.get("custom_shell") if data["shell"] == "custom" and data.get("custom_shell") else data["shell"]
        assert payload == {"func": "rawcmd", "timeout": int(data["timeout"]), "payload": {"command": data["cmd"], "shell": shell}, "run_as_user": data["run_as_user"], "id": 100}, payload

    def compare(data=None, reply="output ü\n", *, user=1, scope="all", target=subject, callback=False):
        nonlocal count
        data = copy.deepcopy(command if data is None else data)
        path = f"/agents/{target}/cmd/"
        setup(scope)
        username = User.objects.get(pk=user).username
        calls = []
        def receive(payload, go=False):
            committed(payload, target, data, username)
            if callback:
                body = {"results": "  callback result ü\n  "}
                callback_path = f"/api/v3/{payload['id']}/{target}/histresult/"
                headers = {"Authorization": "Token " + tokens[31 if target == subject else 32]}
                if go:
                    result = go_request("PATCH", callback_path, body, headers=headers)
                    assert result == (200, "ok"), result
                else:
                    # The reference nats mock executes in an async context; use a
                    # separate connection to model the independently delivered callback.
                    # The callback serializer itself is compared below using APIClient.
                    with psycopg.connect(**connect_options) as conn:
                        with conn.cursor() as cursor:
                            cursor.execute(sql.SQL("UPDATE {}.agents_agenthistory SET results=%s WHERE id=%s").format(sql.Identifier(schema)), [body["results"].strip(), payload["id"]])
            return reply
        async def reference(*args, **kwargs):
            assert kwargs == {"timeout": int(data["timeout"]) + 2}, kwargs
            payload = copy.deepcopy(args[0]); calls.append(payload)
            return receive(payload)
        headers = {"Authorization": "Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest()}
        with patch.object(Agent, "nats_cmd", new=AsyncMock(side_effect=reference)), patch("celery.app.task.Task.apply_async") as jobs:
            expected = reference_request("POST", path, data, headers)
            jobs.assert_not_called()
        expected_state = state()
        setup(scope)
        with responder(target, [lambda payload: receive(payload, go=True)]) as peer:
            actual = go_request("POST", path, data, user_id=user)
        assert actual == expected, (data, reply, user, scope, target, expected, actual)
        assert peer.messages == calls, ("command mismatch/retry", calls, peer.messages)
        assert state() == expected_state, ("rawcmd state mismatch", data, reply, user, scope, expected_state, state())
        if callback and calls:
            assert AgentHistory.objects.get(pk=100).results == "callback result ü"
        count += 1

    def callback_compare(body, *, headers=None, target=subject, pk=31, method="PATCH"):
        nonlocal count
        headers = good if headers is None else headers
        path = f"/api/v3/{pk}/{target}/histresult/"
        setup()
        with patch.object(Agent, "nats_cmd") as commands, patch("celery.app.task.Task.apply_async") as jobs:
            expected = reference_request(method, path, body, headers)
        commands.assert_not_called(); jobs.assert_not_called()
        expected_state = state()
        setup()
        actual = go_request(method, path, body, headers=headers)
        if headers == {"Authorization": "Token " + tokens[34]}:
            # This active token has no agent. Go validates the token-agent-URL
            # binding before the history lookup; Django only filters history.
            assert expected == (404, {"detail": "No AgentHistory matches the given query."}), expected
            expected = (404, {"detail": "No Agent matches the given query."})
        assert actual == expected, (method, body, pk, target, expected, actual)
        assert state() == expected_state, ("callback state mismatch", body, expected_state, state())
        count += 1

    try:
        for user, scope in ((1, "all"), (2, "all"), (2, "client"), (2, "site"), (2, "denied"), (3, "all"), (4, "all"), (5, "client"), (6, "all")):
            for target in (subject, other, "rawcmd-missing-agent-9999"):
                compare(user=user, scope=scope, target=target)
        for changes in ({"cmd": ""}, {"cmd": "  spaced  "}, {"timeout": "10"}, {"timeout": 1}, {"timeout": 180}, {"shell": "powershell", "run_as_user": True}, {"shell": "custom", "custom_shell": "C:\\Tools\\shell.exe"}, {"shell": "custom", "custom_shell": ""}):
            compare({**command, **changes})
        for reply in ("timeout", "", "busy", {"stdout": "ok"}, ["line", 18446744073709551615], True):
            compare(reply=reply)
        compare(callback=True)

        # Validate before history creation, publication or auditing.
        for changes in ({"timeout": 0}, {"timeout": 181}, {"timeout": True}, {"timeout": 1.5}, {"timeout": "bad"}, {"run_as_user": "false"}, {"cmd": None}, {"shell": ""}, {"shell": "custom", "custom_shell": 42}):
            setup(); before = state(auth=False)
            with responder(subject, ["ok"]) as peer:
                result = go_request("POST", f"/agents/{subject}/cmd/", {**command, **changes})
            assert result[0] == 400, (changes, result)
            assert not peer.messages and state(auth=False) == before
            count += 1
        # natsdown is a source false-success; invalid bytes must not be audited either.
        for reply, status in (("natsdown", 400), (b"\xc1", 502)):
            setup()
            with responder(subject, [reply]) as peer:
                result = go_request("POST", f"/agents/{subject}/cmd/", command)
            assert result[0] == status, result
            assert len(peer.messages) == 1 and AgentHistory.objects.filter(pk=100).exists()
            assert not AuditLog.objects.exists()
            count += 1

        setup(); before = state(auth=False)
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE agents_agenthistory ADD CONSTRAINT rawcmd_insert_reject CHECK (id < 100) NOT VALID")
        try:
            with responder(subject, ["ok"]) as peer:
                result = go_request("POST", f"/agents/{subject}/cmd/", command)
            assert result[0] == 500 and not peer.messages, result
            assert state(auth=False) == before
            count += 1
        finally:
            with connection.cursor() as cursor: cursor.execute("ALTER TABLE agents_agenthistory DROP CONSTRAINT rawcmd_insert_reject")

        # A database failure after execution cannot undo it and must not resend it.
        setup()
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE logs_auditlog ADD CONSTRAINT rawcmd_audit_reject CHECK (false) NOT VALID")
        try:
            with responder(subject, ["ok"]) as peer:
                result = go_request("POST", f"/agents/{subject}/cmd/", command)
            assert result[0] == 500 and len(peer.messages) == 1, result
            assert AgentHistory.objects.filter(pk=100).exists() and not AuditLog.objects.exists()
            count += 1
        finally:
            with connection.cursor() as cursor: cursor.execute("ALTER TABLE logs_auditlog DROP CONSTRAINT rawcmd_audit_reject")

        for body in ({}, {"results": "  trimmed ü\n"}, {"results": ""}, {"results": None}, {"results": 12}, {"results": False}, {"results": []}, {"results": "bad\x00value"}):
            callback_compare(body)
        for headers in ({}, {"Authorization": "Token invalid"}, {"Authorization": "Token " + tokens[33]}, {"Authorization": "Token " + tokens[34]}, {"Authorization": "Token " + hashlib.sha256(b"contract-user-1").hexdigest()}):
            callback_compare({"results": "new"}, headers=headers)
        for pk in (0, 32, 999): callback_compare({"results": "new"}, pk=pk)
        for method in ("GET", "HEAD", "POST", "DELETE"):
            callback_compare({}, method=method)
        # URL binding, unsupported side effects and assignment attempts are explicit safety limits.
        for body, target, kind, status in (({"results": "new"}, other, "cmd_run", 404), ({"results": "new"}, subject, "task_run", 501), ({"agent": 32, "results": "new"}, subject, "cmd_run", 400), ({"type": "script_run"}, subject, "cmd_run", 400), ({"script_results": {}}, subject, "cmd_run", 400)):
            setup(history_type=kind); before = state()
            result = go_request("PATCH", f"/api/v3/31/{target}/histresult/", body, headers=good)
            assert result[0] == status, (body, target, kind, result)
            assert state() == before
            count += 1
        setup()
        path = f"/api/v3/31/{subject}/histresult/"
        assert go_request("PATCH", path, {"results": "once"}, headers=good) == (200, "ok")
        before = state()
        assert go_request("PATCH", path, {"results": "once"}, headers=good) == (200, "ok")
        assert state() == before
        count += 1
        setup(); before = state()
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE agents_agenthistory ADD CONSTRAINT rawcmd_callback_reject CHECK (results IS DISTINCT FROM 'reject') NOT VALID")
        try:
            result = go_request("PATCH", path, {"results": "reject"}, headers=good)
            assert result[0] == 500 and state() == before, result
            count += 1
        finally:
            with connection.cursor() as cursor: cursor.execute("ALTER TABLE agents_agenthistory DROP CONSTRAINT rawcmd_callback_reject")
        print(f"Agent rawcmd/history callback contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete(); Agent.objects.all().delete(); seed()
