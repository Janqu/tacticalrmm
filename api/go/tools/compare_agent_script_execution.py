"""Synchronous stored-script contracts against Django and an isolated NATS peer."""
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
    from core.models import CoreSettings, GlobalKVStore
    from django.conf import settings
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog, DebugLog
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from scripts.models import Script, ScriptSnippet

    subject, other = "script-execution-agent-0031", "script-execution-agent-0032"
    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    token = hashlib.sha1(b"script-execution-callback").hexdigest()
    command = {"script": 31, "output": "wait", "args": [], "env_vars": [], "timeout": 10, "run_as_user": False}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema = cursor.fetchone()[0]
    assert schema.startswith("go_contract_")
    connect_options = connection.get_connection_params()
    connect_options["connect_timeout"] = 2
    count = 0

    def setup(scope="all", shell="powershell", override=False, code="Write-Output hello", debug_level="error"):
        Token.objects.all().delete(); Agent.objects.all().delete(); Script.objects.filter(pk=31).delete(); seed()
        DebugLog.objects.all().delete()
        CoreSettings.objects.update(agent_debug_level=debug_level)
        ScriptSnippet.objects.filter(name="Go execution snippet").delete()
        GlobalKVStore.objects.filter(name="Go execution value").delete()
        Client.objects.bulk_create([Client(id=31, name="Script Client"), Client(id=32, name="Other Client")])
        Site.objects.bulk_create([Site(id=31, name="Script Site", client_id=31), Site(id=32, name="Other Site", client_id=32)])
        Agent.objects.bulk_create([Agent(id=31, agent_id=subject, hostname="Script O'Brien", site_id=31), Agent(id=32, agent_id=other, hostname="Other", site_id=32)])
        Agent.objects.update(created_time=fixed, modified_time=fixed)
        Script.objects.bulk_create([Script(id=31, name="Script ü", shell=shell, script_body=code, run_as_user=override,
                                          args=["stored args ignored"], env_vars=["STORED=ignored"], supported_platforms=["linux"])])
        Script.objects.update(created_time=fixed, modified_time=fixed)
        ScriptSnippet.objects.create(name="Go execution snippet", code="snippet output")
        GlobalKVStore.objects.create(name="Go execution value", value="global value")
        User.objects.bulk_create([User(id=31, username="script-callback-agent", agent_id=31, date_joined=fixed)])
        User.objects.filter(pk=31).update(created_time=fixed, modified_time=fixed, date_joined=fixed)
        Token.objects.create(key=token, user_id=31, created=fixed)
        Token.objects.update(created=fixed)
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence('agents_agenthistory','id'),100,false)")
        Role.objects.filter(pk=1).update(can_run_scripts=scope != "denied")
        role = Role.objects.get(pk=1); role.can_view_clients.clear(); role.can_view_sites.clear()
        if scope == "client": role.can_view_clients.add(31)
        if scope == "site": role.can_view_sites.add(32)
        User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    def state(auth=True):
        history = list(AgentHistory.objects.order_by("id").values())
        for row in history:
            assert abs((row["time"] - datetime.now(timezone.utc)).total_seconds()) < 15
            row["time"] = "<now>"
        debug = list(DebugLog.objects.order_by("id").values("entry_time", "agent_id", "log_level", "log_type", "message"))
        for row in debug:
            assert abs((row["entry_time"] - datetime.now(timezone.utc)).total_seconds()) < 15
            row["entry_time"] = "<now>"
        return {"base": {key: value for key, value in snapshot().items() if auth or key != "tokens"}, "history": history, "debug": debug}

    def compare(data=None, reply=None, *, user=1, scope="all", target=subject, shell="powershell", override=False,
                code="Write-Output hello", callback=False, method="POST", debug_level="error"):
        nonlocal count
        data = copy.deepcopy(command if data is None else data)
        reply = {"stdout": "output ü", "stderr": "", "retcode": 0, "execution_time": 0.25} if reply is None else reply
        path = f"/agents/{target}/runscript/"
        setup(scope, shell, override, code, debug_level)
        calls = []
        callback_value = {"stdout": "early callback", "stderr": "", "retcode": 0, "execution_time": 0.1, "id": 100}

        def receive(payload, go=False):
            with psycopg.connect(**connect_options) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql.SQL("SELECT agent_id,type,script_id,results FROM {}.agents_agenthistory WHERE id=%s").format(sql.Identifier(schema)), [payload["id"]])
                    assert cursor.fetchone() == (31 if target == subject else 32, "script_run", 31, None), "history must commit before dispatch"
                    cursor.execute(sql.SQL("SELECT count(*) FROM {}.logs_auditlog WHERE action='execute_script'").format(sql.Identifier(schema)))
                    assert cursor.fetchone()[0] == 1, "audit must commit before dispatch"
                    if callback and not go:
                        cursor.execute(sql.SQL("UPDATE {}.agents_agenthistory SET script_results=%s::jsonb WHERE id=%s").format(sql.Identifier(schema)), [json.dumps(callback_value), payload["id"]])
            if callback and go:
                result = go_request("PATCH", f"/api/v3/{payload['id']}/{target}/histresult/", {"script_results": callback_value}, headers={"Authorization": "Token " + token})
                assert result == (200, "ok"), result
            return reply

        async def reference(*args, **kwargs):
            assert kwargs == {"timeout": int(data["timeout"]) + 3, "wait": True}, kwargs
            payload = copy.deepcopy(args[0]); calls.append(payload)
            assert payload["func"] == "runscript" and payload["timeout"] == int(data["timeout"]) + 3
            assert payload["run_as_user"] == (override or data["run_as_user"])
            assert payload["nushell_enable_config"] == settings.NUSHELL_ENABLE_CONFIG
            assert payload["deno_default_permissions"] == settings.DENO_DEFAULT_PERMISSIONS
            return receive(payload)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        with patch.object(Agent, "nats_cmd", new=AsyncMock(side_effect=reference)), patch("celery.app.task.Task.apply_async") as jobs:
            response = client.generic(method, path, json.dumps(data), content_type="application/json")
            expected = response.status_code, json.loads(response.content) if response.content else None
            jobs.assert_not_called()
        expected_state = state()
        setup(scope, shell, override, code, debug_level)
        with responder(target, [lambda payload: receive(payload, go=True)]) as peer:
            actual = go_request(method, path, data, user_id=user)
        assert actual == expected, (data, user, scope, method, expected, actual)
        assert peer.messages == calls, ("payload mismatch or retry", calls, peer.messages)
        assert state() == expected_state, ("script execution state differs", data, expected_state, state())
        count += 1

    try:
        for user, scope in ((1, "all"), (2, "all"), (2, "client"), (2, "site"), (2, "denied"), (3, "all"), (4, "all"), (5, "client"), (6, "all")):
            for target in (subject, other, "script-missing-agent-9999"):
                compare(user=user, scope=scope, target=target)
        for method in ("GET", "HEAD", "PUT", "PATCH", "DELETE"):
            compare(method=method)
        for shell in ("powershell", "cmd", "bash", "python", "nu", "deno"):
            compare({**command, "args": ["--name={{agent.hostname}}", "{{client.name}}", "{{global.Go execution value}}"],
                     "env_vars": ["HOST={{agent.hostname}}", "NO_EQUALS", "EMPTY={{agent.description}}", "RAW=a=b"]}, shell=shell,
                    code="{{Go execution snippet}}\n{{missing snippet}}")
        for changes in ({"timeout": 1}, {"timeout": 180}, {"timeout": "10"}, {"args": None, "env_vars": None}, {"run_as_user": True}):
            compare({**command, **changes})
        compare(override=True)
        compare(callback=True)
        for level in ("info", "warning", "error", "critical"):
            compare({**command, "args": ["{{agent.description}}", "{{agent.description}}"], "env_vars": ["EMPTY={{agent.description}}"]}, debug_level=level)
        for reply in ("", "text", ["line", 18446744073709551615], True, {"nested": [1, None]}):
            compare(reply=reply)
        compare({**command, "script": 999})

        # Intentional limits reject before audit, history, jobs or publication.
        invalid = [({"output": mode}, 501) for mode in ("email", "unknown-mode")]
        invalid += [({"run_on_server": True}, 501)]
        invalid += [(change, 400) for change in ({"timeout": 0}, {"timeout": 181}, {"timeout": True}, {"timeout": 1.5},
                    {"run_as_user": "false"}, {"args": [1]}, {"env_vars": "A=B"}, {"script": True},
                    {"args": ["{{agent.save}}"]}, {"args": ["{{global.missing execution key}}"]})]
        for changes, status in invalid:
            setup(); before = state(auth=False)
            with responder(subject, ["ok"]) as peer:
                result = go_request("POST", f"/agents/{subject}/runscript/", {**command, **changes})
            assert result[0] == status and not peer.messages, (changes, result)
            assert state(auth=False) == before
            count += 1

        # Once dispatched, failures retain committed audit/history and never retry.
        for reply, status in (("timeout", 400), ("natsdown", 400), (b"\xc1", 502), (None, 400)):
            setup()
            with responder(subject, [reply]) as peer:
                result = go_request("POST", f"/agents/{subject}/runscript/", {**command, "timeout": 1})
            assert result[0] == status and len(peer.messages) == 1, result
            assert AgentHistory.objects.filter(pk=100, type="script_run").exists()
            assert AuditLog.objects.filter(action="execute_script").count() == 1
            count += 1

        for table in ("agents_agenthistory", "logs_auditlog"):
            setup(); before = state(auth=False)
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("ALTER TABLE {} ADD CONSTRAINT script_execution_reject CHECK (false) NOT VALID").format(sql.Identifier(table)))
            try:
                with responder(subject, ["ok"]) as peer:
                    result = go_request("POST", f"/agents/{subject}/runscript/", command)
                assert result[0] == 500 and not peer.messages, result
                assert state(auth=False) == before, "audit and history must roll back together"
                count += 1
            finally:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT script_execution_reject").format(sql.Identifier(table)))
        print(f"Stored-script synchronous execution contracts: {count} comparisons passed")
        return count
    finally:
        Token.objects.all().delete(); Agent.objects.all().delete()
        Script.objects.filter(pk=31).delete()
        ScriptSnippet.objects.filter(name="Go execution snippet").delete()
        GlobalKVStore.objects.filter(name="Go execution value").delete()
        DebugLog.objects.all().delete()
        seed()
