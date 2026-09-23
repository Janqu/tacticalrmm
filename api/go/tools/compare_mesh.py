"""Mesh synchronization contract checks, called inside compare_django's test schema."""

import base64
import copy
import json
import re
import subprocess
import threading
import time
from contextlib import nullcontext
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from Crypto.Cipher import AES
from websockets.sync.server import serve
from websockets.exceptions import ConnectionClosed


class MeshServer:
    def __init__(self, state):
        self.state = copy.deepcopy(state)
        self.writes = []
        self.errors = []
        self.reject = False
        self.on_nodes = None

    def action(self, payload):
        action = payload["action"]
        response = {"action": action, "responseid": "meshctrl"}
        if action == "users":
            response.pop("responseid")
            return response | {"users": list(self.state["users"].values())}
        if action == "nodes":
            if self.on_nodes:
                self.on_nodes()
            return response | {"nodes": {"mesh//test": list(self.state["nodes"].values())}}
        payload = copy.deepcopy(payload)
        payload.pop("responseid", None)
        self.writes.append(payload)
        if self.reject:
            return response | {"result": "secret remote error"}
        if action == "adduser":
            assert re.fullmatch(r"[a-zA-Z0-9!@#$]{30}", payload["pass"])
            assert sum(c in "!@#$" for c in payload["pass"]) == 1
            assert re.fullmatch(r"\w+\.[a-zA-Z0-9]{6}@tacticalrmm-do-not-change-[a-zA-Z0-9]{5}\.local", payload["email"])
            user_id = "user//" + payload["username"]
            assert user_id not in self.state["users"], "duplicate account creation"
            self.state["users"][user_id] = {"_id": user_id}
        elif action == "deleteuser":
            user_id = payload["userid"]
            self.state["users"].pop(user_id, None)
            for node in self.state["nodes"].values():
                node.get("links", {}).pop(user_id, None)
        elif action == "edituser":
            self.state["users"][payload["id"]]["realname"] = payload["realname"]
        elif action == "adddeviceuser":
            links = self.state["nodes"][payload["nodeid"]].setdefault("links", {})
            if payload["remove"]:
                assert payload["rights"] == 0
                for user_id in payload["userids"]:
                    links.pop(user_id, None)
            else:
                assert payload["rights"] == 4088024
                for name in payload["usernames"]:
                    assert "user//" + name in self.state["users"]
                    links["user//" + name] = {"rights": payload["rights"]}
        else:
            raise AssertionError("unexpected action: " + action)
        return response | {"result": "ok"}

    def websocket(self, ws):
        try:
            # Verify Go authentication independently with Python's AES-GCM.
            uri = urlsplit(ws.request.path)
            assert uri.path == "/control.ashx"
            wire = base64.b64decode(parse_qs(uri.query)["auth"][0], altchars=b"@$")
            cipher = AES.new(bytes.fromhex("01" * 32), AES.MODE_GCM, nonce=wire[:12])
            message = json.loads(cipher.decrypt_and_verify(wire[28:], wire[12:28]))
            assert message["userid"] == "user//meshadmin" and message["domainid"] == ""
            assert abs(message["time"] - time.time()) < 30
            payload = json.loads(ws.recv())
            ws.send(json.dumps({"action": "event"}))
            ws.send(json.dumps(self.action(payload)))
        except ConnectionClosed:
            pass  # Expected when the cancellation/crash checks close a connection.
        except Exception as exc:
            self.errors.append(exc)


def normalized(writes):
    values = copy.deepcopy(writes)
    for item in values:
        if item["action"] == "adduser":
            item["pass"] = "validated generated password"
            item["email"] = "validated generated email"
        for field in ("userids", "usernames"):
            if field in item:
                item[field].sort()
    return sorted(json.dumps(item, sort_keys=True) for item in values)


def run(binary, env, seed, go_request):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, Site
    from core.models import CoreSettings
    from core.mesh_utils import MeshSync
    from core.tasks import sync_mesh_perms_task
    from django.db import connection

    def setup(case):
        Agent.objects.all().delete()
        seed()
        CoreSettings.objects.update(mesh_username="MeshAdmin", mesh_token="01" * 32,
                                    mesh_company_name="QDT", sync_mesh_with_trmm=case != "disabled")
        Client.objects.bulk_create([Client(id=2, name="Other client")])
        Site.objects.bulk_create([Site(id=2, name="Other site", client_id=2)])
        Role.objects.filter(pk=1).update(can_use_mesh=True)
        role = Role.objects.get(pk=1)
        role.can_view_sites.clear()
        if case == "site scope":
            role.can_view_clients.clear()
            role.can_view_sites.add(2)
        elif case == "unscoped":
            role.can_view_clients.clear()
        elif case == "combined scope":
            role.can_view_sites.add(2)
        User.objects.filter(pk=2).update(first_name="Alice", last_name="Reader")
        # Each exclusion would grant full access if the query filter were missing.
        User.objects.filter(pk__in=[4, 6]).update(is_superuser=True)
        User.objects.filter(pk=7).update(is_superuser=True, block_dashboard_login=True)
        Agent.objects.bulk_create([
            Agent(id=1, agent_id="mesh-test-1", hostname="one", site_id=1, mesh_node_id="ff"),
            Agent(id=2, agent_id="mesh-test-2", hostname="two", site_id=2, mesh_node_id="ee"),
        ])
        User.objects.bulk_create([User(id=8, username="agent", agent_id=1, is_superuser=True)])
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence('accounts_user', 'id'), (SELECT MAX(id) FROM accounts_user))")
        if case == "no agents":
            Agent.objects.update(mesh_node_id=None)
        if case == "invalid node":
            Agent.objects.filter(pk=1).update(mesh_node_id="invalid")
        users = {key: {"_id": key, "realname": "Old name"} for key in (
            "user//admin___1", "user//reader___2", "user//removed___90", "user//manual")}
        nodes = {
            "node//$w==": {"_id": "node//$w==", "links": {"user//admin___1": {"rights": 4088024}, "user//manual": {"rights": 8}, "user//removed___90": {"rights": 4088024}}},
            "node//7g==": {"_id": "node//7g==", "links": {"user//reader___2": {"rights": 4088024}}},
        }
        return {"users": users, "nodes": nodes}

    def invoke(fake, *flags, during=None):
        with serve(fake.websocket, "127.0.0.1", 0) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.socket.getsockname()[1]
            process = subprocess.Popen([str(binary), *flags], env=env | {
                "MESH_WS_URL": f"ws://127.0.0.1:{port}", "TRMM_DISABLE_MESH_SYNC_TASK": "false",
            }, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                if during:
                    during(process)
                stdout, stderr = process.communicate(timeout=20)
                result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                server.shutdown()
                thread.join(timeout=5)
        assert not fake.errors, fake.errors
        return result

    for case in ("client scope", "site scope", "combined scope", "unscoped", "disabled", "no agents"):
        state = setup(case)
        reference = MeshServer(state)
        with patch("core.tasks.redis_lock", return_value=nullcontext(True)), \
             patch("core.tasks.get_mesh_ws_url", return_value="unused"), \
             patch.object(MeshSync, "mesh_action", lambda self, *, payload, wait=True: reference.action(payload)):
            sync_mesh_perms_task.run()
        assert reference.writes, "reference did not execute"
        actual = MeshServer(state)
        dry = invoke(actual, "--dry-run")
        assert dry.returncode == 0, dry.stderr
        assert json.loads(dry.stdout) and actual.writes == [] and actual.state == state
        result = invoke(actual)
        assert result.returncode == 0, result.stderr
        assert normalized(actual.writes) == normalized(reference.writes), (case, normalized(actual.writes), normalized(reference.writes))
        assert actual.state == reference.state, case
        actual.writes.clear()
        result = invoke(actual)
        assert result.returncode == 0 and not actual.writes, (case, result.stderr, actual.writes)
        print("MATCH MeshCentral:", case, "(dry run, apply, repeat)")

    fake = MeshServer(setup("invalid node"))
    result = invoke(fake)
    assert result.returncode != 0 and not fake.writes
    fake = MeshServer(setup("client scope"))
    fake.reject = True
    result = invoke(fake)
    assert result.returncode != 0 and len(fake.writes) == 1
    assert "secret remote error" not in result.stderr
    fake.reject = False
    fake.writes.clear()
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_lock(%s)", [0x54524D4D4D455348])
        try:
            result = invoke(fake)
            assert result.returncode != 0 and "already running" in result.stderr
            assert not fake.writes
        finally:
            cursor.execute("SELECT pg_advisory_unlock(%s)", [0x54524D4D4D455348])
    assert invoke(fake).returncode == 0
    print("PASS MeshCentral: invalid inventory, mutation failure, advisory lock/release")

    def job_state():
        with connection.cursor() as cursor:
            cursor.execute("SELECT generation, completed_generation, attempts FROM go_mesh_sync WHERE id = 1")
            return cursor.fetchone()

    def request_sync(**fields):
        status, body = go_request("PUT", "/accounts/roles/1/", {"name": "Read only", **fields})
        assert status == 200, (status, body)

    fake = MeshServer(setup("client scope"))
    request_sync()
    fake.reject = True
    result = invoke(fake, "--worker", "--once")
    assert result.returncode != 0 and job_state() == (1, 0, 1)
    fake.writes.clear()
    assert invoke(fake, "--worker", "--once").returncode == 0 and not fake.writes
    with connection.cursor() as cursor:
        cursor.execute("UPDATE go_mesh_sync SET next_attempt_at = CURRENT_TIMESTAMP - INTERVAL '1 second'")
    fake.reject = False
    assert invoke(fake, "--worker", "--once").returncode == 0 and job_state()[:2] == (1, 1)
    print("PASS Mesh worker: API dispatch, persisted retry delay, restart recovery")

    for crash in (False, True):
        fake = MeshServer(setup("client scope"))
        request_sync()
        entered, release = threading.Event(), threading.Event()

        def pause_at_nodes():
            entered.set()
            assert release.wait(timeout=10), "test did not release worker"

        fake.on_nodes = pause_at_nodes

        def during(process):
            try:
                assert entered.wait(timeout=10), "worker did not reach node inventory"
                if crash:
                    process.kill()
                    process.wait(timeout=5)
                else:
                    request_sync(can_use_mesh=False)
            finally:
                release.set()

        result = invoke(fake, "--worker", "--once", during=during)
        fake.on_nodes = None
        if crash:
            assert result.returncode != 0 and job_state()[:2] == (1, 0)
        else:
            assert result.returncode == 0 and job_state()[:2] == (2, 1)
            assert "user//reader___2" in fake.state["users"]
        assert invoke(fake, "--worker", "--once").returncode == 0
        generation, completed, _ = job_state()
        assert generation == completed
        if not crash:
            assert "user//reader___2" not in fake.state["users"]
        print("PASS Mesh worker:", "process crash recovery" if crash else "change during reconciliation remains pending")

    fake = MeshServer(setup("client scope"))
    # Both requests coalesce, but retain monotonically increasing generations.
    request_sync()
    request_sync()
    assert job_state()[:2] == (2, 0)
    assert invoke(fake, "--worker", "--once").returncode == 0 and job_state()[:2] == (2, 2)
    fake.writes.clear()
    assert invoke(fake, "--worker", "--once").returncode == 0 and not fake.writes
    print("PASS Mesh worker: coalescing and completed-generation no-op")

    fake = MeshServer(setup("client scope"))
    request_sync()

    def check_daemon(process):
        for expected in (1, 2):
            deadline = time.monotonic() + 15
            while job_state()[:2] != (expected, expected):
                assert process.poll() is None and time.monotonic() < deadline, "worker stopped making progress"
                time.sleep(0.05)
            if expected == 1:
                request_sync(can_use_mesh=False)
        process.terminate()

    result = invoke(fake, "--worker", during=check_daemon)
    assert result.returncode == 0, result.stderr
    assert "user//reader___2" not in fake.state["users"]
    print("PASS Mesh worker: continuous polling and graceful shutdown")

    fake = MeshServer(setup("client scope"))
    assert go_request("PUT", "/accounts/2/users/", {"username": "renamed", "first_name": "Renamed"})[0] == 200
    assert invoke(fake, "--worker", "--once").returncode == 0
    assert "user//reader___2" not in fake.state["users"]
    assert fake.state["users"]["user//renamed___2"]["realname"] == "Renamed Reader - QDT"
    assert "user//renamed___2" in fake.state["nodes"]["node//$w=="]["links"]
    assert go_request("PUT", "/accounts/2/users/", {"is_active": False})[0] == 200
    assert invoke(fake, "--worker", "--once").returncode == 0
    assert "user//renamed___2" not in fake.state["users"]
    assert job_state()[:2] == (2, 2)
    print("PASS Mesh worker: user rename and deactivation propagate to remote accounts")

    fake = MeshServer(setup("client scope"))
    assert go_request("POST", "/accounts/users/", {
        "username": "new-mesh-user", "email": "", "password": "secret", "first_name": "New", "role": 1,
    })[0] == 200
    new_user = User.objects.get(username="new-mesh-user")
    assert invoke(fake, "--worker", "--once").returncode == 0
    assert fake.state["users"][new_user.mesh_user_id]["realname"] == "New - QDT"
    assert new_user.mesh_user_id in fake.state["nodes"]["node//$w=="]["links"]
    assert new_user.mesh_user_id not in fake.state["nodes"]["node//7g=="]["links"]
    assert job_state()[:2] == (1, 1)
    print("PASS Mesh worker: API user creation provisions a scoped remote account")
    assert go_request("DELETE", f"/accounts/{new_user.pk}/users/")[0] == 200
    assert invoke(fake, "--worker", "--once").returncode == 0
    assert new_user.mesh_user_id not in fake.state["users"]
    assert all(new_user.mesh_user_id not in node.get("links", {}) for node in fake.state["nodes"].values())
    assert job_state()[:2] == (2, 2)
    print("PASS Mesh worker: API user deletion removes remote account and permissions")
