"""Agents read contracts (list, notes, history) against actual Django views.

Run from compare_django.py. Django's checks summary comes from its cache and the
Go API reads the same value from Redis (DJANGO_CACHE_REDIS_URL), so the harness
seeds both when that variable is set.
"""

import hashlib
import json
import pickle
import re
from datetime import datetime, timezone

A1 = "agent-reads-one-0123456789"
A2 = "agent-reads-two-0123456789"
A3 = "agent-reads-three-012345678"
MISSING = "agent-reads-missing-0123456"
WINDOWS_WMI = {
    "cpu": [[{"Name": "Xeon"}, {"NumberOfCores": 4, "NumberOfLogicalProcessors": 8}]],
    "graphics": [[{"Caption": "Microsoft Remote Display Adapter"}], [{"Caption": "NVIDIA"}]],
    "network_config": [[{"IPAddress": ["10.0.0.5", "fe80::1"]}], [{"IPAddress": ["192.168.1.2"]}]],
    "comp_sys": [[{"Model": "To be filled by O.E.M."}, {"SystemFamily": "ThinkPad"}]],
    "comp_sys_prod": [[{"Vendor": "LENOVO"}]],
    "base_board": [[{"Manufacturer": "Lenovo"}, {"Product": "20XW"}]],
    "disk": [[{"InterfaceType": "SCSI"}, {"Caption": "Disk A"}, {"Size": "1000204886016"}],
             [{"InterfaceType": "USB"}, {"Caption": "Stick"}, {"Size": 1}]],
    "bios": [[{"SerialNumber": "SN1"}]],
}
LINUX_WMI = {"cpus": ["EPYC"], "gpus": ["GPU 1", "GPU 2"], "local_ips": ["10.1.1.1"],
             "make_model": "Dell R740", "disks": ["nvme0 1TB"], "serialnumber": "SER-9"}
ISO_HOST = re.compile(r"^https?://[^/]+")


def normalize(value):
    if isinstance(value, dict):
        return {k: (sorted(v, key=lambda x: x["id"]) if k == "custom_fields" else normalize(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        return ISO_HOST.sub("", value)
    return value


def response_body(value):
    value = normalize(value)
    if isinstance(value, list):
        # These unpaginated Django querysets have no ordering. Keep paginated
        # results untouched so history ordering is still verified.
        return sorted(value, key=lambda row: str(row.get("id", row.get("pk", row.get("agent_id")))))
    return value


def run(seed, go_request, snapshot, redis_url=None):
    from accounts.models import Role, User
    from agents.models import Agent, AgentCustomField, AgentHistory, Note
    from alerts.models import AlertTemplate, MatrixChannel
    from automation.models import Policy
    from clients.models import Client, Site
    from core.models import CustomField
    from django.core.cache import cache
    from django.db import connection
    from logs.models import PendingAction
    from rest_framework.test import APIClient
    from scripts.models import Script
    from winupdate.models import WinUpdate

    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    future = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def cleanup():
        Agent.objects.all().delete()
        AlertTemplate.objects.filter(name__startswith="go-agent-reads-").delete()
        Policy.objects.filter(name__startswith="go-agent-reads-").delete()
        MatrixChannel.objects.filter(name__startswith="go-agent-reads-").delete()
        Script.objects.filter(name__startswith="go-agent-reads-").delete()
        CustomField.objects.filter(name__startswith="go-agent-reads-").delete()

    def setup(scope):
        cleanup()
        seed()
        Client.objects.bulk_create([Client(id=21, name="Alpha"), Client(id=22, name="Zulu")])
        Site.objects.bulk_create([Site(id=21, name="A site", client_id=21),
                                  Site(id=22, name="Z site", client_id=21),
                                  Site(id=23, name="Empty", client_id=22)])
        AlertTemplate.objects.bulk_create([AlertTemplate(
            id=21, name="go-agent-reads-template", agent_always_email=True,
            agent_always_text=None, agent_always_alert=False)])
        Policy.objects.bulk_create([Policy(id=21, name="go-agent-reads-policy")])
        channels = MatrixChannel.objects.bulk_create([
            MatrixChannel(id=21, name="go-agent-reads-zed", homeserver="https://m.example", room_id="!a", token_key="k", enabled=True),
            MatrixChannel(id=22, name="go-agent-reads-alpha", homeserver="https://m.example", room_id="!b", token_key="k", enabled=True),
            MatrixChannel(id=23, name="go-agent-reads-off", homeserver="https://m.example", room_id="!c", token_key="k", enabled=False),
        ])
        Agent.objects.bulk_create([
            Agent(id=21, agent_id=A1, hostname="one", site_id=21, wmi_detail=WINDOWS_WMI,
                  last_seen=future, logged_in_username="None", last_logged_in_user="jo",
                  alert_template_id=21, policy_id=21, boot_time=1700000000.5,
                  description="first", public_ip="1.2.3.4", goarch="amd64", needs_reboot=True),
            Agent(id=22, agent_id=A2, hostname="two", site_id=22, plat="linux", wmi_detail=LINUX_WMI,
                  last_seen=fixed, logged_in_username="root", monitoring_type="workstation",
                  maintenance_mode=True),
            Agent(id=23, agent_id=A3, hostname="three", site_id=23, wmi_detail=None),
        ])
        Agent.objects.get(pk=21).matrix_channels.add(channels[0], channels[2])
        AlertTemplate.objects.get(pk=21).matrix_channels.add(channels[1])
        fields = CustomField.objects.bulk_create([
            CustomField(id=21 + i, name="go-agent-reads-" + kind, model="agent", type=kind)
            for i, kind in enumerate(["text", "checkbox", "multiple"])])
        AgentCustomField.objects.bulk_create([
            AgentCustomField(id=21, agent_id=21, field=fields[0], string_value="Grüße"),
            AgentCustomField(id=22, agent_id=21, field=fields[1], bool_value=True),
            AgentCustomField(id=23, agent_id=21, field=fields[2], multiple_value=["a", None, "b"]),
            AgentCustomField(id=24, agent_id=22, field=fields[0], string_value=None),
        ])
        WinUpdate.objects.bulk_create([WinUpdate(agent_id=21, action="approve", installed=False)])
        PendingAction.objects.bulk_create([PendingAction(agent_id=21, status="pending"),
                                           PendingAction(agent_id=21, status="completed")])
        Script.objects.bulk_create([Script(id=21, name="go-agent-reads-script", shell="powershell", script_body="x")])
        Note.objects.bulk_create([Note(id=21, agent_id=21, user_id=1, note="Grüße"),
                                  Note(id=22, agent_id=22, user_id=None, note=None),
                                  Note(id=23, agent_id=23, user_id=2, note="site 23")])
        Note.objects.update(entry_time=fixed)
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence('agents_note', 'id'), 1000)")
        AgentHistory.objects.bulk_create([
            AgentHistory(id=21 + i, agent_id=[21, 22, 23][i % 3], type=["cmd_run", "script_run", "task_run"][i % 3],
                         command=None if i == 4 else f"cmd {i}", username=["b", "a", "c"][i % 3],
                         results=None if i == 2 else "ok", script_id=21 if i % 3 == 1 else None,
                         script_results={"stdout": "x"} if i % 3 == 1 else None)
            for i in range(7)])
        AgentHistory.objects.update(time=fixed)
        AgentHistory.objects.filter(id__in=[23, 24]).update(time=future)
        Role.objects.filter(pk=1).update(can_list_agents=True, can_list_notes=True, can_list_agent_history=True)
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client", "combined"}:
            role.can_view_clients.add(22)
        if scope in {"site", "combined"}:
            role.can_view_sites.add(21)
        if scope == "denied":
            Role.objects.filter(pk=1).update(can_list_agents=False, can_list_notes=False, can_list_agent_history=False)
        if scope == "head":
            Role.objects.filter(pk=1).update(can_edit_agent=True, can_manage_notes=True, can_list_agents=False,
                                            can_list_notes=False)
            role.can_view_clients.add(22)
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
        cache.clear()
        if redis_url:  # Go reads the same summary from Redis, Django from its cache
            import redis
            client = redis.Redis.from_url(redis_url)
            client.delete(*[f":1:agent_checks_data_{i}" for i in (21, 22, 23)])
            summary = {"total": 3, "passing": 1, "failing": 1, "warning": 1, "info": 0, "has_failing_checks": True}
            cache.set("agent_checks_data_21", summary)
            client.set(":1:agent_checks_data_21", pickle.dumps(summary, protocol=pickle.HIGHEST_PROTOCOL))

    paths = ["/agents/", "/agents/?detail=false", "/agents/?detail=nope", "/agents/?monitoring_type=server",
             "/agents/?monitoring_type=bogus", "/agents/?site=21", "/agents/?client=21&detail=false",
             "/agents/?client=22", "/agents/?site=abc", "/agents/notes/", "/agents/notes/21/",
             "/agents/notes/22/", "/agents/notes/999/", "/agents/history/", "/agents/v2/history/",
             "/agents/v2/history/?page_size=2&page=2", "/agents/v2/history/?ordering=username&page_size=3",
             "/agents/v2/history/?ordering=-command&page_size=4&page=2", "/agents/v2/history/?page=99",
             "/agents/v2/history/?page=last&page_size=2", "/agents/v2/history/?page=x",
             "/agents/v2/history/?ordering=--time", "/agents/v2/history/?ordering=bogus&page_size=0"]
    for agent in (A1, A2, A3, MISSING):
        paths += [f"/agents/{agent}/history/", f"/agents/v2/{agent}/history/", f"/agents/{agent}/notes/"]

    def decode(content):
        try:
            return json.loads(content) if content else None
        except ValueError:
            return None

    count = 0
    try:
        for scope, user_id in [("unscoped", 1), ("unscoped", 5), ("unscoped", 2), ("client", 2), ("site", 2),
                               ("combined", 2), ("denied", 2), ("unscoped", 3), ("installer", 6), ("head", 2)]:
            for path in paths:
                method = "HEAD" if scope == "head" else "GET"
                setup(scope)
                client = APIClient(raise_request_exception=False)
                token = hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest()
                client.credentials(HTTP_AUTHORIZATION="Token " + token)
                response = client.generic(method, path)
                expected = (response.status_code, decode(response.content))
                expected_state = snapshot()
                setup(scope)
                actual = go_request(method, path, user_id=user_id)
                if expected[0] >= 500 or (expected[0] == 404 and expected[1] is None):
                    assert actual[0] == expected[0], (scope, user_id, method, path, expected, actual)
                else:
                    assert (actual[0], response_body(actual[1])) == (expected[0], response_body(expected[1])), (
                        scope, user_id, method, path, expected, actual)
                assert snapshot() == expected_state, (scope, path, "unexpected database change")
                count += 1
        print(f"Agent read contracts: {count} comparisons passed")

        def note_state():
            rows = list(Note.objects.order_by("id").values())
            for row in rows:
                if row["id"] > 1000:
                    assert abs((datetime.now(timezone.utc) - row["entry_time"]).total_seconds()) < 30
                    row["entry_time"] = "new"
            return rows

        writes = [
            ("POST", "/agents/notes/", {"agent_id": A1, "note": "  Grüße  ", "user": 2, "agent": 23}),
            ("POST", "/agents/notes/", {"agent_id": A2, "note": "other site"}),
            ("POST", "/agents/notes/", {"agent_id": MISSING, "note": "missing"}),
            ("POST", "/agents/notes/", {"agent_id": A1}),
            *[("POST", "/agents/notes/", {"agent_id": A1, "note": value})
              for value in (None, "", 123, False, [], "bad\x00note")],
            ("PUT", "/agents/notes/21/", {"note": "  changed  "}),
            ("PUT", "/agents/notes/21/", {"note": None, "user": None}),
            ("PUT", "/agents/notes/21/", {"user": ""}),
            ("PUT", "/agents/notes/21/", {"agent": "", "note": "must not change"}),
            ("PUT", "/agents/notes/21/", {"note": "", "user": "2", "agent": "21"}),
            ("PUT", "/agents/notes/21/", {"pk": 99, "entry_time": "2000-01-01", "agent_id": A2}),
            ("PUT", "/agents/notes/21/", {"note": [], "agent": None, "user": 999}),
            ("PUT", "/agents/notes/21/", {"agent": 999, "user": False}),
            ("PUT", "/agents/notes/21/", {"agent": 22}),
            ("PUT", "/agents/notes/22/", {"note": "out of scope"}),
            ("PUT", "/agents/notes/999/", {"note": "missing"}),
            ("DELETE", "/agents/notes/21/", None),
            ("DELETE", "/agents/notes/22/", None),
            ("DELETE", "/agents/notes/999/", None),
        ]
        write_count = 0
        for scope, user_id in [("unscoped", 1), ("unscoped", 2), ("site", 2),
                               ("denied", 2), ("unscoped", 3), ("installer", 6)]:
            for method, path, body in writes:
                def prepare():
                    setup(scope)
                    Role.objects.filter(pk=1).update(can_manage_notes=scope != "denied")
                prepare()
                client = APIClient(raise_request_exception=False)
                token = hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest()
                client.credentials(HTTP_AUTHORIZATION="Token " + token)
                before_notes = note_state()
                response = client.generic(method, path, data=json.dumps(body) if body is not None else "",
                                          content_type="application/json")
                expected = (response.status_code, decode(response.content))
                expected_notes, expected_state = note_state(), snapshot()
                prepare()
                actual = go_request(method, path, body, user_id=user_id)
                if scope == "site" and body == {"agent": 22}:
                    assert expected[0] == 200 and actual[0] == 403, (expected, actual)
                    assert note_state() == before_notes
                else:
                    assert actual[:2] == expected, (scope, user_id, method, path, body, expected, actual)
                    assert note_state() == expected_notes, (scope, method, path, expected_notes, note_state())
                assert snapshot() == expected_state, (scope, method, path, "unexpected audit/user change")
                write_count += 1
        print(f"Agent note write contracts: {write_count} comparisons passed")
        setup("unscoped")
        before_notes = note_state()
        for body in ({}, {"agent_id": None}, {"agent_id": []}, {"agent_id": ""}):
            assert go_request("POST", "/agents/notes/", body, user_id=1)[0] == 400
            assert note_state() == before_notes
        count += write_count
        return count
    finally:
        cleanup()
        seed()
