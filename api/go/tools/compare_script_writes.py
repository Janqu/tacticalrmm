"""Script mutations: serializer, audit, cascade and policy cache parity."""
import hashlib
import json
from contextlib import nullcontext
from datetime import datetime
from unittest.mock import patch


def run(seed, go_request, snapshot, redis_url=None):
    from accounts.models import Role
    from agents.models import Agent, AgentHistory
    from alerts.models import Alert, AlertTemplate, MatrixChannel, MatrixDelivery
    from automation.models import Policy
    from autotasks.models import AutomatedTask
    from checks.models import Check, CheckResult, CheckHistory
    from clients.models import Client, Site
    from django.core.cache import cache
    from django.db import connection
    from logs.models import AuditLog
    from rest_framework.test import APIClient
    from scripts.models import Script
    from qdt_snmp.models import SnmpDevice, SnmpAlert
    from tacticalrmm.cache import TacticalRedisCache

    real_cache = TacticalRedisCache(redis_url, {}) if redis_url else None
    cache_keys = ["role_script_contract", "agent_tbl_pendingactions_script_contract",
                  "agent_checks_data_script_contract", "site_script_contract",
                  "agent_script_contract", "throttle_script_contract", "core_settings",
                  "script_contract_keep"]

    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()
                    if key not in {"created_time", "modified_time", "entry_time", "alert_time", "time"}}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, datetime):
            return "timestamp"
        return value

    models = [Script, Check, CheckResult, CheckHistory, Alert, MatrixDelivery,
              AgentHistory, AlertTemplate, AutomatedTask, SnmpAlert]

    def state():
        out = {model._meta.db_table: normalize(list(model.objects.order_by("id").values()))
               for model in models}
        out["base"] = normalize(snapshot())
        if real_cache:
            out["cache"] = [real_cache.get(key) for key in cache_keys]
        return out

    def mutation_state(value):
        # Knox deletes expired tokens during authentication, even on 400s.
        # Full Django/Go comparison above still verifies that auth side effect.
        return {**value, "base": {key: item for key, item in value["base"].items() if key != "tokens"}}

    def cleanup():
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        Script.objects.all().delete()
        AlertTemplate.objects.all().delete()
        MatrixChannel.objects.all().delete()
        CheckHistory.objects.all().delete()

    def setup(permission="manage", policy=False):
        cleanup()
        seed()
        Script.objects.bulk_create([
            Script(id=31, name="User ü", script_body="  old\n", args=["x", None, ""],
                   script_hash="stored-hash", category="Test"),
            Script(id=32, name="Community", script_type="builtin"),
        ])
        Client.objects.bulk_create([Client(id=31, name="Scripts")])
        Site.objects.bulk_create([Site(id=31, name="Scripts", client_id=31)])
        Agent.objects.bulk_create([Agent(id=31, hostname="script-host", agent_id="script-contract", site_id=31)])
        Policy.objects.bulk_create([Policy(id=31, name="Script policy")])
        Check.objects.bulk_create([Check(id=31, script_id=31, check_type="script",
                                        policy_id=31 if policy else None, agent_id=None if policy else 31)])
        AutomatedTask.objects.bulk_create([AutomatedTask(id=31, name="Script task", win_task_name="TacticalRMM_contract", assigned_check_id=31, agent_id=31)])
        CheckResult.objects.bulk_create([CheckResult(id=31, assigned_check_id=31, agent_id=31)])
        CheckHistory.objects.bulk_create([CheckHistory(id=31, check_id=31, agent_id="script-contract")])
        Alert.objects.bulk_create([Alert(id=31, assigned_check_id=31, agent_id=31)])
        SnmpDevice.objects.bulk_create([SnmpDevice(id=31, name="Fixture", ip="192.0.2.31", site_id=31)])
        SnmpAlert.objects.bulk_create([SnmpAlert(id=31, device_id=31, alert_id=31, metric="fixture", severity="error")])
        MatrixChannel.objects.bulk_create([MatrixChannel(id=31, name="Test", enabled=False)])
        MatrixDelivery.objects.bulk_create([MatrixDelivery(id=31, channel_id=31, alert_id=31, body="old", event="failure:error", transaction_id="00000000-0000-0000-0000-000000000031")])
        AgentHistory.objects.bulk_create([AgentHistory(id=31, agent_id=31, script_id=31)])
        AlertTemplate.objects.bulk_create([AlertTemplate(id=31, name="Actions", action_id=31, resolved_action_id=31)])
        Role.objects.filter(pk=1).update(can_manage_scripts=permission == "manage", can_list_scripts=permission == "read")
        AuditLog.objects.all().delete()
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence('scripts_script','id'),100,false)")
        cache.clear()
        if real_cache:
            for key in cache_keys:
                real_cache.set(key, "retained")

    count = 0

    def compare(method, path, data=None, user=1, permission="manage", policy=False):
        nonlocal count
        setup(permission, policy)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + hashlib.sha256(f"contract-user-{user}".encode()).hexdigest())
        with patch("core.utils.cache", real_cache) if real_cache else nullcontext():
            response = client.generic(method, path, json.dumps(data) if data is not None else "", content_type="application/json")
        expected = (response.status_code, json.loads(response.content) if response.content else None)
        expected_state = state()
        setup(permission, policy)
        before = state()
        actual = go_request(method, path, data, user_id=user)
        actual_state = state()
        assert actual == expected, (method, path, str(data)[:300], user, expected, actual)
        assert actual_state == expected_state, (method, path, str(data)[:300], user, "state mismatch", expected_state, actual_state)
        if actual[0] >= 400:
            assert mutation_state(actual_state) == mutation_state(before), (method, path, str(data)[:300], "failed mutation changed state", before, actual_state)
        count += 1

    try:
        payloads = [
            {}, {"name":"New", "script_body":"  if ($true) {\n    exit 0\n  }\n"},
            {"name":"  New ü  ", "description":None, "shell":"deno", "args":[None, " a ", ""],
             "env_vars":["KEY=a=b"], "supported_platforms":["windows","linux"], "default_timeout":"0.0",
             "favorite":"yes", "hidden":"false", "run_as_user":1, "syntax":None, "filename":"test.ts"},
            {"id":999,"script_type":"builtin","script_hash":"ignored", "created_by":"ignored", "modified_by":"ignored"},
            {"name":""}, {"name":None}, {"name":"x"*256}, {"script_body":None}, {"script_body":"\x00"},
            {"shell":"bad"}, {"args":"bad"}, {"args":[{}, True]}, {"supported_platforms":[None,"", "x"*21]},
            {"args":None,"env_vars":None,"supported_platforms":None},
            {"default_timeout":-1}, {"default_timeout":2147483648}, {"default_timeout":True},
            {"name":"valid", "favorite":None}, {"script_body":" "}, {"script_body":123},
        ]
        for method, path in [("POST","/scripts/"),("PUT","/scripts/31/")]:
            for data in payloads:
                compare(method,path,data)
        for data in [{}, {"script_body":"forbidden"}, {"favorite":True,"hidden":True,"shell":"bad"},
                     {"hidden":True,"name":"forbidden"}, {"favorite":"bad","hidden":True}, {"hidden":None}]:
            compare("PUT","/scripts/32/",data)
        for user,permission in [(1,"none"),(2,"manage"),(2,"read"),(2,"none"),(3,"manage"),(4,"manage"),(5,"none"),(6,"manage")]:
            compare("POST","/scripts/",{"name":"Allowed?"},user,permission)
            compare("PUT","/scripts/31/",{"name":"Allowed?"},user,permission)
            compare("DELETE","/scripts/31/",user=user,permission=permission)
        for pk in (31,32,999,0):
            compare("DELETE",f"/scripts/{pk}/")
        compare("PUT","/scripts/999/",{"favorite":True})
        compare("PUT","/scripts/31/",{"name":"User ü","default_timeout":90})
        if real_cache:
            compare("PUT","/scripts/31/",{"script_body":"updated"},policy=True)
            compare("PUT","/scripts/31/",{},policy=True)
            compare("PUT","/scripts/31/",{"favorite":None},policy=True)
            compare("DELETE","/scripts/31/",policy=True)
        compare("POST","/scripts/",{"name":"Large body", "script_body":"x"*(513*1024)})
        # A late DB rejection must roll back the script AND the earlier audit.
        setup()
        before = state()
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE scripts_script ADD CONSTRAINT script_contract_reject CHECK (name <> 'rollback') NOT VALID")
        try:
            response = go_request("POST", "/scripts/", {"name": "rollback"})
            assert response[0] == 500, response
            assert mutation_state(state()) == mutation_state(before), "late insert error leaked an audit or script row"
            count += 1
        finally:
            with connection.cursor() as cursor:
                cursor.execute("ALTER TABLE scripts_script DROP CONSTRAINT script_contract_reject")
        print(f"Script write contracts: {count} comparisons passed")
        return count
    finally:
        cleanup()
        seed()
        if real_cache:
            real_cache.delete_many(cache_keys)
