#!/usr/bin/env python3
"""Compare implemented routes with Django using an isolated PostgreSQL schema.

Run with the existing Django virtualenv. Requires a loopback PostgreSQL database
whose name ends with _test and a compiled Go API binary. No production defaults.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True)
    parser.add_argument("--go-binary", required=True, type=Path)
    parser.add_argument("--mesh-binary", type=Path)
    parser.add_argument("--jobs-binary", type=Path)
    parser.add_argument("--redis-url", default="redis://127.0.0.1:56379/0")
    parser.add_argument("--nats-url", default="")
    focused = parser.add_mutually_exclusive_group()
    focused.add_argument("--agent-commands-only", action="store_true", help="Run isolated NATS command contracts")
    focused.add_argument("--software-writes-only", action="store_true", help="Run isolated NATS software write contracts")
    focused.add_argument("--diagnostic-reads-only", action="store_true", help="Run isolated event-log and registry read contracts")
    focused.add_argument("--registry-writes-only", action="store_true", help="Run isolated registry write contracts")
    focused.add_argument("--agent-metadata-only", action="store_true", help="Run agent versions, terminal defaults and script history contracts")
    focused.add_argument("--agent-callbacks-only", action="store_true", help="Run agent-token and installation callback contracts")
    focused.add_argument("--raw-commands-only", action="store_true", help="Run isolated raw commands and result callbacks")
    focused.add_argument("--scheduled-jobs-only", action="store_true", help="Run isolated scheduled-job contracts")
    focused.add_argument("--winupdate-auto-approve-only", action="store_true", help="Run isolated Windows update auto-approve job contracts")
    focused.add_argument("--script-resolver-only", action="store_true", help="Run isolated script database lookup contracts")
    focused.add_argument("--winupdate-supersedence-only", action="store_true", help="Run isolated superseded-update cleanup contracts")
    focused.add_argument("--winupdate-execution-only", action="store_true", help="Run isolated Windows update scan/install and callback contracts")
    focused.add_argument("--script-collectors-only", action="store_true", help="Run isolated synchronous script collector contracts")
    focused.add_argument("--script-notes-only", action="store_true", help="Run isolated synchronous script note contracts")
    focused.add_argument("--async-script-execution-only", action="store_true", help="Run isolated asynchronous script contracts")
    focused.add_argument("--winupdate-completion-only", action="store_true", help="Run update completion contracts without remote reboot")
    focused.add_argument("--winupdate-results-only", action="store_true", help="Run isolated update result callback contracts")
    focused.add_argument("--script-execution-only", action="store_true", help="Run isolated stored-script execution contracts")
    focused.add_argument("--note-completion-only", action="store_true", help="Run asynchronous note completion contracts")
    focused.add_argument("--collector-callbacks-only", action="store_true", help="Run isolated collector result callbacks")
    focused.add_argument("--script-callbacks-only", action="store_true", help="Run isolated script result callback contracts")
    focused.add_argument("--winupdate-policy-only", action="store_true", help="Run isolated effective update policy contracts")
    focused.add_argument("--manager-reads-only", action="store_true", help="Run only script, automation and alert read contracts")
    focused.add_argument("--write-flows-only", action="store_true", help="Run script, snippet and existing-alert write contracts")
    focused.add_argument("--monitoring-reads-only", action="store_true", help="Run check, task and alert-query contracts")
    focused.add_argument("--agent-monitoring-only", action="store_true", help="Run inherited agent check and task contracts")
    focused.add_argument("--patch-logs-only", action="store_true", help="Run patch-policy mutations and log queries")
    focused.add_argument("--core-only", action="store_true", help="Run core settings and object contracts")
    focused.add_argument("--endpoint-management-only", action="store_true", help="Run software, update and pending-action contracts")
    args = parser.parse_args()
    if args.scheduled_jobs_only and not args.jobs_binary:
        parser.error("--scheduled-jobs-only requires --jobs-binary")
    if args.winupdate_auto_approve_only and not args.jobs_binary:
        parser.error("--winupdate-auto-approve-only requires --jobs-binary")
    if (args.agent_commands_only or args.software_writes_only or args.diagnostic_reads_only or args.registry_writes_only or args.raw_commands_only or args.winupdate_execution_only or args.script_execution_only or args.async_script_execution_only or args.script_notes_only or args.script_collectors_only or args.note_completion_only or args.winupdate_auto_approve_only) != bool(args.nats_url):
        parser.error("Use an isolated NATS suite (--agent-commands-only, --software-writes-only, --diagnostic-reads-only, --registry-writes-only, --raw-commands-only, --winupdate-execution-only, --script-execution-only, --async-script-execution-only, --script-notes-only, --script-collectors-only, --note-completion-only, --winupdate-auto-approve-only) with --nats-url")
    for key in ("NATS_URL", "NATS_USER", "NATS_PASSWORD", "TRMM_TEST_NATS_URL"):
        os.environ.pop(key, None)
    if args.nats_url:
        broker = urllib.parse.urlsplit(args.nats_url)
        if (broker.scheme != "nats" or broker.port is None
                or broker.hostname not in {"localhost", "127.0.0.1", "::1"}
                or broker.username is not None or broker.path or broker.query or broker.fragment):
            parser.error("Use a loopback NATS URL without credentials, path, query or fragment")
        os.environ["TRMM_TEST_NATS_URL"] = args.nats_url
    url = urllib.parse.urlsplit(args.dsn)
    database = url.path.removeprefix("/")
    if (url.scheme not in {"postgres", "postgresql"}
            or url.hostname not in {"localhost", "127.0.0.1", "::1"}
            or not database.endswith("_test") or url.query or url.fragment):
        parser.error("Use a loopback PostgreSQL URL with a *_test database and no query/fragment")
    binary = args.go_binary.resolve(strict=True)
    redis_url = urllib.parse.urlsplit(args.redis_url)
    if redis_url.scheme != "redis" or redis_url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        parser.error("Use a loopback Redis URL for the isolated login tests")
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tacticalrmm"))
    os.environ["GHACTIONS"] = "yes"
    os.environ["DJANGO_SETTINGS_MODULE"] = "tacticalrmm.settings"
    from django.conf import settings

    settings.LOGGING_CONFIG = None
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    settings.DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql", "NAME": database,
        "USER": urllib.parse.unquote(url.username or ""),
        "PASSWORD": urllib.parse.unquote(url.password or ""),
        "HOST": url.hostname, "PORT": str(url.port or 5432),
    }}
    settings.ALLOWED_HOSTS = ["testserver", "127.0.0.1"]
    settings.ROOT_USER = "admin"
    if args.script_execution_only or args.async_script_execution_only or args.script_notes_only or args.script_collectors_only:
        # Exercise explicit runtime overrides, especially empty Deno permissions.
        settings.NUSHELL_ENABLE_CONFIG = True
        settings.DENO_DEFAULT_PERMISSIONS = ""
    import django
    django.setup()
    from django.apps import apps
    from django.db import connection
    from rest_framework.test import APIClient
    from accounts.models import APIKey, Role, User
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from knox.models import AuthToken
    from logs.models import AuditLog
    from tacticalrmm.middleware import request_local
    from allauth.socialaccount.models import SocialAccount
    from django.contrib.auth.hashers import check_password, is_password_usable
    import pyotp

    schema = "go_contract_" + uuid.uuid4().hex
    process = None
    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    future = datetime(2099, 1, 1, tzinfo=timezone.utc)
    past = datetime(2000, 1, 1, tzinfo=timezone.utc)
    tokens = {i: hashlib.sha256(f"contract-user-{i}".encode()).hexdigest() for i in range(1, 8)}
    extra = {"expired": "ee" * 32, "permanent": "ff" * 32,
             "refresh": "aa" * 32, "collision": "cc" * 32}
    refresh_expiry = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=1)
    digest = lambda raw: hashlib.sha512(bytes.fromhex(raw)).hexdigest()

    def seed():
        # All referenced tables live in this unique schema, including cascades.
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM go_mesh_sync")
        request_local.username = None
        request_local.debug_info = {}
        cache.clear()
        CoreSettings.objects.all().delete()
        CoreSettings.objects.bulk_create([CoreSettings(id=1)])
        AuditLog.objects.all().delete()
        AuthToken.objects.all().delete()
        APIKey.objects.all().delete()
        User.objects.all().delete()
        Role.objects.all().delete()
        Site.objects.all().delete()
        Client.objects.all().delete()
        Role.objects.bulk_create([
            Role(id=1, name="Read only", can_list_accounts=True, can_list_roles=True, can_list_api_keys=True),
            Role(id=2, name="Administrator", is_superuser=True),
        ])
        User.objects.bulk_create([
            User(id=1, username="admin", is_superuser=True, last_login=fixed),
            User(id=2, username="reader", role_id=1, last_login=fixed),
            User(id=3, username="no-role"),
            User(id=4, username="inactive", is_active=False),
            User(id=5, username="role-admin", role_id=2),
            User(id=6, username="installer", is_installer_user=True),
            User(id=7, username="sso"),
        ])
        SocialAccount.objects.create(user_id=7, provider="openid_connect", uid="reference-sso")
        Client.objects.bulk_create([Client(id=1, name="Client")])
        Site.objects.bulk_create([Site(id=1, name="Site", client_id=1)])
        Role.objects.get(pk=1).can_view_clients.add(1)
        Role.objects.get(pk=1).can_view_sites.add(1)
        Role.objects.update(created_time=fixed, modified_time=fixed)
        User.objects.update(created_time=fixed, modified_time=fixed, date_joined=fixed)
        User.objects.update(totp_key="JBSWY3DPEHPK3PXP")
        User.objects.filter(pk__in=[3, 7]).update(totp_key="")
        AuthToken.objects.bulk_create([
            AuthToken(digest=hashlib.sha512(bytes.fromhex(token)).hexdigest(),
                      token_key=token[:8], user_id=i, expiry=future)
            for i, token in tokens.items()
        ] + [
            AuthToken(digest="expired", token_key="expired!", user_id=1, expiry=past),
            AuthToken(digest="permanent", token_key="perm!!!!", user_id=1, expiry=None),
            AuthToken(digest=digest(extra["expired"]), token_key=extra["expired"][:8], user_id=1, expiry=past),
            AuthToken(digest=digest(extra["permanent"]), token_key=extra["permanent"][:8], user_id=1, expiry=None),
            AuthToken(digest=digest(extra["refresh"]), token_key=extra["refresh"][:8], user_id=1, expiry=refresh_expiry),
            AuthToken(digest=digest("cc" * 4 + "dd" * 28), token_key="cc" * 4, user_id=3, expiry=future),
            AuthToken(digest=digest(extra["collision"]), token_key=extra["collision"][:8], user_id=1, expiry=future),
        ])
        AuthToken.objects.update(created=fixed)
        APIKey.objects.bulk_create([
            APIKey(id=1, name="valid", key="valid-api-key", user_id=1),
            APIKey(id=2, name="expired", key="expired-api-key", user_id=1, expiration=past),
            APIKey(id=3, name="inactive", key="inactive-api-key", user_id=4),
        ])
        APIKey.objects.update(created_time=fixed, modified_time=fixed)
        from django.core.management.color import no_style
        with connection.cursor() as cursor:
            for sql in connection.ops.sequence_reset_sql(no_style(), [APIKey, Role, User]):
                cursor.execute(sql)

    def normalize_timestamp(value):
        if value is None or value == fixed:
            return value
        assert abs((value - datetime.now(timezone.utc)).total_seconds()) < 10, "unexpected audit timestamp"
        return "current timestamp"

    def snapshot(password_input=None):
        rows = list(AuthToken.objects.order_by("digest").values("digest", "user_id", "expiry"))
        for row in rows:
            if row["digest"] == digest(extra["refresh"]) and row["expiry"] != refresh_expiry:
                remaining = row["expiry"] - datetime.now(timezone.utc)
                assert abs(remaining.total_seconds() - 5 * 3600) < 5, "incorrect refresh TTL"
                row["expiry"] = "renewed for five hours"
        keys = list(APIKey.objects.order_by("id").values())
        for key in keys:
            for field in ("created_time", "modified_time"):
                key[field] = normalize_timestamp(key[field])
            if key["id"] > 3:
                assert re.fullmatch(r"[A-Z0-9]{32}", key["key"]), "invalid generated API key"
                key["key"] = "generated key"
        audits = list(AuditLog.objects.order_by("id").values())
        for entry in audits:
            del entry["id"]
            entry["entry_time"] = normalize_timestamp(entry["entry_time"])
            for value in (entry["before_value"], entry["after_value"]):
                if value is not None:
                    assert not {"key", "password", "totp_key"}.intersection(value), "credential leaked to audit log"
        users = list(User.objects.order_by("id").values())
        for user in users:
            for field in ("created_time", "modified_time", "date_joined"):
                user[field] = normalize_timestamp(user[field])
            if user["password"]:
                if password_input is None:
                    assert not is_password_usable(user["password"]), "password should be disabled"
                else:
                    assert user["password"].startswith("pbkdf2_sha256$600000$"), "unexpected hash algorithm"
                    assert check_password(password_input, user["password"]), "Django cannot verify password"
                user["password"] = "verified password hash"
            if user["totp_key"] not in ("JBSWY3DPEHPK3PXP", "", None):
                assert re.fullmatch(r"[A-Z2-7]{32}", user["totp_key"])
                assert len(base64.b32decode(user["totp_key"])) == 20
                user["totp_key"] = "generated TOTP key"
        roles = list(Role.objects.order_by("id").values())
        for role in roles:
            for field in ("created_time", "modified_time"):
                role[field] = normalize_timestamp(role[field])
        clients = list(Role.can_view_clients.through.objects.order_by("role_id", "client_id").values_list("role_id", "client_id"))
        sites = list(Role.can_view_sites.through.objects.order_by("role_id", "site_id").values_list("role_id", "site_id"))
        return {"tokens": rows, "api_keys": keys, "audit": audits, "users": users, "roles": roles, "role_clients": clients, "role_sites": sites}

    def decode(data):
        body = json.loads(data) if data else None
        if isinstance(body, dict) and "totp_key" in body:
            assert User.objects.get(username=body["username"]).totp_key == body["totp_key"]
            assert body["qr_url"] == pyotp.TOTP(body["totp_key"]).provisioning_uri(body["username"], issuer_name="rmm.example.com")
            body["totp_key"], body["qr_url"] = "generated TOTP key", "verified PyOTP URI"
        return body

    try:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE SCHEMA "{schema}"')
            cursor.execute(f'SET search_path TO "{schema}"')
        # Use actual Django models, not GORM AutoMigrate or a simplified test schema.
        with connection.schema_editor() as editor:
            for model in apps.get_models():
                if model._meta.managed and not model._meta.proxy:
                    editor.create_model(model)
        with connection.cursor() as cursor:
            cursor.execute((Path(__file__).resolve().parents[1] / "migrations/001_mesh_sync.sql").read_text())
            cursor.execute((Path(__file__).resolve().parents[1] / "migrations/002_script_note_completion.sql").read_text())
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env = os.environ | {
            "DATABASE_URL": args.dsn + "?" + urllib.parse.urlencode({"search_path": schema}),
            "LISTEN_ADDR": f"127.0.0.1:{port}",
            "CORS_ALLOWED_ORIGINS": "https://rmm.example.com",
            "DJANGO_SECRET_KEY": settings.SECRET_KEY,
            "SESSION_COOKIE_DOMAIN": settings.SESSION_COOKIE_DOMAIN,
            "REDIS_URL": args.redis_url,
            "DJANGO_CACHE_REDIS_URL": args.redis_url,
            "LOGIN_THROTTLE_PREFIX": schema + ":",
            "ROOT_USER": settings.ROOT_USER,
            "LATEST_AGENT_VER": settings.LATEST_AGENT_VER,
            "NUSHELL_ENABLE_CONFIG": str(settings.NUSHELL_ENABLE_CONFIG).lower(),
            "DENO_DEFAULT_PERMISSIONS": settings.DENO_DEFAULT_PERMISSIONS,
        }
        if args.nats_url:
            env.update(NATS_URL=args.nats_url, NATS_USER="tacticalrmm", NATS_PASSWORD="trmm-test-only")
        process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL)
        base = f"http://127.0.0.1:{port}"
        for attempt in range(100):
            if process.poll() is not None:
                raise RuntimeError("Go API exited during startup")
            try:
                with urllib.request.urlopen(base + "/", timeout=1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Go API did not become ready")
        auth = lambda i: {"Authorization": "Token " + tokens[i]}
        def go_request(method, path, data=None, user_id=1, headers=None):
            headers = auth(user_id) if headers is None else dict(headers)
            body = None
            if data is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(data).encode()
            try:
                response = urllib.request.urlopen(urllib.request.Request(base + path, method=method, headers=headers, data=body), timeout=205)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                return response.status, json.loads(data) if data else None


        from compare_scripts_reads import run as compare_scripts_reads
        from compare_automation_reads import run as compare_automation_reads
        from compare_alerts_reads import run as compare_alerts_reads

        def compare_manager_reads():
            # Mesh fixtures retain agents whose restricted site FK blocks seed().
            # All data here belongs to this disposable contract schema.
            from agents.models import Agent
            Agent.objects.all().delete()
            compare_scripts_reads(seed, go_request, snapshot)
            compare_automation_reads(seed, go_request, snapshot)
            compare_alerts_reads(seed, go_request, snapshot)

        def compare_write_flows():
            from agents.models import Agent
            from compare_script_writes import run as compare_script_writes
            from compare_script_snippets import run as compare_script_snippets
            from compare_alert_writes import run as compare_alert_writes
            Agent.objects.all().delete()
            compare_script_writes(seed, go_request, snapshot, args.redis_url)
            compare_script_snippets(seed, go_request, snapshot)
            compare_alert_writes(seed, go_request, snapshot)

        def compare_monitoring_reads():
            from agents.models import Agent
            from compare_checks_reads import run as compare_checks_reads
            from compare_autotasks_reads import run as compare_autotasks_reads
            from compare_alert_queries import run as compare_alert_queries
            Agent.objects.all().delete()
            compare_checks_reads(seed, go_request, snapshot)
            compare_autotasks_reads(seed, go_request, snapshot)
            compare_alert_queries(seed, go_request, snapshot)

        def compare_agent_monitoring():
            from agents.models import Agent
            from compare_agent_monitoring import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)

        def compare_patch_logs():
            from agents.models import Agent
            from compare_patchpolicy_writes import run as compare_patchpolicy_writes
            from compare_patchpolicy_reset import run as compare_patchpolicy_reset
            from compare_logs_reads import run as compare_logs_reads
            Agent.objects.all().delete()
            compare_patchpolicy_writes(seed, go_request, snapshot)
            compare_patchpolicy_reset(seed, go_request, snapshot)
            compare_logs_reads(seed, go_request, snapshot)

        def compare_endpoint_management():
            from agents.models import Agent
            from compare_winupdates import run as compare_winupdates
            from compare_software_reads import run as compare_software_reads
            from compare_pendingactions import run as compare_pendingactions
            from compare_agent_commands import run_disabled
            Agent.objects.all().delete()
            compare_software_reads(seed, go_request, snapshot)
            compare_winupdates(seed, go_request, snapshot)
            compare_pendingactions(seed, go_request, snapshot)
            run_disabled(seed, go_request, snapshot)

        def compare_agent_metadata():
            from agents.models import Agent
            from compare_agent_versions import run as versions
            from compare_terminal_defaults import run as terminal
            from compare_script_history import run as history
            Agent.objects.all().delete()
            versions(seed, go_request, snapshot)
            terminal(seed, go_request, snapshot)
            history(seed, go_request, snapshot)

        def compare_agent_callbacks():
            from agents.models import Agent
            from compare_agent_callbacks import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)

        if args.agent_callbacks_only:
            compare_agent_callbacks()
            return

        if args.agent_metadata_only:
            compare_agent_metadata()
            return

        if args.raw_commands_only:
            from agents.models import Agent
            from compare_agent_rawcmd import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.scheduled_jobs_only:
            from agents.models import Agent
            from compare_scheduled_jobs import run
            Agent.objects.all().delete()
            run(seed, snapshot, args.jobs_binary.resolve(strict=True), env["DATABASE_URL"])
            return

        if args.winupdate_auto_approve_only:
            from agents.models import Agent
            from compare_winupdate_auto_approve import run
            Agent.objects.all().delete()
            run(seed, snapshot, args.jobs_binary.resolve(strict=True), env["DATABASE_URL"], args.nats_url)
            return

        if args.script_resolver_only or args.winupdate_supersedence_only:
            from agents.models import Agent
            if args.script_resolver_only:
                from compare_script_resolver import run
            else:
                from compare_winupdate_supersedence import run
            Agent.objects.all().delete()
            run(seed, snapshot, env["DATABASE_URL"])
            return

        if args.winupdate_execution_only:
            from agents.models import Agent
            from compare_winupdate_execution import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.script_collectors_only:
            from agents.models import Agent
            from compare_script_collectors import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.script_notes_only:
            from agents.models import Agent
            from compare_script_notes import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.winupdate_completion_only:
            from agents.models import Agent
            from compare_winupdate_completion import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.async_script_execution_only or args.winupdate_results_only:
            from agents.models import Agent
            if args.async_script_execution_only:
                from compare_async_script_execution import run
            else:
                from compare_winupdate_results import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.note_completion_only:
            from agents.models import Agent
            from compare_note_completion_schema import run as schema_checks
            from compare_note_completion import run
            Agent.objects.all().delete()
            schema_checks(seed, snapshot)
            run(seed, go_request, snapshot)
            return

        if args.collector_callbacks_only:
            from agents.models import Agent
            from compare_collector_callbacks import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.script_execution_only or args.script_callbacks_only:
            from agents.models import Agent
            if args.script_execution_only:
                from compare_agent_script_execution import run
            else:
                from compare_script_callbacks import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.winupdate_policy_only:
            from agents.models import Agent
            from compare_winupdate_policy import run
            Agent.objects.all().delete()
            run(seed, snapshot, env["DATABASE_URL"])
            return

        if args.registry_writes_only:
            from agents.models import Agent
            from compare_registry_writes import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.diagnostic_reads_only:
            from agents.models import Agent
            from compare_eventlog import run as compare_eventlog
            from compare_registry_reads import run as compare_registry_reads
            Agent.objects.all().delete()
            compare_eventlog(seed, go_request, snapshot)
            compare_registry_reads(seed, go_request, snapshot)
            return

        if args.software_writes_only:
            from agents.models import Agent
            from compare_software_writes import run
            Agent.objects.all().delete()
            run(seed, go_request, snapshot)
            return

        if args.agent_commands_only:
            from agents.models import Agent
            from compare_agent_commands import run as compare_agent_commands
            from compare_pending_nats import run as compare_pending_nats
            from compare_agent_processes import run as compare_agent_processes
            from compare_services_reads import run as compare_services_reads
            from compare_services_writes import run as compare_services_writes
            from compare_agent_power import run as compare_agent_power
            from compare_software_writes import run as compare_software_writes
            from compare_eventlog import run as compare_eventlog
            from compare_registry_reads import run as compare_registry_reads
            from compare_registry_writes import run as compare_registry_writes
            from compare_agent_rawcmd import run as compare_agent_rawcmd
            from compare_winupdate_execution import run as compare_winupdate_execution
            from compare_script_collectors import run as compare_script_collectors
            from compare_script_notes import run as compare_script_notes
            from compare_async_script_execution import run as compare_async_script_execution
            from compare_agent_script_execution import run as compare_agent_script_execution
            Agent.objects.all().delete()
            compare_agent_commands(seed, go_request, snapshot)
            compare_pending_nats(seed, go_request, snapshot)
            compare_agent_processes(seed, go_request, snapshot)
            compare_services_reads(seed, go_request, snapshot)
            compare_services_writes(seed, go_request, snapshot)
            compare_agent_power(seed, go_request, snapshot)
            compare_software_writes(seed, go_request, snapshot)
            compare_eventlog(seed, go_request, snapshot)
            compare_registry_reads(seed, go_request, snapshot)
            compare_registry_writes(seed, go_request, snapshot)
            compare_agent_rawcmd(seed, go_request, snapshot)
            compare_winupdate_execution(seed, go_request, snapshot)
            compare_agent_script_execution(seed, go_request, snapshot)
            compare_async_script_execution(seed, go_request, snapshot)
            compare_script_notes(seed, go_request, snapshot)
            compare_script_collectors(seed, go_request, snapshot)
            return

        if args.endpoint_management_only:
            compare_endpoint_management()
            return

        if args.core_only:
            from compare_core import run
            run(seed, go_request, snapshot)
            return

        if args.patch_logs_only:
            compare_patch_logs()
            return

        if args.agent_monitoring_only:
            compare_agent_monitoring()
            return

        if args.monitoring_reads_only:
            compare_monitoring_reads()
            return

        if args.write_flows_only:
            compare_write_flows()
            return

        if args.manager_reads_only:
            compare_manager_reads()
            return

        cases = [
            ("public", "GET", "/", {}),
            ("missing token", "GET", "/core/version/", {}),
            ("version", "GET", "/core/version/", auth(1)),
            ("api key", "GET", "/core/version/", {"X-API-KEY": "valid-api-key"}),
            ("expired api key", "GET", "/core/version/", {"X-API-KEY": "expired-api-key"}),
            ("inactive api key", "GET", "/core/version/", {"X-API-KEY": "inactive-api-key"}),
            ("invalid api key", "GET", "/core/version/", {"X-API-KEY": "bad"}),
            ("inactive user", "GET", "/core/version/", auth(4)),
            ("expired token", "GET", "/core/version/", {"Authorization": "Token " + extra["expired"]}),
            ("permanent token", "GET", "/core/version/", {"Authorization": "Token " + extra["permanent"]}),
            ("refresh token", "GET", "/core/version/", {"Authorization": "Token " + extra["refresh"]}),
            ("token prefix collision", "GET", "/accounts/roles/", {"Authorization": "Token " + extra["collision"]}),
            ("malformed header", "GET", "/core/version/", {"Authorization": "Token"}),
            ("spaces in token", "GET", "/core/version/", {"Authorization": "Token a b"}),
            ("invalid hex", "GET", "/core/version/", {"Authorization": "Token zz"}),
            ("invalid hex matching prefix", "GET", "/core/version/", {"Authorization": "Token " + tokens[1][:8] + "zz"}),
            ("token takes precedence", "GET", "/core/version/", {"Authorization": "Token zz", "X-API-KEY": "valid-api-key"}),
            ("other auth scheme", "GET", "/core/version/", {"Authorization": "Bearer x", "X-API-KEY": "valid-api-key"}),
            ("user", "GET", "/accounts/2/users/", auth(1)),
            ("leading zero identifier", "GET", "/accounts/000000000000000000000000002/users/", auth(1)),
            ("missing user", "GET", "/accounts/999/users/", auth(1)),
            ("no role", "GET", "/accounts/2/users/", auth(3)),
            ("role permission", "GET", "/accounts/2/users/", auth(2)),
            ("HEAD read permission", "HEAD", "/accounts/2/users/", auth(2)),
            ("HEAD admin permission", "HEAD", "/accounts/2/users/", auth(1)),
            ("roles", "GET", "/accounts/roles/", auth(2)),
            ("HEAD roles read permission", "HEAD", "/accounts/roles/", auth(2)),
            ("role", "GET", "/accounts/roles/1/", auth(2)),
            ("missing role", "GET", "/accounts/roles/999/", auth(1)),
            ("sessions", "GET", "/accounts/users/1/sessions/", auth(1)),
            ("delete sessions", "DELETE", "/accounts/users/1/sessions/", auth(1)),
            ("read cannot delete", "DELETE", "/accounts/users/1/sessions/", auth(2)),
            ("role admin", "DELETE", "/accounts/users/1/sessions/", auth(5)),
            ("delete session", "DELETE", "/accounts/sessions/permanent/", auth(1)),
            ("missing session", "DELETE", "/accounts/sessions/not-found/", auth(1)),
            ("logout", "POST", "/logout/", auth(1)),
            ("logout all", "POST", "/logoutall/", auth(1)),
            ("logout rejects api key", "POST", "/logout/", {"X-API-KEY": "valid-api-key"}),
            ("list API keys", "GET", "/accounts/apikeys/", auth(1)),
            ("list API keys reader", "GET", "/accounts/apikeys/", auth(2)),
            ("list API keys denied", "GET", "/accounts/apikeys/", auth(3)),
            ("HEAD API keys denied", "HEAD", "/accounts/apikeys/", auth(2)),
            ("create API key", "POST", "/accounts/apikeys/", auth(1), {"name": "new key", "user": 2}),
            ("create key expiration", "POST", "/accounts/apikeys/", auth(1), {"name": "expiring", "user": "2", "expiration": "2099-01-01T12:34:56.123400+02:00"}),
            ("create key date only", "POST", "/accounts/apikeys/", auth(1), {"name": "date", "user": 2, "expiration": "2099-01-01"}),
            ("create overrides supplied key", "POST", "/accounts/apikeys/", auth(1), {"name": "generated", "user": 1, "key": {"bad": True}, "id": 999, "created_time": "ignored"}),
            ("create key no permission", "POST", "/accounts/apikeys/", auth(2), {"name": "denied", "user": 1}),
            ("create key missing fields", "POST", "/accounts/apikeys/", auth(1), {}),
            ("create key null fields", "POST", "/accounts/apikeys/", auth(1), {"name": None, "user": None}),
            ("create key blank name", "POST", "/accounts/apikeys/", auth(1), {"name": "   ", "user": 1}),
            ("create key duplicate name", "POST", "/accounts/apikeys/", auth(1), {"name": "valid", "user": 1}),
            ("create key long unicode", "POST", "/accounts/apikeys/", auth(1), {"name": "ä" * 26, "user": 1}),
            ("create key numeric name", "POST", "/accounts/apikeys/", auth(1), {"name": 42, "user": 1}),
            ("create key invalid types", "POST", "/accounts/apikeys/", auth(1), {"name": True, "user": True, "expiration": False}),
            ("create key missing user", "POST", "/accounts/apikeys/", auth(1), {"name": "missing", "user": 999}),
            ("create key invalid user", "POST", "/accounts/apikeys/", auth(1), {"name": "invalid", "user": {}}),
            ("create key invalid date", "POST", "/accounts/apikeys/", auth(1), {"name": "date", "user": 1, "expiration": "tomorrow"}),
            ("create key null character", "POST", "/accounts/apikeys/", auth(1), {"name": "bad\u0000name", "user": 1}),
            ("create key audit fields", "POST", "/accounts/apikeys/", auth(1), {"name": "audit", "user": 1, "created_by": "creator", "modified_by": "ignored"}),
            ("create key invalid audit fields", "POST", "/accounts/apikeys/", auth(1), {"name": "audit", "user": 1, "modified_by": "x" * 256}),
            ("update API key", "PUT", "/accounts/apikeys/1/", auth(1), {"name": "renamed", "user": 2, "expiration": "2099-01-01T00:00:00Z"}),
            ("update preserves key", "PUT", "/accounts/apikeys/1/", auth(1), {"key": "replaced"}),
            ("update no-op", "PUT", "/accounts/apikeys/1/", auth(1), {"name": "valid"}),
            ("update clears expiration", "PUT", "/accounts/apikeys/2/", auth(1), {"expiration": None}),
            ("update duplicate name", "PUT", "/accounts/apikeys/1/", auth(1), {"name": "expired"}),
            ("update missing key", "PUT", "/accounts/apikeys/999/", auth(1), {}),
            ("update no permission", "PUT", "/accounts/apikeys/1/", auth(2), {"name": "denied"}),
            ("delete API key", "DELETE", "/accounts/apikeys/1/", auth(1)),
            ("delete API key via itself", "DELETE", "/accounts/apikeys/1/", {"X-API-KEY": "valid-api-key"}),
            ("delete missing key", "DELETE", "/accounts/apikeys/999/", auth(1)),
            ("delete key denied", "DELETE", "/accounts/apikeys/1/", auth(2)),
            ("update UI", "PATCH", "/accounts/users/ui/", auth(2), {"dark_mode": False, "show_community_scripts": False, "loading_bar_color": "blue", "client_tree_splitter": 20, "client_tree_sort": "alpha"}),
            ("update UI audit fields", "PATCH", "/accounts/users/ui/", auth(2), {"block_dashboard_login": True, "date_format": "DD.MM.YYYY"}),
            ("update UI nulls", "PATCH", "/accounts/users/ui/", auth(2), {"date_format": None, "url_action": None}),
            ("update UI empty", "PATCH", "/accounts/users/ui/", auth(2), {}),
            ("update UI null body", "PATCH", "/accounts/users/ui/", auth(2), None),
            ("update UI ignores privilege fields", "PATCH", "/accounts/users/ui/", auth(2), {"is_superuser": True, "role": 2, "password": "ignored", "username": "root", "agent": 99}),
            ("update UI choices", "PATCH", "/accounts/users/ui/", auth(3), {"agent_dblclick_action": "takecontrol", "default_agent_tbl_tab": "server", "client_tree_sort": "alpha"}),
            ("update UI invalid choices", "PATCH", "/accounts/users/ui/", auth(2), {"agent_dblclick_action": "invalid", "default_agent_tbl_tab": "invalid", "client_tree_sort": "invalid"}),
            ("update UI boolean coercion", "PATCH", "/accounts/users/ui/", auth(2), {"dark_mode": "OFF", "show_community_scripts": 1, "clear_search_when_switching": "Yes"}),
            ("update UI invalid boolean", "PATCH", "/accounts/users/ui/", auth(2), {"dark_mode": "unknown", "show_community_scripts": None}),
            ("update UI invalid color", "PATCH", "/accounts/users/ui/", auth(2), {"loading_bar_color": "", "dash_info_color": None, "dash_warning_color": "a" * 256}),
            ("update UI missing URL action", "PATCH", "/accounts/users/ui/", auth(2), {"url_action": 999}),
            ("update UI invalid splitter", "PATCH", "/accounts/users/ui/", auth(2), {"client_tree_splitter": "1.1"}),
            ("update UI negative splitter", "PATCH", "/accounts/users/ui/", auth(2), {"client_tree_splitter": -1}),
            ("update UI large splitter", "PATCH", "/accounts/users/ui/", auth(2), {"client_tree_splitter": 2147483648}),
            ("update UI huge splitter", "PATCH", "/accounts/users/ui/", auth(2), {"client_tree_splitter": "9" * 100}),
            ("update UI oversized splitter string", "PATCH", "/accounts/users/ui/", auth(2), {"client_tree_splitter": "9" * 1001}),
            ("update UI integral string", "PATCH", "/accounts/users/ui/", auth(2), {"client_tree_splitter": "25.0"}),
            ("update UI installer denied", "PATCH", "/accounts/users/ui/", auth(6), {"dark_mode": False}),
            ("reset own password", "PUT", "/accounts/resetpw/", auth(2), {"password": "New!密碼ä-password", "id": 1}),
            ("reset root password", "PUT", "/accounts/resetpw/", auth(1), {"password": "admin password"}),
            ("reset empty password", "PUT", "/accounts/resetpw/", auth(2), {"password": ""}),
            ("disable password", "PUT", "/accounts/resetpw/", auth(2), {"password": None}),
            ("reset SSO password denied", "PUT", "/accounts/resetpw/", auth(7), {"password": "denied"}),
            ("reset own two factor", "PUT", "/accounts/reset2fa/", auth(2), {"id": 1}),
            ("reset SSO two factor denied", "PUT", "/accounts/reset2fa/", auth(7)),
            ("setup two factor", "POST", "/accounts/users/setup_totp/", auth(3)),
            ("setup existing two factor", "POST", "/accounts/users/setup_totp/", auth(2)),
            ("setup installer denied", "POST", "/accounts/users/setup_totp/", auth(6)),
            ("setup SSO two factor", "POST", "/accounts/users/setup_totp/", auth(7)),
            ("admin resets user password", "POST", "/accounts/users/reset/", auth(1), {"id": 2, "password": "new admin password"}),
            ("admin password alias", "POST", "/accounts/users/reset_totp/", auth(1), {"id": 2, "password": "alias password"}),
            ("reader resets own password", "POST", "/accounts/users/reset/", auth(2), {"id": "2", "password": " own password "}),
            ("no-role resets own password", "POST", "/accounts/users/reset/", auth(3), {"id": 3, "password": "self password"}),
            ("reader cannot reset another", "POST", "/accounts/users/reset/", auth(2), {"id": 3, "password": "denied"}),
            ("role manager resets password", "POST", "/accounts/users/reset/", auth(5), {"id": 2, "password": "manager password"}),
            ("root protected from other admin", "POST", "/accounts/users/reset/", auth(5), {"id": 1, "password": "denied"}),
            ("root may reset own password", "POST", "/accounts/users/reset/", auth(1), {"id": 1, "password": "root password"}),
            ("admin resets SSO password", "POST", "/accounts/users/reset/", auth(1), {"id": 7, "password": "SSO local password"}),
            ("admin disables password", "POST", "/accounts/users/reset/", auth(1), {"id": 2, "password": None}),
            ("admin sets empty password", "POST", "/accounts/users/reset/", auth(1), {"id": 2, "password": ""}),
            ("reset missing user", "POST", "/accounts/users/reset/", auth(1), {"id": 999, "password": "unused"}),
            ("reset missing user denied first", "POST", "/accounts/users/reset/", auth(2), {"id": 999, "password": "unused"}),
            ("admin resets TOTP", "PUT", "/accounts/users/reset_totp/", auth(1), {"id": 2}),
            ("admin TOTP alias", "PUT", "/accounts/users/reset/", auth(1), {"id": 2}),
            ("reader resets own TOTP", "PUT", "/accounts/users/reset_totp/", auth(2), {"id": 2}),
            ("reader cannot reset other TOTP", "PUT", "/accounts/users/reset_totp/", auth(2), {"id": 3}),
            ("root TOTP protected", "PUT", "/accounts/users/reset_totp/", auth(5), {"id": 1}),
            ("admin resets SSO TOTP", "PUT", "/accounts/users/reset_totp/", auth(1), {"id": 7}),
            ("local logon block denies root reset", "POST", "/accounts/users/reset/", auth(1), {"id": 2, "password": "denied"}, {"block_local": True}),
            ("local logon block denies self reset", "POST", "/accounts/users/reset/", auth(2), {"id": 2, "password": "denied"}, {"block_local": True}),
            ("local logon block denies TOTP reset", "PUT", "/accounts/users/reset_totp/", auth(2), {"id": 2}, {"block_local": True}),
            ("create role", "POST", "/accounts/roles/", auth(1), {"name": "New role"}),
            ("create role flags", "POST", "/accounts/roles/", auth(1), {"name": "Flag role", "can_manage_accounts": True, "can_use_mesh": "yes", "can_run_scripts": 1, "can_list_agents": "OFF"}),
            ("create role all flags", "POST", "/accounts/roles/", auth(1), {"name": "All flags", **{f.name: True for f in Role._meta.fields if f.get_internal_type() == "BooleanField"}}),
            ("create superuser role", "POST", "/accounts/roles/", auth(1), {"name": "Full role", "is_superuser": True}),
            ("create role scope", "POST", "/accounts/roles/", auth(1), {"name": "Scoped", "can_view_clients": [1, "1"], "can_view_sites": [1]}),
            ("create role empty scope", "POST", "/accounts/roles/", auth(1), {"name": "Empty scope", "can_view_clients": [], "can_view_sites": []}),
            ("create role audit input", "POST", "/accounts/roles/", auth(1), {"name": "Audit role", "created_by": "creator", "modified_by": "modifier", "created_time": "ignored", "modified_time": "ignored", "id": 999, "user_count": 20}),
            ("create role audit nulls", "POST", "/accounts/roles/", auth(1), {"name": "Nulls", "created_by": None, "modified_by": ""}),
            ("create role missing name", "POST", "/accounts/roles/", auth(1), {}),
            ("create role null name", "POST", "/accounts/roles/", auth(1), {"name": None}),
            ("create role blank name", "POST", "/accounts/roles/", auth(1), {"name": "   "}),
            ("create role long name", "POST", "/accounts/roles/", auth(1), {"name": "ü"*256}),
            ("create duplicate role", "POST", "/accounts/roles/", auth(1), {"name": "Read only"}),
            ("create role numeric name", "POST", "/accounts/roles/", auth(1), {"name": 42}),
            ("create role invalid flags", "POST", "/accounts/roles/", auth(1), {"name": "Bad flags", "can_use_mesh": "invalid", "can_run_scripts": None}),
            ("create role bad audit fields", "POST", "/accounts/roles/", auth(1), {"name": "Bad audit", "created_by": [], "modified_by": "x"*256}),
            ("create role missing scope", "POST", "/accounts/roles/", auth(1), {"name": "Bad scope", "can_view_clients": [999], "can_view_sites": [999]}),
            ("create role invalid scope", "POST", "/accounts/roles/", auth(1), {"name": "Bad scope", "can_view_clients": "1", "can_view_sites": {"id": 1}}),
            ("create role null scope", "POST", "/accounts/roles/", auth(1), {"name": "Null scope", "can_view_clients": None}),
            ("create role boolean scope", "POST", "/accounts/roles/", auth(1), {"name": "Bool scope", "can_view_clients": [True]}),
            ("create role null scope item", "POST", "/accounts/roles/", auth(1), {"name": "Null item", "can_view_clients": [None]}),
            ("create role dictionary scope", "POST", "/accounts/roles/", auth(1), {"name": "Dict scope", "can_view_clients": {"1": "ignored"}, "can_view_sites": {}}),
            ("create role scope error order", "POST", "/accounts/roles/", auth(1), {"name": "First error", "can_view_clients": [999, True]}),
            ("create role denied", "POST", "/accounts/roles/", auth(2), {"name": "Denied"}),
            ("create role via role permission", "POST", "/accounts/roles/", auth(5), {"name": "Managed role"}),
            ("edit role", "PUT", "/accounts/roles/1/", auth(1), {"name": "Edited", "can_use_mesh": True}),
            ("edit role no-op", "PUT", "/accounts/roles/1/", auth(1), {"name": "Read only"}),
            ("edit role false flags", "PUT", "/accounts/roles/1/", auth(1), {"name": "Read only", "can_list_accounts": False}),
            ("edit role all flags", "PUT", "/accounts/roles/1/", auth(1), {"name": "All flags", **{f.name: True for f in Role._meta.fields if f.get_internal_type() == "BooleanField"}}),
            ("edit role clear scopes", "PUT", "/accounts/roles/1/", auth(1), {"name": "Read only", "can_view_clients": [], "can_view_sites": []}),
            ("edit role deduplicate scopes", "PUT", "/accounts/roles/1/", auth(1), {"name": "Scoped", "can_view_clients": [1, 1], "can_view_sites": []}),
            ("edit role audit input", "PUT", "/accounts/roles/1/", auth(1), {"name": "Read only", "created_by": "creator", "modified_by": "modifier"}),
            ("edit role audit nulls", "PUT", "/accounts/roles/1/", auth(1), {"name": "Read only", "created_by": None, "modified_by": None}),
            ("edit role readonly input", "PUT", "/accounts/roles/1/", auth(1), {"name": "Read only", "id": 99, "created_time": "ignored", "modified_time": "ignored", "user_count": 99}),
            ("edit role duplicate name", "PUT", "/accounts/roles/1/", auth(1), {"name": "Administrator"}),
            ("edit role missing name", "PUT", "/accounts/roles/1/", auth(1), {}),
            ("edit role invalid scope", "PUT", "/accounts/roles/1/", auth(1), {"name": "Invalid", "can_view_clients": [999]}),
            ("edit role invalid flag", "PUT", "/accounts/roles/1/", auth(1), {"name": "Invalid", "can_use_mesh": None}),
            ("edit role denied", "PUT", "/accounts/roles/1/", auth(2), {"name": "Denied"}),
            ("edit role missing", "PUT", "/accounts/roles/999/", auth(1), {"name": "Missing"}),
            ("edit role own permission", "PUT", "/accounts/roles/2/", auth(5), {"name": "Administrator", "is_superuser": False}),
            ("delete role", "DELETE", "/accounts/roles/1/", auth(1)),
            ("delete own role", "DELETE", "/accounts/roles/2/", auth(5)),
            ("delete role denied", "DELETE", "/accounts/roles/1/", auth(2)),
            ("delete role missing", "DELETE", "/accounts/roles/999/", auth(1)),
        ]
        cases.extend([
            ("add user", "POST", "/accounts/users/", auth(1), {"username": "new-user", "email": "User@EXAMPLE.COM", "password": "new-secret"}),
            ("add user details", "POST", "/accounts/users/", auth(1), {"username": "new-user", "email": " user@EXAMPLE.COM ", "password": "new-secret", "first_name": " First ", "last_name": "Last", "role": 1}),
            ("add user normalized", "POST", "/accounts/users/", auth(1), {"username": "Ｕｓｅｒ", "email": "", "password": ""}),
            ("add user disabled password", "POST", "/accounts/users/", auth(1), {"username": "new-user", "email": None, "password": None}),
            ("add user ignores string role", "POST", "/accounts/users/", auth(1), {"username": "new-user", "email": "", "password": "secret", "role": "1"}),
            ("add user boolean role", "POST", "/accounts/users/", auth(1), {"username": "new-user", "email": "", "password": "secret", "role": True}),
            ("add user ignores privilege fields", "POST", "/accounts/users/", auth(1), {"username": "new-user", "email": "", "password": "secret", "is_superuser": True, "is_staff": True, "is_active": False, "agent": 1, "is_installer_user": True, "totp_key": "attacker", "block_dashboard_login": True, "date_format": "ignored"}),
            ("add user invalid username", "POST", "/accounts/users/", auth(1), {"username": "bad username", "email": "", "password": "secret"}),
            ("add user denied", "POST", "/accounts/users/", auth(2), {"username": "new-user", "email": "", "password": "secret"}),
            ("add user role administrator", "POST", "/accounts/users/", auth(5), {"username": "new-user", "email": "not-validated-on-create", "password": "secret"}),
        ])
        for label, payload in [
            ("partial details", {"first_name": " Alice ", "last_name": " Reader ", "email": "Alice@EXAMPLE.COM"}),
            ("empty", {}),
            ("username", {"username": "renamed"}),
            ("username Unicode", {"username": "Ｕｓｅｒ"}),
            ("username numeric", {"username": 123}),
            ("username duplicate", {"username": "admin"}),
            ("username invalid", {"username": "bad username"}),
            ("username blank", {"username": " "}),
            ("username null", {"username": None}),
            ("username long", {"username": "a" * 151}),
            ("username invalid long", {"username": "a" * 150 + "!"}),
            ("null characters", {"username": "bad\x00", "first_name": "bad\x00", "email": "bad\x00@example.com"}),
            ("flags", {"is_active": "off", "block_dashboard_login": 1}),
            ("invalid flags", {"is_active": None, "block_dashboard_login": "bad"}),
            ("role", {"role": "2"}),
            ("clear role", {"role": None}),
            ("bad role", {"role": 999}),
            ("boolean role", {"role": True}),
            ("float role", {"role": 2.9}),
            ("date fields", {"date_format": None, "last_login": "2030-01-02T03:04:05.123456+02:00"}),
            ("clear last login", {"last_login": None, "last_login_ip": None}),
            ("invalid date", {"last_login": "not a date"}),
            ("IPv4", {"last_login_ip": " 192.0.2.1 "}),
            ("IPv6", {"last_login_ip": "2001:0db8:0000:0000:0000:0000:0000:0001"}),
            ("mapped IP", {"last_login_ip": "::ffff:192.0.2.1"}),
            ("scoped IP", {"last_login_ip": "fe80::1%eth0"}),
            ("invalid IP", {"last_login_ip": "192.168.001.1"}),
            ("blank IP", {"last_login_ip": ""}),
            ("numeric IP", {"last_login_ip": 123}),
            ("email localhost", {"email": "local@localhost"}),
            ("email IDN", {"email": "user@bücher.de"}),
            ("email literal", {"email": "user@[2001:db8::1]"}),
            ("email quoted", {"email": '"user..name"@example.com'}),
            ("email invalid", {"email": "user@example"}),
            ("email invalid local", {"email": "user..name@example.com"}),
            ("email Unicode local", {"email": "müller@example.com"}),
            ("email empty", {"email": ""}),
            ("email null", {"email": None}),
            ("name null", {"first_name": None, "last_name": None}),
            ("name long", {"first_name": "a"*151, "last_name": "a"*151}),
            ("ignore privileged fields", {"password": "ignored", "is_superuser": True, "is_staff": True, "is_installer_user": True, "agent": 1, "totp_key": "ignored", "created_by": "ignored", "id": 99}),
        ]:
            cases.append(("edit user " + label, "PUT", "/accounts/2/users/", auth(1), payload))
        cases.extend([
            ("edit user denied", "PUT", "/accounts/2/users/", auth(2), {"first_name": "Denied"}),
            ("edit user missing", "PUT", "/accounts/999/users/", auth(1), {}),
            ("edit root protected", "PUT", "/accounts/1/users/", auth(5), {"first_name": "Denied"}),
            ("edit root self", "PUT", "/accounts/1/users/", auth(1), {"first_name": "Root"}),
            ("edit user SSO", "PUT", "/accounts/7/users/", auth(1), {"first_name": "SSO"}),
            ("edit user installer", "PUT", "/accounts/6/users/", auth(1), {"first_name": "Installer"}),
            ("edit user local block", "PUT", "/accounts/2/users/", auth(1), {"first_name": "Allowed"}, {"block_local": True}),
        ])
        for label, method, path, headers, *payload in cases:
            body = json.dumps(payload[0]).encode() if payload else b""
            headers = headers | ({"Content-Type": "application/json"} if payload else {})
            seed()
            if len(payload) > 1 and payload[1].get("block_local"):
                CoreSettings.objects.update(block_local_user_logon=True)
            client = APIClient()
            with patch("accounts.views.sync_mesh_perms_task.delay") as mesh_dispatch:
                expected = client.generic(method, path, data=body, content_type=headers.get("Content-Type", "application/octet-stream"), **{
                    "HTTP_" + key.upper().replace("-", "_"): value for key, value in headers.items()
                })
            dispatched = mesh_dispatch.call_count
            password_input = payload[0].get("password") if payload and isinstance(payload[0], dict) else None
            expected_body, expected_state = decode(expected.content), snapshot(password_input)
            seed()
            if len(payload) > 1 and payload[1].get("block_local"):
                CoreSettings.objects.update(block_local_user_logon=True)
            request = urllib.request.Request(base + path, method=method, headers=headers, data=body if payload else None)
            try:
                actual = urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                actual = error
            with actual:
                actual_body = decode(actual.read())
                # The source session queryset has no ORDER BY. PostgreSQL may
                # choose different row orders after reseeding the same schema.
                if method == "GET" and path.endswith("/sessions/") and isinstance(actual_body, list) and isinstance(expected_body, list):
                    actual_body.sort(key=lambda row: row["digest"])
                    expected_body.sort(key=lambda row: row["digest"])
                assert actual.status == expected.status_code, (label, actual.status, expected.status_code, actual_body)
                assert actual_body == expected_body, (label, actual_body, expected_body)
                assert actual.headers.get("WWW-Authenticate") == expected.get("WWW-Authenticate"), label
            actual_state = snapshot(password_input)
            assert actual_state == expected_state, (label, "database effects differ", actual_state, expected_state)
            with connection.cursor() as cursor:
                cursor.execute("SELECT generation, completed_generation FROM go_mesh_sync")
                assert cursor.fetchall() == ([(1, 0)] if dispatched else []), (label, "Mesh dispatch differs")
            print("PASS", label)
        print(f"{len(cases)} Django/Go contract cases passed")


        seed()
        go_request("GET", "/core/version/")
        before = snapshot()
        with connection.cursor() as cursor:
            cursor.execute("""CREATE FUNCTION fail_mesh_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$""")
            cursor.execute("CREATE TRIGGER fail_mesh_enqueue BEFORE INSERT OR UPDATE ON go_mesh_sync FOR EACH ROW EXECUTE FUNCTION fail_mesh_enqueue()")
        try:
            for method, data in (("PUT", {"name": "Rollback", "can_view_clients": []}), ("DELETE", None)):
                assert go_request(method, "/accounts/roles/1/", data)[0] == 500
                assert snapshot() == before, "outbox failure did not roll back role/audit/scopes/users"
            for method, path, data in (
                ("PUT", "/accounts/2/users/", {"username": "rollback-user", "role": 2}),
                ("POST", "/accounts/users/", {"username": "rollback-user", "email": "", "password": "secret", "role": 1}),
            ):
                assert go_request(method, path, data)[0] == 500
                assert snapshot() == before, "outbox failure did not roll back user/audit"
        finally:
            with connection.cursor() as cursor:
                cursor.execute("DROP TRIGGER fail_mesh_enqueue ON go_mesh_sync")
                cursor.execute("DROP FUNCTION fail_mesh_enqueue()")
        print("PASS role mutation/audit/outbox atomic rollback")
        for data, expected_status in (
            ({"username": "admin", "email": "", "password": "secret"}, 400),
            ({"username": "invalid-role", "email": "", "password": "secret", "role": 999}, 404),
            ({"username": "invalid-password", "email": "", "password": []}, 400),
            ({"username": "missing-password", "email": ""}, 400),
        ):
            assert go_request("POST", "/accounts/users/", data)[0] == expected_status
            assert snapshot() == before, "failed user creation left account or audit rows"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: go_request("POST", "/accounts/users/", {
                "username": "concurrent-user", "email": "", "password": "secret",
            }), range(2)))
        assert sorted(status for status, _ in results) == [200, 400], results
        assert User.objects.filter(username="concurrent-user").count() == 1
        assert AuditLog.objects.filter(object_type="user", action="add").count() == 1
        assert check_password("secret", User.objects.get(username="concurrent-user").password)
        with connection.cursor() as cursor:
            cursor.execute("SELECT generation, completed_generation FROM go_mesh_sync")
            assert cursor.fetchall() == [(1, 0)]
        print("PASS user/audit/outbox rollback and concurrent unique creation")

        # Deliberate safety improvement: failed writes must not leave orphan
        # audit entries, and failed auditing must roll back a preceding deletion.
        seed()
        assert go_request("GET", "/core/version/")[0] == 200
        baseline = snapshot()
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE FUNCTION reject_key_write() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'injected write failure'; END $$;
                CREATE TRIGGER reject_key_write BEFORE UPDATE OR INSERT ON accounts_apikey
                FOR EACH ROW EXECUTE FUNCTION reject_key_write();
            """)
        assert go_request("PUT", "/accounts/apikeys/1/", {"name": "failed write"}) == (500, {"detail": "Internal server error."})
        assert snapshot() == baseline, "failed key write left database changes"
        with connection.cursor() as cursor:
            cursor.execute("DROP TRIGGER reject_key_write ON accounts_apikey")
            cursor.execute("""
                CREATE TRIGGER reject_audit_write BEFORE INSERT ON logs_auditlog
                FOR EACH ROW EXECUTE FUNCTION reject_key_write();
            """)
        assert go_request("DELETE", "/accounts/apikeys/1/") == (500, {"detail": "Internal server error."})
        assert snapshot() == baseline, "failed audit write did not roll back key deletion"
        with connection.cursor() as cursor:
            cursor.execute("DROP TRIGGER reject_audit_write ON logs_auditlog")
            cursor.execute("DROP FUNCTION reject_key_write()")
        print("PASS mutation/audit rollback")

        seed()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(go_request, "POST", "/accounts/apikeys/", {"name": "concurrent", "user": 1}) for _ in range(2)]
            results = [future.result() for future in futures]
        assert sorted(status for status, _ in results) == [200, 400], results
        assert APIKey.objects.filter(name="concurrent").count() == 1
        assert AuditLog.objects.filter(object_type="apikey", action="add").count() == 1
        print("PASS concurrent unique API-key creation")

        seed()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(go_request, "POST", "/accounts/users/setup_totp/", user_id=3) for _ in range(2)]
            results = [future.result() for future in futures]
        assert all(status == 200 for status, _ in results), results
        for _, body in results:
            if isinstance(body, dict):
                decode(json.dumps(body))  # ORM checks stay on the schema-owning main thread.
        assert sum(body is False for _, body in results) == 1, results
        assert sum(isinstance(body, dict) for _, body in results) == 1, results
        assert User.objects.get(pk=3).modified_time == fixed
        assert not AuditLog.objects.exists()
        print("PASS concurrent TOTP setup")

        seed()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(go_request, "POST", "/accounts/roles/", {"name": "Concurrent role", "can_view_clients": [1], "can_view_sites": [1]}) for _ in range(2)]
            results = [future.result() for future in futures]
        assert sorted(status for status, _ in results) == [200, 400], results
        role = Role.objects.get(name="Concurrent role")
        assert list(role.can_view_clients.values_list("pk", flat=True)) == [1]
        assert list(role.can_view_sites.values_list("pk", flat=True)) == [1]
        assert AuditLog.objects.filter(object_type="role", action="add").count() == 1
        print("PASS concurrent unique role creation")

        seed()
        # Knox expiry cleanup happens during authentication, outside the
        # mutation transaction. Complete it before taking the rollback baseline.
        assert go_request("GET", "/core/version/")[0] == 200
        baseline = snapshot()
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE FUNCTION reject_account_write() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'injected account failure'; END $$;
                CREATE TRIGGER reject_role_scope BEFORE INSERT ON accounts_role_can_view_sites
                FOR EACH ROW EXECUTE FUNCTION reject_account_write();
                CREATE TRIGGER reject_user_reset BEFORE UPDATE ON accounts_user
                FOR EACH ROW EXECUTE FUNCTION reject_account_write();
            """)
        assert go_request("POST", "/accounts/roles/", {"name": "Rollback role", "can_view_clients": [1], "can_view_sites": [1]})[0] == 500
        assert snapshot() == baseline, "failed scope insert left a role or audit entry"
        assert go_request("POST", "/accounts/users/reset/", {"id": 2, "password": "rejected"})[0] == 500
        assert snapshot() == baseline, "failed reset left user changes"
        with connection.cursor() as cursor:
            cursor.execute("DROP TRIGGER reject_role_scope ON accounts_role_can_view_sites")
            cursor.execute("DROP TRIGGER reject_user_reset ON accounts_user")
            cursor.execute("DROP FUNCTION reject_account_write()")
        print("PASS role/scope/audit and user-reset rollback")

        # Safer than Django's unhandled KeyError/TypeError on malformed input.
        for data in ({}, {"id": []}, {"id": 2}, {"id": 2, "password": 123}):
            assert go_request("POST", "/accounts/users/reset/", data)[0] == 400
        assert snapshot() == baseline
        print("PASS malformed reset input fails without mutations")
        from compare_user_list import run as compare_user_list
        from compare_user_delete import run as compare_user_delete
        from compare_client_sites import run as compare_client_sites
        compare_user_list(seed, go_request, snapshot)
        compare_user_delete(seed, go_request, snapshot)
        compare_client_sites(seed, go_request, snapshot)
        from compare_client_writes import run as compare_client_writes
        compare_client_writes(seed, go_request, snapshot)
        from compare_agents_reads import run as compare_agents_reads
        compare_agents_reads(seed, go_request, snapshot, args.redis_url)
        from compare_core import run as compare_core
        compare_core(seed, go_request, snapshot)
        from compare_login import run
        run(base, seed, args.redis_url, schema + ":")
        if args.mesh_binary:
            from compare_mesh import run as compare_mesh
            compare_mesh(args.mesh_binary.resolve(strict=True), env, seed, go_request)
        compare_manager_reads()
        compare_write_flows()
        compare_monitoring_reads()
        compare_agent_monitoring()
        compare_patch_logs()
        compare_endpoint_management()
        compare_agent_metadata()
        compare_agent_callbacks()
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        with connection.cursor() as cursor:
            cursor.execute('SET search_path TO public')
            cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        connection.close()


if __name__ == "__main__":
    main()
