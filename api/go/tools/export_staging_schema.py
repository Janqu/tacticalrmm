#!/usr/bin/env python3
"""Offline Django-reference export for a fresh Go-only staging database.

Run locally with the Django virtualenv, after tacticalrmm-go-test is running:
  python tools/export_staging_schema.py --dsn \
    postgresql://postgres:trmm-test-only@127.0.0.1:55439/trmm_go_test

Only generated SQL is transferred to staging; no Python runtime is needed there.
The destination database must be empty. This is model-derived bootstrap schema,
not a Django migration-history export and not a production upgrade procedure.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import types
from urllib.parse import unquote, urlsplit
import uuid


def rewrite_schema(dump, schema):
    if not re.fullmatch(r"go_staging_export_[a-f0-9]{32}", schema):
        raise ValueError("Invalid export schema")
    declaration = f"CREATE SCHEMA {schema};"
    if dump.count(declaration) != 1:
        raise ValueError("Unexpected schema declaration in dump")
    dump = dump.replace(declaration, "CREATE SCHEMA IF NOT EXISTS public;")
    # pg_dump emits this generated ASCII identifier unquoted. Rewrite only
    # qualified SQL identifiers and schema metadata comments, never COPY values.
    output, copying = [], False
    for line in dump.splitlines(keepends=True):
        if copying:
            output.append(line)
            if line.rstrip("\r\n") == r"\.":
                copying = False
            continue

        # pg_dump 17 emits this setting; the fresh staging server is PG16.
        if line.rstrip("\r\n") == "SET transaction_timeout = 0;":
            continue
        line = re.sub(r"\b" + re.escape(schema) + r"\.", "public.", line)
        if line.startswith("--"):
            line = re.sub(r"\b" + re.escape(schema) + r"\b", "public", line)
        output.append(line)
        copying = line.startswith("COPY ") and line.rstrip().endswith("FROM stdin;")
    result = "".join(output)
    if schema in result:
        raise ValueError("Unmapped schema reference remains in dump")
    return result


def write_private(path, value):
    # Refuse overwrite, including symlinks, so a rerun cannot orphan credentials.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True)
    args = parser.parse_args()
    url = urlsplit(args.dsn)
    database = url.path.removeprefix("/")
    if (url.scheme not in {"postgres", "postgresql"}
            or url.hostname not in {"localhost", "127.0.0.1", "::1"}
            or url.port != 55439 or database != "trmm_go_test"
            or unquote(url.username or "") != "postgres" or url.query or url.fragment):
        parser.error("Use the isolated tacticalrmm-go-test database on loopback port 55439")
    output = Path("/private/tmp/trmm-go-staging-init.sql")
    credentials = Path("/private/tmp/trmm-staging-login.json")
    if any(path.exists() or path.is_symlink() for path in (output, credentials)):
        parser.error("Staging export output already exists; preserve/review it before starting a new export")

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root.parent / "tacticalrmm"))
    os.environ["GHACTIONS"] = "yes"
    os.environ["DJANGO_SETTINGS_MODULE"] = "tacticalrmm.settings"
    # Reference settings must not execute a developer's local secret/config file.
    sys.modules["tacticalrmm.local_settings"] = types.ModuleType("tacticalrmm.local_settings")
    from django.conf import settings
    settings.LOGGING_CONFIG = None
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    settings.DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql", "NAME": database,
        "USER": "postgres", "PASSWORD": unquote(url.password or ""),
        "HOST": url.hostname, "PORT": str(url.port),
    }}
    settings.ROOT_USER = "staging-admin"
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher"]
    import django
    django.setup()
    from django.apps import apps
    from django.db import connection
    from django.core.management.color import no_style
    from accounts.models import Role, User
    from clients.models import Client, Site
    from core.models import CoreSettings

    schema = "go_staging_export_" + uuid.uuid4().hex
    created = False
    written = []
    try:
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE SCHEMA "{schema}"')
            created = True
            cursor.execute(f'SET search_path TO "{schema}"')
        with connection.schema_editor() as editor:
            for model in apps.get_models():
                if model._meta.managed and not model._meta.proxy:
                    editor.create_model(model)

        password = secrets.token_urlsafe(30)
        admin = User(id=1, username="staging-admin", is_superuser=True, is_staff=True,
                     is_active=True, role_id=1, totp_key="")
        admin.set_password(password)
        if not admin.password.startswith("pbkdf2_sha256$") or not admin.check_password(password):
            raise RuntimeError("Expected a valid PBKDF2 credential")
        Role.objects.bulk_create([Role(id=1, name="Staging Administrator", is_superuser=True)])
        User.objects.bulk_create([admin])
        CoreSettings.objects.bulk_create([CoreSettings(
            id=1, default_time_zone="Europe/Berlin", agent_auto_update=False,
            sync_mesh_with_trmm=False, enable_server_scripts=False,
            smtp_host="", smtp_host_user="", smtp_host_password="", smtp_from_email="",
            email_alert_recipients=[], sms_alert_recipients=[],
            mesh_site="https://mesh2.q-dt.de", mesh_username="", mesh_token="",
        )])
        Client.objects.bulk_create([Client(id=1, name="Staging Test")])
        Site.objects.bulk_create([Site(id=1, name="Testlabor", client_id=1)])
        with connection.cursor() as cursor:
            for statement in connection.ops.sequence_reset_sql(no_style(), [Role, User, CoreSettings, Client, Site]):
                cursor.execute(statement)
            # Exactly five seed rows. No agents, tokens, schedules, channels or
            # production data can leak into this schema through an ORM hook.
            total = 0
            for model in apps.get_models():
                if model._meta.managed and not model._meta.proxy:
                    cursor.execute('SELECT count(*) FROM "' + model._meta.db_table.replace('"', '""') + '"')
                    total += cursor.fetchone()[0]
            if total != 5:
                raise RuntimeError("Unexpected rows in fresh staging schema")

        dumped = subprocess.run([
            "docker", "exec", "tacticalrmm-go-test", "pg_dump", "-U", "postgres",
            "-d", database, "--no-owner", "--no-acl", "--schema", schema,
        ], check=True, capture_output=True, text=True).stdout
        sql = "-- Fresh, model-derived Go staging database. Import into an EMPTY database only.\n"
        sql += rewrite_schema(dumped, schema)
        sql += "\nSET search_path TO public;\n"
        for migration in ("001_mesh_sync.sql", "002_script_note_completion.sql"):
            sql += "\n-- Go-owned extension: " + migration + "\n"
            sql += (root / "migrations" / migration).read_text()
        write_private(credentials, json.dumps({"username": admin.username, "password": password,
                                              "frontend": "https://rmm2.q-dt.de", "api": "https://api2.q-dt.de"}, indent=2) + "\n")
        written.append(credentials)
        write_private(output, sql)
        written.append(output)
        print("Exported fresh schema and five seed rows; credentials and SQL are mode 0600 in /private/tmp.")
    except Exception:
        for path in written:
            path.unlink()
        raise
    finally:
        if created:
            with connection.cursor() as cursor:
                cursor.execute("SET search_path TO public")
                cursor.execute(f'DROP SCHEMA "{schema}" CASCADE')
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # ORM/subprocess exceptions can include data. Never print a generated
        # password, password hash, connection parameters or SQL in the console.
        print("Staging export failed; no credentials or SQL values are printed.", file=sys.stderr)
        raise SystemExit(1)
