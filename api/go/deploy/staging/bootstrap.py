#!/usr/bin/env python3
"""Prepare isolated staging storage and units; never start services or migrate."""

import argparse
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile


BASE = Path("/opt/trmm-staging")
ENV = BASE / "staging.env"
ACCOUNT = "trmm-staging"
PSQL = "/usr/lib/postgresql/17/bin/psql"
FIXED = {
    "ROOT_USER": "staging-admin",
    "STAGING_MESH_USERNAME": "staging-admin",
    "NATS_USER": "tacticalrmm",
    "NATS_URL": "nats://127.0.0.1:4223",
    "LISTEN_ADDR": "127.0.0.1:18082",
    "CORS_ALLOWED_ORIGINS": "https://rmm2.q-dt.de",
    "SESSION_COOKIE_DOMAIN": "api2.q-dt.de",
    "REDIS_URL": "redis://127.0.0.1:6382/0",
    "DJANGO_SETTINGS_MODULE": "tacticalrmm.staging_settings",
    "NATS_CONNECT_HOST": "127.0.0.1",
    "NATS_STD_BIND_HOST": "127.0.0.1",
    "NATS_WS_BIND_HOST": "127.0.0.1",
}


def command(args, *, stdin=None):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, check=False, timeout=60)
    if result.returncode:
        # SQL and process diagnostics may contain credentials. Never echo them.
        raise RuntimeError("Command failed: " + Path(args[0]).name)
    return result.stdout.strip()


def sql(statement):
    return command([
        "sudo", "-u", "postgres", PSQL, "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
        "-h", "/var/run/postgresql", "-p", "5432", "-d", "postgres",
    ], stdin=statement + "\n")


def regular(path):
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_nlink != 1)):
        raise RuntimeError("Refusing non-regular file: " + str(path))


def write_file(path, content, gid, mode):
    regular(path)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def environment():
    regular(ENV)
    if ENV.exists():
        metadata = ENV.stat()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o027:
            raise RuntimeError("Existing staging.env has unsafe ownership or permissions")
        values = {}
        for line in ENV.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise RuntimeError("Invalid existing staging.env; refusing replacement")
            values[key] = value
        if set(values) != set(FIXED) | {"DJANGO_SECRET_KEY", "STAGING_DB_PASSWORD", "STAGING_MESH_TOKEN_KEY", "NATS_PASSWORD", "DATABASE_URL"}:
            raise RuntimeError("Unexpected existing staging.env keys; refusing replacement")
        for key, value in FIXED.items():
            if values[key] != value:
                raise RuntimeError("Existing staging.env is not isolated: " + key)
        for key, length in (("DJANGO_SECRET_KEY", 80), ("STAGING_DB_PASSWORD", 64), ("STAGING_MESH_TOKEN_KEY", 80)):
            if not re.fullmatch("[0-9a-f]{" + str(length) + "}", values[key]):
                raise RuntimeError("Invalid existing secret format: " + key)
        if values["NATS_PASSWORD"] != values["DJANGO_SECRET_KEY"] or values["DATABASE_URL"] != database_url(values["STAGING_DB_PASSWORD"]):
            raise RuntimeError("Existing staging credentials are inconsistent")
        return values
    secret, password = secrets.token_hex(40), secrets.token_hex(32)
    return dict(FIXED, DJANGO_SECRET_KEY=secret, STAGING_DB_PASSWORD=password,
                STAGING_MESH_TOKEN_KEY=secrets.token_hex(40), NATS_PASSWORD=secret,
                DATABASE_URL=database_url(password))


def database_url(password):
    return "postgres://trmm_staging:" + password + "@127.0.0.1:5432/trmm_staging?sslmode=disable"


def unit(description, executable, memory, *, directory=BASE, env=False, writable=()):
    settings = [
        "[Unit]", "Description=" + description, "After=network.target",
        "", "[Service]", "Type=simple", "User=" + ACCOUNT, "Group=" + ACCOUNT,
        "WorkingDirectory=" + str(directory), "ExecStart=" + executable,
        "Restart=on-failure", "RestartSec=5", "MemoryMax=" + memory,
        "UMask=0027", "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict",
        "ProtectHome=yes", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "IPAddressDeny=any", "IPAddressAllow=localhost",
    ]
    if env:
        settings.append("EnvironmentFile=" + str(ENV))
    if writable:
        settings.append("ReadWritePaths=" + " ".join(map(str, writable)))
    return "\n".join(settings + ["", "[Install]", "WantedBy=multi-user.target", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nats-binary", default="/usr/local/bin/nats-server")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Run as root on the staging host")
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.nats_binary):
        raise RuntimeError("NATS binary must be a plain absolute path")
    if BASE.is_symlink() or (BASE.exists() and not BASE.is_dir()):
        raise RuntimeError("Refusing invalid staging directory")
    values = environment()
    version = int(sql("SHOW server_version_num;"))
    if not 170000 <= version < 180000:
        raise RuntimeError("Expected PostgreSQL 17 on local port 5432")
    database_exists = sql("SELECT EXISTS(SELECT FROM pg_database WHERE datname='trmm_staging');") == "t"
    role_exists = sql("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname='trmm_staging');") == "t"
    if not ENV.exists() and (database_exists or role_exists):
        raise RuntimeError("Existing staging database/role without staging.env; refusing adoption")
    if role_exists and sql("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname='trmm_staging';") != "f":
        raise RuntimeError("Existing staging role has excessive privileges")
    if database_exists and sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='trmm_staging';") != "trmm_staging":
        raise RuntimeError("Existing staging database has unexpected owner")
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        command(["useradd", "--system", "--user-group", "--home-dir", str(BASE), "--no-create-home", "--shell", "/usr/sbin/nologin", ACCOUNT])
        account = pwd.getpwnam(ACCOUNT)
    if account.pw_uid == 0:
        raise RuntimeError("Staging account cannot be root")
    for relative in ("", "bin", "django", "frontend", "community-scripts", "private", "private/log", "private/exe", "redis"):
        directory = BASE / relative
        if directory.is_symlink():
            raise RuntimeError("Refusing symlink: " + str(directory))
        directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        writable = relative in ("private", "private/log", "private/exe", "redis")
        os.chown(directory, account.pw_uid if writable else 0, account.pw_gid)
        os.chmod(directory, 0o750)
    # Persist once before DB creation, allowing a safe retry after interruption.
    if not ENV.exists():
        write_file(ENV, "".join(key + "=" + value + "\n" for key, value in values.items()), account.pw_gid, 0o640)
    else:
        os.chown(ENV, 0, account.pw_gid)
        os.chmod(ENV, 0o640)
    if not role_exists:
        sql("CREATE ROLE trmm_staging LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + values["STAGING_DB_PASSWORD"] + "';")
    if not database_exists:
        sql("CREATE DATABASE trmm_staging OWNER trmm_staging;")
    sql("REVOKE CONNECT,TEMPORARY ON DATABASE trmm_staging FROM PUBLIC;")
    write_file(BASE / "redis.conf", "bind 127.0.0.1\nport 6382\nprotected-mode yes\ndaemonize no\nsupervised no\ndir /opt/trmm-staging/redis\nlogfile \"\"\nmaxmemory 32mb\nmaxmemory-policy noeviction\nsave \"\"\nappendonly no\n", account.pw_gid, 0o640)
    write_file(BASE / "nats.conf", 'host: "127.0.0.1"\nport: 4223\nhttp: "127.0.0.1:8223"\nwebsocket { host: "127.0.0.1", port: 9236, no_tls: true }\nauthorization { users: [{ user: "tacticalrmm", password: "' + values["NATS_PASSWORD"] + '" }] }\n', account.pw_gid, 0o640)
    units = {
        "go": unit("Tactical RMM isolated staging Go API", "/opt/trmm-staging/bin/trmm-go", "256M", env=True),
        "django": unit("Tactical RMM isolated staging Django API", "/rmm/api/env/bin/python -m uvicorn tacticalrmm.asgi:application --host 127.0.0.1 --port 18083 --workers 1", "384M", directory=BASE / "django", env=True, writable=[BASE / "private"]),
        "redis": unit("Tactical RMM isolated staging Redis", "/usr/bin/redis-server /opt/trmm-staging/redis.conf", "64M", writable=[BASE / "redis"]),
        "nats": unit("Tactical RMM isolated staging NATS", args.nats_binary + " -c /opt/trmm-staging/nats.conf", "96M"),
    }
    for name, content in units.items():
        write_file(Path("/etc/systemd/system") / ("trmm-staging-" + name + ".service"), content, 0, 0o644)
    print("Staging database, private configuration and four units prepared. No services started, enabled or migrated.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired):
        # Keep even unexpected OS/DB errors from leaking paths with credentials.
        print("Staging bootstrap failed; configuration was not printed. Review local prerequisites and isolated staging state.", file=sys.stderr)
        sys.exit(1)
