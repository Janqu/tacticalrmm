#!/usr/bin/env python3
"""Prepare the dedicated pure-Go test LXC. No Django runtime or production data."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile

SOURCE = Path('/root/trmm-setup')
BASE = Path('/opt/trmm')
ENV = Path('/etc/trmm-staging.env')
STAMP = Path('/etc/trmm-staging-schema.sha256')
PSQL = '/usr/lib/postgresql/16/bin/psql'


def run(args, data=None):
    p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=180)
    if p.returncode:
        raise RuntimeError('Command failed: ' + Path(args[0]).name)
    return p.stdout.strip()


def sql(text, database='postgres', atomic=False):
    args = ['runuser', '-u', 'postgres', '--', PSQL, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h', '/var/run/postgresql', '-p', '5432', '-d', database]
    if atomic:
        args.append('--single-transaction')
    return run(args, text)


def write(path, text, mode=0o640, gid=0):
    if path.is_symlink():
        raise RuntimeError('Refusing symlink')
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), mode)
            os.fchown(f.fileno(), 0, gid)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Requires root inside the dedicated LXC')
    if run(['systemd-detect-virt', '--container']) != 'lxc':
        raise RuntimeError('Requires the dedicated LXC')
    for name in ('trmm-go-staging-init.sql', 'trmm-staging-login.json', 'trmm-staging-go-api', 'trmm-staging-frontend.tar.gz'):
        if not (SOURCE / name).is_file() or (SOURCE / name).is_symlink():
            raise RuntimeError('Missing regular setup input')
    login = json.loads((SOURCE / 'trmm-staging-login.json').read_text())
    if not isinstance(login, dict):
        raise RuntimeError('Invalid supplied login file')
    if not 160000 <= int(sql('SHOW server_version_num;')) < 170000:
        raise RuntimeError('Requires PostgreSQL 16')
    exists = sql("SELECT EXISTS(SELECT FROM pg_database WHERE datname='trmm_staging');") == 't'
    role = sql("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname='trmm_staging');") == 't'
    if not ENV.exists() and (exists or role):
        raise RuntimeError('Refusing database or role without existing staging secrets')
    if ENV.is_symlink():
        raise RuntimeError('Refusing environment symlink')
    if ENV.exists():
        if ENV.stat().st_uid != 0 or ENV.stat().st_mode & 0o027:
            raise RuntimeError('Unsafe environment permissions')
        env = dict(line.split('=', 1) for line in ENV.read_text().splitlines() if line and not line.startswith('#'))
    else:
        secret, password = secrets.token_hex(40), secrets.token_hex(32)
        env = {
            'DATABASE_URL': 'postgres://trmm_staging:' + password + '@127.0.0.1:5432/trmm_staging?sslmode=disable',
            'STAGING_DB_PASSWORD': password, 'DJANGO_SECRET_KEY': secret,
            'ROOT_USER': 'staging-admin', 'LISTEN_ADDR': '127.0.0.1:18082',
            'REDIS_URL': 'redis://127.0.0.1:6379/0', 'NATS_URL': 'nats://127.0.0.1:4222',
            'NATS_USER': 'tacticalrmm', 'NATS_PASSWORD': secret,
            'CORS_ALLOWED_ORIGINS': 'https://rmm2.q-dt.de', 'SESSION_COOKIE_DOMAIN': 'api2.q-dt.de',
            'STAGING_MESH_TOKEN_KEY': secrets.token_hex(40),
        }
    expected = 'postgres://trmm_staging:' + env.get('STAGING_DB_PASSWORD', '') + '@127.0.0.1:5432/trmm_staging?sslmode=disable'
    if env.get('DATABASE_URL') != expected or env.get('LISTEN_ADDR') != '127.0.0.1:18082' or env.get('NATS_URL') != 'nats://127.0.0.1:4222' or env.get('REDIS_URL') != 'redis://127.0.0.1:6379/0':
        raise RuntimeError('Existing environment is not isolated')
    for name in ('STAGING_DB_PASSWORD', 'DJANGO_SECRET_KEY', 'STAGING_MESH_TOKEN_KEY'):
        if len(env.get(name, '')) < 64 or any(c not in '0123456789abcdef' for c in env[name]):
            raise RuntimeError('Invalid secret format')
    if env.get('NATS_PASSWORD') != env['DJANGO_SECRET_KEY'] or env.get('NATS_USER') != 'tacticalrmm':
        raise RuntimeError('Invalid NATS credentials')
    if role and sql("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname='trmm_staging';") != 'f':
        raise RuntimeError('Staging role has excessive privileges')
    if exists and sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='trmm_staging';") != 'trmm_staging':
        raise RuntimeError('Wrong database owner')
    try:
        account = pwd.getpwnam('trmm')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--home-dir', str(BASE), '--no-create-home', '--shell', '/usr/sbin/nologin', 'trmm'])
        account = pwd.getpwnam('trmm')
    if account.pw_uid == 0:
        raise RuntimeError('Invalid runtime user')
    for item in ('', 'bin', 'frontend', 'mesh', 'mesh-data', 'mesh-files'):
        directory = BASE / item
        if directory.is_symlink():
            raise RuntimeError('Refusing directory symlink')
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, account.pw_uid if item.startswith('mesh') else 0, account.pw_gid)
        os.chmod(directory, 0o750 if item.startswith('mesh') else 0o755)
    if not ENV.exists():
        write(ENV, ''.join(k + '=' + v + '\n' for k, v in env.items()), gid=account.pw_gid)
    credentials = Path('/root/trmm-staging-login.json')
    if not credentials.exists():
        # Preserve the provided Go login exactly; keep separate Mesh credentials.
        write(credentials, (SOURCE / 'trmm-staging-login.json').read_text(), mode=0o600)
    mesh_credentials = Path('/root/trmm-staging-mesh.json')
    if not mesh_credentials.exists():
        write(mesh_credentials, json.dumps({'username': 'staging-admin', 'password': secrets.token_urlsafe(32), 'token_key': env['STAGING_MESH_TOKEN_KEY']}) + '\n', mode=0o600)
    if not role:
        sql("CREATE ROLE trmm_staging LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + env['STAGING_DB_PASSWORD'] + "';")
    if not exists:
        sql('CREATE DATABASE trmm_staging OWNER trmm_staging;')
    sql('REVOKE CONNECT,TEMPORARY ON DATABASE trmm_staging FROM PUBLIC;')
    schema = (SOURCE / 'trmm-go-staging-init.sql').read_text()
    digest = hashlib.sha256(schema.encode()).hexdigest()
    tables = int(sql("SELECT count(*) FROM pg_tables WHERE schemaname='public';", 'trmm_staging'))
    if tables == 0:
        if STAMP.exists():
            raise RuntimeError('Schema marker exists but database is empty')
        sql('SET ROLE trmm_staging;\n' + schema, 'trmm_staging', atomic=True)
        if int(sql("SELECT count(*) FROM pg_tables WHERE schemaname='public';", 'trmm_staging')) == 0:
            raise RuntimeError('Schema import created no tables')
        write(STAMP, digest + '\n', mode=0o600)
    elif not STAMP.is_file() or STAMP.read_text().strip() != digest:
        raise RuntimeError('Populated or partial database without matching schema marker; refusing import')
    shutil.copyfile(SOURCE / 'trmm-staging-go-api', BASE / 'bin/trmm-go')
    os.chown(BASE / 'bin/trmm-go', 0, account.pw_gid)
    os.chmod(BASE / 'bin/trmm-go', 0o755)
    with tarfile.open(SOURCE / 'trmm-staging-frontend.tar.gz') as archive:
        for member in archive.getmembers():
            p = Path(member.name)
            if p.is_absolute() or '..' in p.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError('Unsafe frontend archive member')
        archive.extractall(BASE / 'frontend', filter='data')
    index = list((BASE / 'frontend').rglob('index.html'))
    if len(index) != 1:
        raise RuntimeError('Expected one frontend index.html')
    write(index[0].parent / 'env-config.js', 'window._env_ = {PROD_URL: "https://api2.q-dt.de"};\n', mode=0o644)
    for path in (BASE / 'frontend').rglob('*'):
        os.chown(path, 0, account.pw_gid)
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    write(Path('/etc/nats-server.conf'), 'host: "127.0.0.1"\nport: 4222\nhttp: "127.0.0.1:8222"\nwebsocket { host: "127.0.0.1", port: 9236, no_tls: true }\nauthorization { users: [{ user: "tacticalrmm", password: "' + env['NATS_PASSWORD'] + '" }] }\n', gid=pwd.getpwnam('nats').pw_gid)
    write(Path('/etc/systemd/system/trmm-go.service'), '[Unit]\nDescription=Isolated pure Go RMM test API\nAfter=network.target postgresql.service redis-server.service nats-server.service\n\n[Service]\nUser=trmm\nGroup=trmm\nWorkingDirectory=/opt/trmm\nEnvironmentFile=/etc/trmm-staging.env\nExecStart=/opt/trmm/bin/trmm-go\nRestart=on-failure\nRestartSec=5\nMemoryMax=512M\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\nUMask=0027\n\n[Install]\nWantedBy=multi-user.target\n', mode=0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', 'nats-server.service'])
    run(['systemctl', 'start', 'trmm-go.service'])
    run(['systemctl', 'is-active', '--quiet', 'nats-server.service', 'trmm-go.service'])
    print('Pure Go LXC setup complete. Go and NATS active; nginx and Mesh were not started. Credentials remain root-only.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired, tarfile.TarError):
        print('Isolated LXC setup failed. No credentials or database diagnostics printed.', file=sys.stderr)
        sys.exit(1)
