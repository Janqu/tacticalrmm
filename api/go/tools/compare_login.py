"""Login contract checks, called inside compare_django's isolated schema."""

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor


def run(base, seed, redis_url, prefix):
    import pyotp
    import redis
    from django.conf import settings
    from django.contrib.auth.hashers import make_password, check_password
    from django.contrib.sessions.models import Session
    from django.contrib.sessions.backends.db import SessionStore
    from django.core.cache import cache
    from django.db import connection
    from rest_framework.test import APIClient
    from accounts.models import User
    from core.models import CoreSettings
    from knox.models import AuthToken
    from logs.models import AuditLog
    from tacticalrmm.middleware import request_local

    store = redis.Redis.from_url(redis_url)
    password = " valid password ä🔑 "
    encoded = make_password(password)
    secret = "JBSWY3DPEHPK3PXP"
    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)

    def clear_limits():
        cache.clear()
        keys = list(store.scan_iter(prefix + "*"))
        if keys:
            store.delete(*keys)

    def prepare(mode=None):
        clear_limits()
        seed()
        Session.objects.all().delete()
        CoreSettings.objects.all().delete()
        CoreSettings.objects.bulk_create([CoreSettings(id=1)])
        User.objects.update(password=encoded)
        if mode == "inactive":
            User.objects.filter(username="admin").update(is_active=False)
        if mode == "blocked":
            User.objects.filter(username="admin").update(block_dashboard_login=True)
        if mode == "local-block":
            CoreSettings.objects.update(block_local_user_logon=True)
        if mode == "upgrade":
            User.objects.filter(username="admin").update(password=make_password(password, hasher="pbkdf2_sha1"))
        if mode == "authenticated":
            return {"Authorization": "Token " + hashlib.sha256(b"contract-user-2").hexdigest()}
        if mode == "invalid-auth":
            return {"Authorization": "Token invalid"}
        if mode == "forwarded":
            return {"X-Forwarded-For": "8.8.8.8, 10.0.0.1"}
        if mode in {"same-session", "custom-expiry", "browser-session", "anonymous-session", "other-session", "tampered-session"}:
            user = User.objects.get(username="admin" if mode in {"same-session", "custom-expiry", "browser-session"} else "reader")
            data = {"label": "München 🔑"}
            if mode in {"custom-expiry", "browser-session"}:
                data["_session_expiry"] = 3600 if mode == "custom-expiry" else 0
            if mode != "anonymous-session":
                data |= {"_auth_user_id": str(user.pk), "_auth_user_backend": "django.contrib.auth.backends.ModelBackend", "_auth_user_hash": user.get_session_auth_hash()}
            signed = SessionStore().encode(data)
            if mode == "tampered-session":
                signed += "x"
            Session.objects.create(session_key="s" * 32, session_data=signed, expire_date=datetime.now(timezone.utc) + timedelta(days=14))
            return {"Cookie": "sessionid=" + "s" * 32}
        return {}

    def request(kind, path, body, headers=None):
        headers = headers or {}
        data = json.dumps(body).encode()
        if kind == "django":
            request_local.username = None
            request_local.debug_info = {}
            response = APIClient().generic("POST", path, data=data, content_type="application/json", **{"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()})
            return response.status_code, json.loads(response.content), dict(response.items()), response.cookies
        req = urllib.request.Request(base + path, data=data, headers=headers | {"Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            cookies = SimpleCookie()
            for line in response.headers.get_all("Set-Cookie", []):
                cookies.load(line)
            return response.status, json.loads(response.read()), dict(response.headers.items()), cookies

    def timestamp(value):
        if value is None or value == fixed:
            return value
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if value == fixed:
                return value
        assert abs((value - datetime.now(timezone.utc)).total_seconds()) < 15, value
        return "now"

    def result(response, setup=False, mode=None):
        status, body, headers, cookies = response
        headers = {k.lower(): v for k, v in headers.items()}
        sessions = []
        for session in Session.objects.order_by("session_key"):
            data = SessionStore().decode(session.session_data)
            assert data, "Django cannot decode signed Go session"
            user = User.objects.get(pk=data["_auth_user_id"])
            assert data["_auth_user_hash"] == user.get_session_auth_hash(), "session auth hash mismatch"
            assert data["_auth_user_backend"] == "django.contrib.auth.backends.ModelBackend"
            assert abs((session.expire_date - datetime.now(timezone.utc)).total_seconds() - (3600 if mode == "custom-expiry" else 1209600)) < 15
            if mode in {"same-session", "custom-expiry", "browser-session"}:
                assert session.session_key == "s" * 32
            else:
                assert session.session_key != "s" * 32
            assert re.fullmatch("[a-z0-9]{32}", session.session_key)
            sessions.append(data)
        if isinstance(body, dict) and "token" in body:
            token = body["token"]
            assert re.fullmatch("[a-f0-9]{64}", token)
            digest = hashlib.sha512(bytes.fromhex(token)).hexdigest()
            row = AuthToken.objects.get(digest=digest)
            assert row.token_key == token[:8]
            assert row.expiry.isoformat().replace("+00:00", "Z") == body["expiry"]
            assert abs((row.expiry-row.created).total_seconds() - (180 if setup else 18000)) < 1
            assert abs((row.created-datetime.now(timezone.utc)).total_seconds()) < 15
            assert len(sessions) == 1 and sessions[0]["_auth_user_id"] == str(row.user_id)
            assert cookies["sessionid"].value == Session.objects.get().session_key
            assert re.fullmatch("[a-zA-Z0-9]{32}", cookies["csrftoken"].value)
            body = body | {"token": "verified token", "expiry": "verified expiry"}
        cookie_attrs = {}
        for key, cookie in cookies.items():
            cookie_attrs[key] = {k: v for k, v in cookie.items() if k != "expires"}
            assert bool(cookie["expires"]) == (key != "sessionid" or mode != "browser-session")
            cookie_attrs[key]["samesite"] = cookie_attrs[key]["samesite"].lower()
            cookie_attrs[key]["max-age"] = str(cookie_attrs[key]["max-age"])
        audits = list(AuditLog.objects.order_by("id").values())
        for entry in audits:
            del entry["id"]
            entry["entry_time"] = timestamp(entry["entry_time"])
            for value in (entry["before_value"], entry["after_value"]):
                if value and value.get("last_login"):
                    value["last_login"] = timestamp(value["last_login"])
        users = list(User.objects.order_by("id").values("id", "last_login", "last_login_ip", "modified_time", "created_by", "modified_by", "password"))
        for user in users:
            for field in ("last_login", "modified_time"):
                user[field] = timestamp(user[field])
            assert check_password(password, user["password"])
            user["password"] = user["password"].split("$", 2)[:2]
        for session in sessions:
            session["_auth_user_hash"] = "verified auth hash"
        return status, body, cookie_attrs, sessions, users, audits, headers.get("www-authenticate"), AuthToken.objects.count()

    check, login = "/v2/checkcreds/", "/v2/login/"
    good = {"username": "admin", "password": password, "twofactor": pyotp.TOTP(secret).now()}
    cases = [
        ("check requires TOTP", check, good, None),
        ("check setup token", check, good | {"username": "no-role"}, None),
        ("check wrong password", check, good | {"password": "wrong"}, None),
        ("check unknown user", check, good | {"username": "unknown"}, None),
        ("check inactive", check, good, "inactive"),
        ("check blocked", check, good, "blocked"),
        ("check SSO denied", check, good | {"username": "sso"}, None),
        ("check local block", check, good | {"username": "reader"}, "local-block"),
        ("root bypasses local block", check, good, "local-block"),
        ("password hash upgraded", check, good, "upgrade"),
        ("full login", login, good, None),
        ("login with existing auth", login, good, "authenticated"),
        ("login with invalid auth", login, good, "invalid-auth"),
        ("login proxy address", login, good, "forwarded"),
        ("login wrong password", login, good | {"password": "wrong"}, None),
        ("login bad TOTP", login, good | {"twofactor": "bad"}, None),
        ("login missing credentials", login, {}, None),
        ("login blank credentials", login, {"username": " ", "password": ""}, None),
        ("login null credentials", login, {"username": None, "password": None}, None),
        ("login inactive", login, good, "inactive"),
        ("login blocked", login, good, "blocked"),
        ("login local block", login, good | {"username": "reader"}, "local-block"),
        ("login SSO denied", login, good | {"username": "sso"}, None),
        ("reuse signed session", login, good, "same-session"),
        ("custom session expiry", login, good, "custom-expiry"),
        ("browser session expiry", login, good, "browser-session"),
        ("rotate anonymous session", login, good, "anonymous-session"),
        ("flush other user's session", login, good, "other-session"),
        ("reject tampered session", login, good, "tampered-session"),
    ]
    for label, path, body, mode in cases:
        headers = prepare(mode)
        expected = result(request("django", path, body, headers), path == check, mode)
        headers = prepare(mode)
        actual = result(request("go", path, body, headers), path == check, mode)
        assert actual == expected, (label, actual, expected)
        print("PASS", label)

    for kind in ("django", "go"):
        prepare()
        replies = [request(kind, check, good) for _ in range(11)]
        assert [r[0] for r in replies] == [200]*10 + [429], (kind, replies[-1])
        retry = {k.lower(): v for k, v in replies[-1][2].items()}["retry-after"]
        assert 50 <= int(retry) <= 60, ("minute Retry-After", kind, retry, replies[-1])
        assert request(kind, login, good)[0] == 200, "login and check scopes must be independent"
    print("PASS login minute throttles and independent scopes")
    identity = hashlib.sha256(b"127.0.0.1").hexdigest()
    throttle_key = prefix + "{check_creds:" + identity + "}"
    for kind in ("django", "go"):
        prepare()
        if kind == "django":
            now = time.time()
            cache.set("throttle_check_creds_day_127.0.0.1", [now] * 300, 86400)
        else:
            # The Lua limiter uses Redis TIME, which can differ from the host
            # clock (Docker VM drift, even <1s, can otherwise ceil to 86401).
            seconds, microseconds = store.time()
            now = seconds + microseconds / 1_000_000
            store.rpush(throttle_key + ":day", *([str(now)] * 300))
            store.expire(throttle_key + ":day", 86400)
        reply = request(kind, check, good)
        assert reply[0] == 429, (kind, reply)
        retry = {k.lower(): v for k, v in reply[2].items()}["retry-after"]
        assert 86390 <= int(retry) <= 86400, ("daily Retry-After", kind, retry, "seed_time", now, reply)
    print("PASS login daily throttle")
    prepare()
    store.set(throttle_key + ":min", "wrong cache type")
    assert request("go", check, good)[0] == 503, "cache failure must fail closed"
    print("PASS login cache failure is closed")
    prepare()
    with ThreadPoolExecutor(max_workers=16) as executor:
        replies = list(executor.map(lambda _: request("go", check, good), range(16)))
    assert sorted(r[0] for r in replies) == [200]*10 + [429]*6
    print("PASS atomic concurrent login throttle")

    prepare()
    baseline_tokens = AuthToken.objects.count()
    with connection.cursor() as cursor:
        cursor.execute("""CREATE FUNCTION reject_login_audit() RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN RAISE EXCEPTION 'injected login failure'; END $$;
          CREATE TRIGGER reject_login_audit BEFORE INSERT ON logs_auditlog
          FOR EACH ROW EXECUTE FUNCTION reject_login_audit();""")
    try:
        response = request("go", login, good)
        assert response[0] == 500 and not response[3]
        assert not Session.objects.exists() and AuthToken.objects.count() == baseline_tokens
        assert User.objects.get(pk=1).last_login == fixed
    finally:
        with connection.cursor() as cursor:
            cursor.execute("DROP TRIGGER reject_login_audit ON logs_auditlog")
            cursor.execute("DROP FUNCTION reject_login_audit()")
    clear_limits()
    store.close()
    print(f"PASS login rollback; {len(cases)} Django/Go login contract cases passed")
