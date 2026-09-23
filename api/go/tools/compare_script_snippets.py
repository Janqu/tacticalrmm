"""Script snippet CRUD parity; use compare_django's isolated schema runner."""
import hashlib
import json


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from django.core.cache import cache
    from django.core.management.color import no_style
    from django.db import connection
    from rest_framework.test import APIClient
    from scripts.models import ScriptSnippet

    def setup(scope):
        ScriptSnippet.objects.all().delete()
        seed()
        ScriptSnippet.objects.bulk_create([
            ScriptSnippet(id=41, name="Zulu", desc="Existing", code="  Write-Host hi\n"),
            ScriptSnippet(id=42, name="Alpha", shell="python", code="print('Grüße')\n"),
        ])
        with connection.cursor() as cursor:
            for sql in connection.ops.sequence_reset_sql(no_style(), [ScriptSnippet]):
                cursor.execute(sql)
        Role.objects.filter(pk=1).update(can_list_scripts=scope in {"reader", "all"},
                                        can_manage_scripts=scope in {"manager", "all"})
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
            Role.objects.filter(pk=1).update(can_list_scripts=True, can_manage_scripts=True)
        cache.clear()

    def state():
        return snapshot(), list(ScriptSnippet.objects.order_by("id").values())

    base = "/scripts/snippets/"
    detail = base + "41/"
    cases = [("GET", base, None), ("GET", detail, None),
             ("GET", base + "999/", None), ("HEAD", base, None),
             ("HEAD", detail, None), ("POST", base, {"name": "Created"}),
             ("PUT", detail, {"desc": "Changed"}), ("DELETE", detail, None)]
    count = 0

    def compare(scope, user_id, method, path, data):
        setup(scope)
        client = APIClient()
        token = hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest()
        client.credentials(HTTP_AUTHORIZATION="Token " + token)
        response = client.generic(method, path, data=json.dumps(data) if data is not None else "",
                                  content_type="application/json")
        expected = (response.status_code, json.loads(response.content) if response.content else None)
        if method in {"POST", "PUT", "DELETE"} and scope in {"reader", "manager"}:
            assert response.status_code == (403 if scope == "reader" else 200), (
                "Django snippet write permission contract", scope, method, response.status_code)
        expected_state = state()
        setup(scope)
        actual = go_request(method, path, data, user_id=user_id)
        assert actual == expected, (scope, user_id, method, path, data, expected, actual)
        assert state() == expected_state, (scope, method, path, data, "database/audit mismatch", expected_state, state())

    try:
        for scope, user_id in [("all", 1), ("all", 5), ("reader", 2), ("manager", 2),
                               ("all", 2), ("denied", 2), ("all", 3), ("all", 4),
                               ("installer", 6)]:
            for method, path, data in cases:
                compare(scope, user_id, method, path, data)
                count += 1
        writes = [
            ("POST", base, {}), ("POST", base, {"name": "Zulu"}),
            ("POST", base, {"name": "new", "desc": "  description  ", "code": "  echo hi\n", "shell": "shell"}),
            ("POST", base, {"name": "   ", "code": "", "shell": "invalid", "desc": None}),
            ("POST", base, {"name": None, "code": None, "shell": None}),
            ("POST", base, {"name": 23, "desc": 12, "code": 45}),
            ("POST", base, {"name": "a" * 41, "desc": "ä" * 51}),
            ("POST", base, {"name": "new", "code": "\t   \n"}),
            ("POST", base, {"name": "new", "code": "bad\x00code"}),
            ("POST", base, {"name": "new", "code": False, "shell": True}),
            ("POST", base, {"name": "new", "id": 41, "created_by": "spoof", "extra": "ignored"}),
            ("POST", base, ["not a dictionary"]),
            ("PUT", detail, {}), ("PUT", detail, {"name": "Zulu"}),
            ("PUT", detail, {"name": "Alpha"}),
            ("PUT", detail, {"code": "\n  unchanged indentation\n", "desc": ""}),
            ("PUT", detail, {"id": 42, "unknown": True}),
            ("PUT", detail, {"name": "", "code": ""}),
            ("PUT", base + "999/", {"name": ""}),
            ("DELETE", base + "999/", None),
        ] + [("PUT", detail, {"shell": shell}) for shell in ["powershell", "cmd", "python", "shell", "nushell", "deno", " shell "]]
        for method, path, data in writes:
            compare("all", 1, method, path, data)
            count += 1
        print(f"Script snippet contracts: {count} comparisons passed")
        return count
    finally:
        ScriptSnippet.objects.all().delete()
        seed()
