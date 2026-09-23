"""Script-library read parity, run inside compare_django's isolated schema."""

import hashlib
import json


def run(seed, go_request, snapshot):
    from accounts.models import Role
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from scripts.models import Script

    def setup(permission):
        seed()
        Script.objects.all().delete()
        Script.objects.bulk_create([
            Script(id=31, name="Visible ü", category="Alpha", script_body="{{snippet}}\n",
                   script_hash="stored-hash", args=["a", None, ""], env_vars=["KEY=x=y"]),
            Script(id=32, name="Community", category="Beta", script_type="builtin",
                   args=None, supported_platforms=None, env_vars=None, description=None),
            Script(id=33, name="Hidden", category="Gamma", hidden=True,
                   script_body="secret body", run_as_user=True, favorite=True),
            Script(id=34, name="Hidden community", category=None, hidden=True,
                   script_type="builtin", supported_platforms=["windows", "linux"]),
        ])
        Role.objects.filter(pk=1).update(
            can_list_scripts=permission == "read", can_manage_scripts=permission == "manage")
        cache.clear()

    count = 0
    paths = ["/scripts/", "/scripts/31/", "/scripts/32/", "/scripts/33/",
             "/scripts/999/", "/scripts/0/", "/scripts/00031/"]
    queries = ["", "showCommunityScripts=false", "showCommunityScripts=",
               "showCommunityScripts=False", "showHiddenScripts=true",
               "showHiddenScripts=True", "showHiddenScripts=",
               "showCommunityScripts=false&showHiddenScripts=true",
               "showCommunityScripts=true&showCommunityScripts=false",
               "showCommunityScripts=false&showCommunityScripts=true",
               "showHiddenScripts=true&showHiddenScripts=false",
               "showHiddenScripts=false&showHiddenScripts=true"]
    cases = [(method, path, user, permission)
             for method in ["GET", "HEAD"]
             for path in paths
             for user, permission in [(1, "none"), (5, "none"), (2, "read"),
                                      (2, "manage"), (2, "none"), (3, "none"),
                                      (4, "none"), (6, "none")]]
    cases += [("GET", "/scripts/?" + query, 2, "read") for query in queries]

    try:
        for method, path, user, permission in cases:
            setup(permission)
            client = APIClient()
            token = hashlib.sha256(f"contract-user-{user}".encode()).hexdigest()
            client.credentials(HTTP_AUTHORIZATION="Token " + token)
            response = client.generic(method, path)
            expected = (response.status_code, json.loads(response.content) if response.content else None)
            # Script audit timestamps are recreated by setup; compare each
            # request to its own baseline rather than comparing those clocks.
            expected_state = snapshot()
            setup(permission)
            before = list(Script.objects.order_by("id").values())
            actual = go_request(method, path, user_id=user)
            assert actual == expected, (method, path, user, permission, expected, actual)
            assert snapshot() == expected_state, (method, path, "unexpected state change")
            assert list(Script.objects.order_by("id").values()) == before
            count += 1
        print(f"Script read contracts: {count} comparisons passed")
        return count
    finally:
        Script.objects.all().delete()
        seed()
