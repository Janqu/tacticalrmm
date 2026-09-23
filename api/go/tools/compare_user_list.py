"""Read-only user listing contracts against the installed Django/allauth stack."""

import hashlib
from datetime import datetime, timezone
from urllib.parse import quote


def run(seed, go_request, snapshot):
    from accounts.models import User
    from agents.models import Agent
    from allauth.socialaccount.models import SocialAccount, SocialApp
    from django.db import connection
    from rest_framework.test import APIClient

    def configure(kind):
        SocialApp.objects.all().delete()
        SocialAccount.objects.update(last_login=datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc), date_joined=datetime(2024, 1, 2, tzinfo=timezone.utc))
        if kind == "search":
            User.objects.filter(pk=2).update(username="Reader_%\\Ä")
        elif kind == "blocked":
            User.objects.filter(pk=2).update(block_dashboard_login=True)
        elif kind == "agent":
            Agent.objects.bulk_create([Agent(id=900001, agent_id="user-list-contract", hostname="listing-fixture", site_id=1)])
            User.objects.filter(pk=2).update(agent_id=900001)
        elif kind.startswith("social-"):
            name = kind.removeprefix("social-")
            provider = "unsupported" if name == "unsupported" else "openid_connect"
            app = SocialApp.objects.create(provider=provider, provider_id="company", name="Company Login", client_id="reference")
            account = SocialAccount.objects.get(user_id=7)
            account.provider = "company"
            account.extra_data = {
                "username": "  preferred  ", "email": "email@example.test", "name": "Name",
                "first_name": "First", "givenName": "Given", "last_name": "Last", "surname": "Family",
            }
            if name == "email":
                account.extra_data["username"] = 123
            elif name == "name":
                account.extra_data = {"first_name": "First", "givenName": "Given", "last_name": "Last", "surname": "Family"}
            elif name == "empty":
                account.extra_data = {}
            elif name == "array":
                account.extra_data = ["ignored"]
            elif name in {"ambiguous", "hidden", "all-hidden"}:
                app.settings = {"hidden": name != "ambiguous"}
                app.save()
                SocialApp.objects.create(provider=provider, provider_id="company", name="Visible Login", client_id="second", settings={"hidden": name == "all-hidden"})
            account.save(update_fields=["provider", "extra_data"])

    cases = [("base", "", user) for user in (1, 2, 3, 4, 5, 6)]
    cases += [("base", "?search=" + quote(value), 1) for value in ("ADMIN", "no-such-user", " ", "' OR 1=1 --")]
    cases += [("search", "?search=" + quote(value), 1) for value in ("%", "_", "\\", "ä", "READER")]
    cases += [("base", "?search=missing&search=admin", 1), ("blocked", "", 1), ("agent", "", 1)]
    cases += [("social-" + name, "", 1) for name in ("username", "email", "name", "empty", "array", "ambiguous", "hidden", "all-hidden", "unsupported")]
    cases = [(kind, query, user, "GET") for kind, query, user in cases]
    cases += [("base", "", user, "HEAD") for user in (1, 2, 3, 5, 6)]

    def reset():
        # This isolated fixture has no dependent agent objects. Remove it before
        # seed deletes sites (their agent foreign key uses RESTRICT).
        User.objects.filter(agent_id=900001).update(agent=None)
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM agents_agent WHERE id = %s AND agent_id = %s", [900001, "user-list-contract"])
        seed()

    try:
        for kind, query, user, method in cases:
            path = "/accounts/users/" + query
            reset()
            configure(kind)
            client = APIClient()
            token = hashlib.sha256(f"contract-user-{user}".encode()).hexdigest()
            client.credentials(HTTP_AUTHORIZATION="Token " + token)
            expected = getattr(client, method.lower())(path)
            expected_state = snapshot()
            reset()
            configure(kind)
            status, actual = go_request(method, path, user_id=user)
            expected_body = expected.json() if method != "HEAD" else None
            if isinstance(actual, list) and isinstance(expected_body, list):
                actual.sort(key=lambda row: row["id"])
                expected_body.sort(key=lambda row: row["id"])
            assert (status, actual) == (expected.status_code, expected_body), (kind, query, user, method, expected.status_code, expected_body, status, actual)
            assert snapshot() == expected_state, ("user list changed state", kind, query, user)
    finally:
        SocialApp.objects.all().delete()
    print(f"User listing contracts: {len(cases)} comparisons passed")
    return len(cases)
