"""Client/site read contracts against actual Django models and permissions."""

import hashlib
import json


def normalize_custom_fields(value):
    # Neither custom-value model has Meta.ordering, and Django's prefetch and
    # select_related queries can return different PostgreSQL join-plan orders.
    # Client/site name ordering remains part of the contract and is untouched.
    if isinstance(value, dict):
        return {
            key: sorted(item, key=lambda field: field["id"])
            if key == "custom_fields" else normalize_custom_fields(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_custom_fields(item) for item in value]
    return value


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from clients.models import Client, Site, ClientCustomField, SiteCustomField
    from core.models import CustomField
    from django.core.cache import cache
    from rest_framework.test import APIClient

    def setup(scope):
        Agent.objects.all().delete()
        seed()
        CustomField.objects.filter(name__startswith="go-client-site-contract-").delete()
        Client.objects.bulk_create([
            Client(id=21, name="Alpha", block_policy_inheritance=True,
                   failing_checks={"error": True, "warning": False}),
            Client(id=22, name="Zulu"),
        ])
        Site.objects.bulk_create([
            Site(id=21, name="A site", client_id=21),
            Site(id=22, name="Z site", client_id=21),
            Site(id=23, name="Empty", client_id=22),
        ])
        Agent.objects.bulk_create([
            Agent(id=21, agent_id="client-site-1", hostname="one", site_id=21),
            Agent(id=22, agent_id="client-site-2", hostname="two", site_id=22,
                  maintenance_mode=True),
        ])
        fields = CustomField.objects.bulk_create([
            CustomField(id=21+i, name="go-client-site-contract-"+kind,
                        model="client", type=kind)
            for i, kind in enumerate(["text", "checkbox", "multiple"])
        ])
        for model, owner in [(ClientCustomField, {"client_id": 21}),
                             (SiteCustomField, {"site_id": 21})]:
            model.objects.bulk_create([
                model(id=21, field=fields[0], string_value="Grüße", **owner),
                model(id=22, field=fields[1], bool_value=True, **owner),
                model(id=23, field=fields[2], multiple_value=["a", None, "b"], **owner),
                model(id=24, field=fields[0], string_value=None, **owner),
                model(id=25, field=fields[2], multiple_value=None, **owner),
                model(id=26, field=fields[2], multiple_value=[], **owner),
            ])
        Role.objects.filter(pk=1).update(can_list_clients=True, can_list_sites=True)
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client", "combined"}:
            role.can_view_clients.add(1)
        if scope in {"site", "combined"}:
            role.can_view_sites.add(21)
        if scope == "denied":
            Role.objects.filter(pk=1).update(can_list_clients=False, can_list_sites=False)
        if scope == "head":
            Role.objects.filter(pk=1).update(can_manage_clients=True, can_manage_sites=True,
                                            can_list_clients=False, can_list_sites=False)
            role.can_view_clients.add(1)
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    count = 0
    paths = ["/clients/", "/clients/21/", "/clients/22/", "/clients/999/",
             "/clients/sites/", "/clients/sites/21/", "/clients/sites/22/",
             "/clients/sites/23/", "/clients/sites/999/"]
    try:
        for scope, user_id in [("unscoped", 1), ("unscoped", 5), ("unscoped", 2),
                               ("client", 2), ("site", 2), ("combined", 2),
                               ("denied", 2), ("unscoped", 3), ("unscoped", 4),
                               ("installer", 6), ("head", 2)]:
            for path in paths:
                method = "HEAD" if scope == "head" else "GET"
                setup(scope)
                client = APIClient()
                token = hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest()
                client.credentials(HTTP_AUTHORIZATION="Token " + token)
                response = client.generic(method, path)
                expected = (response.status_code, json.loads(response.content) if response.content else None)
                expected_state = snapshot()
                setup(scope)
                actual = go_request(method, path, user_id=user_id)
                assert (actual[0], normalize_custom_fields(actual[1])) == (
                    expected[0], normalize_custom_fields(expected[1])
                ), (scope, user_id, method, path, expected, actual)
                assert snapshot() == expected_state, (scope, path, "unexpected database change")
                count += 1
        print(f"Client/site contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        CustomField.objects.filter(name__startswith="go-client-site-contract-").delete()
        seed()
