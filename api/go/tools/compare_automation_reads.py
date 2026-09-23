"""Automation read parity against real Django serializers and role scopes.

Invoked by compare_django.py inside its disposable PostgreSQL schema.
"""
import hashlib
import json


def normalize_unordered(value):
    # Agent has no Meta.ordering: PostgreSQL join order is not an API contract.
    # Preserve ordered client/site relations, only canonicalize agent sets.
    if isinstance(value, dict):
        return {k: sorted(normalize_unordered(v), key=lambda x: x["id"] if isinstance(x, dict) else x)
                if k in {"excluded_agents", "agents", "winupdatepolicy"} and isinstance(v, list)
                else normalize_unordered(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_unordered(v) for v in value]
    return value


def run(seed, go_request, snapshot):
    from accounts.models import Role, User
    from agents.models import Agent
    from alerts.models import AlertTemplate
    from automation.models import Policy
    from clients.models import Client, Site
    from core.models import CoreSettings
    from django.core.cache import cache
    from rest_framework.test import APIClient
    from winupdate.models import WinUpdatePolicy

    def setup(scope, defaults):
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        AlertTemplate.objects.all().delete()
        seed()
        AlertTemplate.objects.bulk_create([AlertTemplate(id=41, name="Automation template")])
        Policy.objects.bulk_create([
            Policy(id=41, name="Shared", active=True, desc="Grüße", alert_template_id=41),
            Policy(id=42, name="Inactive", enforced=True),
            Policy(id=43, name="No assignments"),
        ])
        Client.objects.bulk_create([
            Client(id=41, name="Alpha", server_policy_id=41),
            Client(id=42, name="Beta", workstation_policy_id=41, block_policy_inheritance=True),
            Client(id=43, name="Gamma"),
        ])
        Site.objects.bulk_create([
            Site(id=41, name="A", client_id=41, workstation_policy_id=41),
            Site(id=42, name="B", client_id=41, server_policy_id=41, block_policy_inheritance=True),
            Site(id=43, name="C", client_id=42),
            Site(id=44, name="D", client_id=43, server_policy_id=41, block_policy_inheritance=True),
            Site(id=45, name="E", client_id=43),
        ])
        Agent.objects.bulk_create([
            Agent(id=41+i, agent_id=f"automation-contract-{i:04d}", hostname=f"host-{i}",
                  site_id=site, monitoring_type=kind, policy_id=direct,
                  block_policy_inheritance=blocked)
            for i, (site, kind, direct, blocked) in enumerate([
                (41, "server", None, False), (41, "workstation", None, False),
                (42, "server", 41, True), (42, "workstation", None, False),
                (43, "server", None, False), (44, "workstation", None, False),
                (45, "server", 41, False), (45, "workstation", 42, True),
                (41, "server", 41, False), (43, "server", 41, False),
            ])
        ])
        Agent.objects.filter(pk=49).update(hostname="Zulu")
        Agent.objects.filter(pk=50).update(hostname="Alpha")
        policy = Policy.objects.get(pk=41)
        policy.excluded_agents.add(49, 50)
        policy.excluded_sites.add(41)
        policy.excluded_clients.add(42)
        # Excluded site 41 remains included through explicit client inheritance:
        # preserve the current Django contract rather than "fixing" it in Go.
        WinUpdatePolicy.objects.bulk_create([
            WinUpdatePolicy(id=41, policy_id=41, run_time_days=[0, 2, 6], critical="approve"),
            WinUpdatePolicy(id=42, policy_id=41, run_time_days=None),
        ])
        if defaults in {"server", "both"}:
            CoreSettings.objects.update(server_policy_id=41)
        if defaults == "both":
            CoreSettings.objects.update(workstation_policy_id=41)
        Role.objects.filter(pk=1).update(can_list_automation_policies=scope != "denied",
                                        can_manage_automation_policies=scope == "head")
        role = Role.objects.get(pk=1)
        role.can_view_clients.clear()
        role.can_view_sites.clear()
        if scope in {"client", "combined"}:
            role.can_view_clients.add(41)
        if scope in {"site", "combined"}:
            role.can_view_sites.add(44)
        if scope == "installer":
            User.objects.filter(pk=6).update(role_id=1)
        cache.clear()

    paths = ["/automation/policies/", "/automation/policies/41/",
             "/automation/policies/42/", "/automation/policies/999/",
             "/automation/policies/41/related/", "/automation/policies/43/related/",
             "/automation/policies/999/related/", "/automation/policies/overview/"]
    count = 0
    try:
        for defaults in ["none", "server", "both"]:
            scopes = [("unscoped", 1), ("unscoped", 5), ("unscoped", 2),
                      ("client", 2), ("site", 2), ("combined", 2), ("denied", 2),
                      ("unscoped", 3), ("unscoped", 4), ("installer", 6),
                      ("head", 2), ("head-denied", 2)] if defaults == "none" else [("unscoped", 1)]
            for scope, user_id in scopes:
                for path in paths:
                    method = "HEAD" if scope.startswith("head") else "GET"
                    setup(scope, defaults)
                    client = APIClient()
                    token = hashlib.sha256(f"contract-user-{user_id}".encode()).hexdigest()
                    client.credentials(HTTP_AUTHORIZATION="Token " + token)
                    response = client.generic(method, path)
                    expected = (response.status_code, json.loads(response.content) if response.content else None)
                    state = snapshot()
                    actual = go_request(method, path, user_id=user_id)
                    if path == "/automation/policies/" and isinstance(expected[1], list) and isinstance(actual[1], list):
                        # Policy has no default ordering.
                        expected = (expected[0], sorted(expected[1], key=lambda row: row["id"]))
                        actual = (actual[0], sorted(actual[1], key=lambda row: row["id"]))
                    assert normalize_unordered(actual) == normalize_unordered(expected), (scope, defaults, method, path, expected, actual)
                    assert snapshot() == state, (path, "unexpected database change")
                    count += 1
        print(f"Automation read contracts: {count} comparisons passed")
        return count
    finally:
        Agent.objects.all().delete()
        Policy.objects.all().delete()
        AlertTemplate.objects.all().delete()
        seed()
