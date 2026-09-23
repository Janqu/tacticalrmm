"""Bounded DB resolver contracts; isolated schema supplied by compare_django."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch


def run(seed, snapshot, dsn):
    from agents.models import Agent, AgentCustomField
    from clients.models import Client, Site, ClientCustomField, SiteCustomField
    from core.models import CustomField, GlobalKVStore
    from logs.models import DebugLog
    from scripts.models import Script
    from tacticalrmm.utils import get_db_value

    url = urlsplit(dsn)
    schema = parse_qs(url.query).get("search_path", [""])[0]
    if url.hostname not in {"127.0.0.1", "localhost", "::1"} or not re.fullmatch(r"go_contract_[a-f0-9]+", schema):
        raise ValueError("resolver harness requires isolated loopback contract schema")

    def cleanup():
        Agent.objects.all().delete()
        CustomField.objects.filter(pk__gte=301, pk__lt=400).delete()
        GlobalKVStore.objects.filter(pk__gte=301, pk__lt=400).delete()

    models = (Agent, Client, Site, CustomField, AgentCustomField, ClientCustomField, SiteCustomField, GlobalKVStore, DebugLog)
    def state():
        return {model._meta.db_table: list(model.objects.order_by("id").values()) for model in models}, snapshot()

    try:
        cleanup()
        seed()
        Client.objects.bulk_create([Client(id=31, name="Resolver Client", block_policy_inheritance=False)])
        Site.objects.bulk_create([Site(id=31, client_id=31, name="Resolver Site", block_policy_inheritance=True)])
        Agent.objects.bulk_create([Agent(id=31, site_id=31, hostname="Resolver Agent", agent_id="script-resolver-agent-001",
                                        version="2.11.0", description="", total_ram=0, boot_time=10.0,
                                        needs_reboot=False, choco_installed=True, public_ip=None)])
        globals_ = [("Go value", "O'Brien\\path"), ("Go empty", ""), ("Go case", "lower"),
                    ("GO case", "upper"), ("Go duplicate", "first"), ("Go duplicate", "second")]
        GlobalKVStore.objects.bulk_create([GlobalKVStore(id=301+i, name=name, value=value) for i, (name, value) in enumerate(globals_)])
        field_id = 301
        fields, field_values = [], {AgentCustomField: [], SiteCustomField: [], ClientCustomField: []}
        for model, field_model in [("agent", AgentCustomField), ("site", SiteCustomField), ("client", ClientCustomField)]:
            for name, kind, actual, default in [
                ("Text", "text", "actual ' text", "fallback"), ("Empty", "text", "", "fallback"),
                ("Missing", "text", None, "default-only"), ("Null default", "text", "", None),
                ("Number", "number", "42", "0"), ("Single", "single", "choice", "default"),
                ("Datetime", "datetime", "2026-01-02", ""), ("Multiple", "multiple", ["a", "b"], ["default"]),
                ("Empty multiple", "multiple", [], ["fallback"]), ("Missing multiple", "multiple", None, []),
                ("Check", "checkbox", False, True), ("Missing check", "checkbox", None, True),
                ("hostname", "text", "custom-host", "default-host")]:
                defaults = {"default_value_string": default} if kind not in {"multiple", "checkbox"} else {
                    "default_values_multiple" if kind == "multiple" else "default_value_bool": default}
                fields.append(CustomField(id=field_id, model=model, name=name, type=kind, **defaults))
                if actual is not None:
                    column = "multiple_value" if kind == "multiple" else "bool_value" if kind == "checkbox" else "string_value"
                    field_values[field_model].append(field_model(field_id=field_id, **{model + "_id": 31, column: actual}))
                field_id += 1
        CustomField.objects.bulk_create(fields)
        for model, values in field_values.items(): model.objects.bulk_create(values)
        roots = {"agent": Agent.objects.get(pk=31), "site": Site.objects.get(pk=31), "client": Client.objects.get(pk=31), "": None}
        cases, expected = [], []
        def compare(model, expression):
            cases.append({"model": model, "id": 31 if model else 0, "expression": expression})
            # This foundation is deliberately read-only. Missing diagnostics
            # belong to the caller; they are not claimed as Go parity here.
            with patch.object(DebugLog, "error"):
                value = get_db_value(string=expression, instance=roots[model])
                args = Script.parse_script_args(roots[model], "powershell", ["{{"+expression+"}}"])
                env = Script.parse_script_env_vars(roots[model], "powershell", ["VALUE={{"+expression+"}}"])
            expected.append({"value": value, "args": args, "env": env})
        for model in roots:
            for name in ("Go value", "Go empty", "Go case", "GO case"):
                compare(model, "global." + name)
        for expression in ("agent.id", "agent.pk", "agent.hostname", "hostname", "agent.agent_id", "agent.version", "agent.total_ram", "agent.boot_time",
                           "agent.description", "agent.public_ip", "agent.needs_reboot", "agent.choco_installed", "agent.site_id", "site.name", "client.name",
                           "agent.site.name", "agent.site.client.name", "agent.client.id", " agent.hostname "):
            compare("agent", expression)
        for expression in ("site.id", "site.name", "name", "site.client_id", "client.name", "site.client.name", "site.block_policy_inheritance"):
            compare("site", expression)
        for expression in ("client.id", "client.pk", "client.name", "name", "client.block_policy_inheritance", "client.server_policy_id"):
            compare("client", expression)
        for root in ("agent", "site", "client"):
            for model in ("agent", "site", "client"):
                for name in ("Text", "Empty", "Missing", "Null default", "Number", "Single", "Datetime", "Multiple", "Empty multiple", "Missing multiple", "Check", "Missing check", "hostname"):
                    compare(root, model + "." + name)
        unsupported = ["agent.save", "agent.checks", "agent.user.password", "agent.last_seen", "agent.wmi_detail", "agent.no_such_property",
                       "agent.hostname.upper", "agent.site", "agent.__class__", "client.sites.name", "agent. hostname", "global.Go value.extra", "agent.id;DELETE"]
        for expression in unsupported:
            cases.append({"model": "agent", "id": 31, "expression": expression})
            expected.append({"error": "unsupported"})
        for expression, error in [("global.Not present", "missing"), ("global.Go duplicate", "ambiguous")]:
            cases.append({"model": "agent", "id": 31, "expression": expression})
            expected.append({"error": error})
        cases.append({"model": "agent", "id": 999, "expression": "agent.id"})
        expected.append({"error": "missing"})
        before = state()
        with tempfile.TemporaryDirectory(prefix="trmm-script-resolver-") as temporary:
            source, output = Path(temporary) / "input.json", Path(temporary) / "output.json"
            source.write_text(json.dumps(cases))
            env = dict(os.environ, TRMM_SCRIPT_RESOLVER_INPUT=str(source), TRMM_SCRIPT_RESOLVER_OUTPUT=str(output), TRMM_SCRIPT_RESOLVER_DSN=dsn)
            subprocess.run(["go", "test", "./internal/httpapi", "-run", "^TestScriptResolverContract$", "-count=1"],
                           cwd=Path(__file__).resolve().parents[1], env=env, check=True)
            actual = json.loads(output.read_text())
        assert len(actual) == len(expected)
        for index, (want, got) in enumerate(zip(expected, actual)):
            # Avoid including resolved values or global secrets in failures.
            assert got == want, f"script resolver case {index} differs ({cases[index]['expression']})"
        assert state() == before, "read-only resolver changed database state"
        print(f"Script resolver contracts: {len(cases)} comparisons passed")
        return len(cases)
    finally:
        cleanup()
        seed()
