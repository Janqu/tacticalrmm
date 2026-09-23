"""Supersedence parity using a test-only Go bridge and an isolated local DB."""
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import urlparse


def run(seed, snapshot, dsn):
    from agents.models import Agent
    from clients.models import Client, Site
    from django.db import connection
    from winupdate.models import WinUpdate

    assert urlparse(dsn).hostname in {"127.0.0.1", "localhost", "::1"}
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        schema = cursor.fetchone()[0]
    assert schema.startswith("go_contract_")
    fixed = datetime(2024, 1, 2, 3, 4, 5, 123400, tzinfo=timezone.utc)
    count = 0

    def setup(groups):
        Agent.objects.all().delete(); seed()
        Client.objects.bulk_create([Client(id=31, name="Prune")])
        Site.objects.bulk_create([Site(id=31, name="Prune", client_id=31)])
        Agent.objects.bulk_create([Agent(id=31, agent_id="supersedence-agent-00031", hostname="A", site_id=31), Agent(id=32, agent_id="supersedence-agent-00032", hostname="B", site_id=31)])
        Agent.objects.update(created_time=fixed, modified_time=fixed)
        rows = []
        for kb, titles in groups:
            for title in titles:
                pk = len(rows) + 31
                rows.append(WinUpdate(id=pk, agent_id=31, kb=kb, title=title, guid=f"guid-{pk}", installed=pk % 2 == 0, action="ignore"))
        rows.extend([WinUpdate(id=901, agent_id=32, kb="KB-other", title="(Version 1)"), WinUpdate(id=902, agent_id=32, kb="KB-other", title="(Version 2)")])
        WinUpdate.objects.bulk_create(rows)

    def state():
        return {"base": snapshot(), "agents": list(Agent.objects.order_by("id").values()), "updates": list(WinUpdate.objects.order_by("id").values())}

    with tempfile.TemporaryDirectory(prefix="go-supersedence-") as directory:
        binary = Path(directory) / "contracts"
        module = Path(__file__).resolve().parents[1]
        subprocess.run(["go", "test", "-c", "-o", str(binary), "./internal/httpapi"], cwd=module, check=True, capture_output=True, text=True, timeout=120)
        def invoke():
            env = os.environ.copy(); env["TRMM_SUPERSEDENCE_DSN"] = dsn
            return subprocess.run([str(binary), "-test.run=^TestSupersedenceDatabaseContract$"], env=env, capture_output=True, text=True, timeout=15)

        def compare(groups):
            nonlocal count
            setup(groups)
            with patch.object(Agent, "nats_cmd") as bus, patch("celery.app.task.Task.apply_async") as jobs:
                Agent.objects.get(pk=31).delete_superseded_updates()
            bus.assert_not_called(); jobs.assert_not_called()
            expected = state()
            setup(groups)
            result = invoke()
            assert result.returncode == 0, result.stdout + result.stderr
            assert state() == expected, (groups, "supersedence difference", expected["updates"], state()["updates"])
            count += 1

        try:
            compare([])
            for versions in [
                ["1", "2"], ["2", "1"], ["1", "1", "2"], ["12", "2"], ["1.10", "1.1"],
                ["1", "1.0", "1.0.0"], ["1dev1", "1a0", "1b0", "1rc0", "1", "1post0"],
                ["1rc1dev1", "1rc1", "1post0dev1", "1post0"],
                ["1+abc", "1+abc.1", "1+1", "1+2"], ["1!0", "999999999999999999999999999!0", "99999"],
                ["v01.0", "0!1", "1.0.1"], ["1-1", "1post2", "1rev3"],
                ["1", "broken", "2"], ["1", "1.2.3foo", "2"], ["1", "1rc١", "2"], ["1", "", "2"],
            ]:
                compare([("KB1", [f"App (Version {v})" for v in versions])])
            for titles in [["App (VERSÃO 1)", "App (version 2)"], ["App (Version 1)", None], ["App (Version 1)", "No version"], ["App (Version 1\n)", "App (Version 2)"], ["App (Version  1 )", "App (Version 2)"], ["(Version 1) (Version 9)", "(Version 2)"]]:
                compare([("KB1", titles)])
            compare([(None, ["(Version 1)", "(Version 2)"]), ("", ["(Version 1)", "(Version 2)"]), ("different", ["(Version 1)"])])
            compare([("bad", ["(Version 1)", None]), ("good", ["(Version 1)", "(Version 2)"])])
            # Source suppresses DB failures. Go must return failure to its caller;
            # deletion still rolls back as one transaction.
            setup([("KB1", ["(Version 1)", "(Version 2)", "(Version 3)"])])
            before = state()
            with connection.cursor() as cursor:
                cursor.execute("CREATE FUNCTION supersedence_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.id=32 THEN RAISE EXCEPTION 'fixture delete failure'; END IF; RETURN OLD; END $$")
                cursor.execute("CREATE TRIGGER supersedence_reject BEFORE DELETE ON winupdate_winupdate FOR EACH ROW EXECUTE FUNCTION supersedence_reject()")
            try:
                result = invoke()
                assert result.returncode != 0 and state() == before, "failed prune did not roll back"
                count += 1
            finally:
                with connection.cursor() as cursor:
                    cursor.execute("DROP TRIGGER supersedence_reject ON winupdate_winupdate")
                    cursor.execute("DROP FUNCTION supersedence_reject()")
            print(f"Windows supersedence contracts: {count} comparisons passed")
            return count
        finally:
            Agent.objects.all().delete(); seed()
