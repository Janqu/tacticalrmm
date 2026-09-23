"""Isolated checks for the explicitly applied Go note completion migration."""


def run(seed, snapshot):
    from agents.models import Agent, AgentHistory, Note
    from clients.models import Site
    from django.db import IntegrityError, connection, transaction

    seed()
    before = snapshot()
    checks = 0

    def rejected(query, args):
        nonlocal checks
        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute(query, args)
        except IntegrityError:
            checks += 1
        else:
            raise AssertionError("note completion schema accepted an invalid row")

    with transaction.atomic():
        agent = Agent(agent_id="note-schema-contract-agent", hostname="Note schema", site_id=Site.objects.order_by("id").first().pk)
        Agent.objects.bulk_create([agent])
        history = AgentHistory(agent_id=agent.pk, type="script_run", save_to_agent_note=True)
        legacy = AgentHistory(agent_id=agent.pk, type="script_run", save_to_agent_note=True)
        AgentHistory.objects.bulk_create([history, legacy])
        note = Note.objects.create(agent_id=agent.pk, note="schema-only fixture")
        insert = "INSERT INTO go_script_note_completion (history_id,agent_id,payload_identity,note_id) VALUES (%s,%s,%s::jsonb,%s)"

        # No inferred legacy completion or nullable producer identity.
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM go_script_note_completion WHERE history_id IN (%s,%s)", [history.pk, legacy.pk])
            assert cursor.fetchone()[0] == 0
        checks += 1
        rejected(insert, [history.pk, None, None, None])
        rejected(insert, [0, agent.pk, None, None])
        rejected(insert, [history.pk, agent.pk, None, note.pk])
        for identity in ("null", "[]", '"text"', "false", "1"):
            rejected(insert, [history.pk, agent.pk, identity, None])

        with connection.cursor() as cursor:
            cursor.execute(insert, [history.pk, agent.pk, None, None])
        checks += 1
        rejected(insert, [history.pk, agent.pk, None, None])
        rejected("UPDATE go_script_note_completion SET payload_identity='{}'::jsonb,note_id=%s WHERE history_id=%s", [0, history.pk])
        with connection.cursor() as cursor:
            cursor.execute("UPDATE go_script_note_completion SET payload_identity=%s::jsonb,note_id=%s WHERE history_id=%s", ['{"script_results":{"stdout":"schema-only fixture"}}', note.pk, history.pk])
            # A real SQL delete verifies the DB action without ORM knowledge of
            # the Go-owned table, as required for continued Django coexistence.
            cursor.execute("DELETE FROM agents_note WHERE id=%s", [note.pk])
            cursor.execute("SELECT payload_identity IS NOT NULL,note_id IS NULL,agent_id FROM go_script_note_completion WHERE history_id=%s", [history.pk])
            assert cursor.fetchone() == (True, True, agent.pk)
            checks += 1
            cursor.execute("DELETE FROM agents_agenthistory WHERE id=%s", [history.pk])
            cursor.execute("SELECT count(*) FROM go_script_note_completion WHERE history_id=%s", [history.pk])
            assert cursor.fetchone()[0] == 0
            checks += 1
        transaction.set_rollback(True)

    assert snapshot() == before, "note completion schema checks changed persistent state"
    print(f"note completion schema: {checks} checks passed")
