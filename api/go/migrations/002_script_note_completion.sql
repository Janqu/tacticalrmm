BEGIN;

-- Only new, explicitly opted-in Go histories receive pending rows. Existing
-- histories cannot be backfilled: Django notes have no link to their history.
CREATE TABLE IF NOT EXISTS go_script_note_completion (
    history_id bigint PRIMARY KEY
        REFERENCES agents_agenthistory(id) ON DELETE CASCADE,
    -- Immutable producer identity, checked against the authenticated callback
    -- and current history. History owns lifetime; this snapshot is not a FK.
    agent_id bigint NOT NULL,
    payload_identity jsonb,
    note_id bigint REFERENCES agents_note(id) ON DELETE SET NULL,
    CONSTRAINT go_script_note_completion_payload_object
        CHECK (payload_identity IS NULL OR jsonb_typeof(payload_identity) = 'object'),
    CONSTRAINT go_script_note_completion_pending_without_note
        CHECK (payload_identity IS NOT NULL OR note_id IS NULL)
);

-- A completed marker survives note deletion, preventing replay from recreating
-- a deliberately deleted note. Deleting history removes its replay identity.
COMMIT;
