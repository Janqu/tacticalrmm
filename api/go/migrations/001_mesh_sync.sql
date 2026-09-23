BEGIN;

-- Go-owned outbox; existing Django tables are unchanged.
CREATE TABLE IF NOT EXISTS go_mesh_sync (
    id smallint PRIMARY KEY CHECK (id = 1),
    generation bigint NOT NULL CHECK (generation > 0),
    completed_generation bigint NOT NULL DEFAULT 0,
    requested_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    next_attempt_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts bigint NOT NULL DEFAULT 0,
    CHECK (completed_generation >= 0 AND completed_generation <= generation),
    CHECK (attempts >= 0)
);

COMMIT;
