-- Ephemeral nf_test only. Assumes schema_v1.sql loaded first.
-- These test fixture rows are NOT a real signed owner or source authorization.
CREATE TABLE IF NOT EXISTS nf_effect_scope_fixture (
    task_id text PRIMARY KEY REFERENCES nf_task(task_id),
    project_id text NOT NULL,
    input_core_sha40 text NOT NULL,
    source_file_sha256 text NOT NULL,
    input_task_sha256 text NOT NULL,
    target text NOT NULL,
    policy_sha256 text NOT NULL,
    fixture_authorized boolean NOT NULL DEFAULT false
);
-- One permanent intent per task; globally unique idempotency key for test DB.
-- A reservation does NOT atomically commit a filesystem effect or receipt.
CREATE TABLE IF NOT EXISTS nf_effect_intent (
    task_id text PRIMARY KEY REFERENCES nf_task(task_id),
    project_id text NOT NULL,
    worker_id text NOT NULL,
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    fencing_token_sha256 text NOT NULL,
    idempotency_key text NOT NULL UNIQUE,
    source_sha40 text NOT NULL,
    source_file_sha256 text NOT NULL,
    input_task_sha256 text NOT NULL,
    target text NOT NULL,
    policy_sha256 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
