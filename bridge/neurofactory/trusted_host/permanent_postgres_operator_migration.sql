-- NEUROFACTORY TRUSTED HOST: operator-reviewed permanent PostgreSQL DDL candidate.
--
-- NEVER execute on an existing production DB before independent review and
-- operator authorization. NO database creation, test flags, passwords,
-- credentials, environment overrides, auto-granted public privileges or
-- filesystem effect authority are provided here.
--
-- PostgreSQL tables are bookkeeping, NOT the root of authorization.
-- DB owners/superusers/backup restores can rewind all rows/triggers, so
-- OFF-HOST durable witness/highwater and separately privileged signer are
-- mandatory before even one user file operation. Never auto-retry UNKNOWN.

BEGIN;

CREATE SCHEMA IF NOT EXISTS nf_trusted_host;
REVOKE ALL ON SCHEMA nf_trusted_host FROM PUBLIC;

CREATE TABLE IF NOT EXISTS nf_trusted_host.lease_register (
    task_id text PRIMARY KEY CHECK (length(task_id) BETWEEN 3 AND 90),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 3 AND 90),
    repository_full_name text NOT NULL
        CHECK (repository_full_name ~ '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$'),
    project_id text NOT NULL CHECK (length(project_id) BETWEEN 3 AND 90),
    source_sha40 char(40) NOT NULL
        CHECK (source_sha40 ~ '^[0-9a-f]{40}$'),
    source_file_sha256 char(64) NOT NULL
        CHECK (source_file_sha256 ~ '^[0-9a-f]{64}$'),
    policy_sha256 char(64) NOT NULL
        CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    approved_scope_sha256 char(64) NOT NULL
        CHECK (approved_scope_sha256 ~ '^[0-9a-f]{64}$'),
    worker_id text CHECK (worker_id IS NULL OR length(worker_id) BETWEEN 3 AND 90),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    fencing_token_sha256 char(64)
        CHECK (fencing_token_sha256 IS NULL OR fencing_token_sha256 ~ '^[0-9a-f]{64}$'),
    lease_deadline timestamptz,
    state text NOT NULL DEFAULT 'BLOCKED'
        CHECK (state IN ('BLOCKED', 'CLAIMED', 'UNKNOWN', 'COMPLETED')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (state <> 'CLAIMED' OR
           (worker_id IS NOT NULL AND lease_epoch > 0 AND
            fencing_token_sha256 IS NOT NULL AND lease_deadline IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS nf_trusted_host.effect_receipt (
    task_id text NOT NULL REFERENCES nf_trusted_host.lease_register(task_id),
    operation_id text NOT NULL CHECK (length(operation_id) BETWEEN 3 AND 90),
    idempotency_key char(64) NOT NULL UNIQUE
        CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    signed_scope_sha256 char(64) NOT NULL
        CHECK (signed_scope_sha256 ~ '^[0-9a-f]{64}$'),
    target_sha256 char(64) NOT NULL
        CHECK (target_sha256 ~ '^[0-9a-f]{64}$'),
    content_sha256 char(64) NOT NULL
        CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    external_witness_root_sha256 char(64) NOT NULL
        CHECK (external_witness_root_sha256 ~ '^[0-9a-f]{64}$'),
    external_witness_sequence bigint NOT NULL
        CHECK (external_witness_sequence >= 1),
    status text NOT NULL DEFAULT 'UNKNOWN'
        CHECK (status IN ('UNKNOWN', 'COMPLETED')),
    receiver_file_sha256 char(64)
        CHECK (receiver_file_sha256 IS NULL OR
               receiver_file_sha256 ~ '^[0-9a-f]{64}$'),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (task_id, operation_id),
    UNIQUE (task_id),
    CHECK ((status = 'UNKNOWN' AND receiver_file_sha256 IS NULL
                                   AND completed_at IS NULL) OR
           (status = 'COMPLETED' AND receiver_file_sha256 IS NOT NULL
                                      AND completed_at IS NOT NULL)),
    CHECK (receiver_file_sha256 IS NULL OR receiver_file_sha256 = content_sha256)
);

-- No deletion of evidence or rewrite/replay in ordinary SQL execution.
-- This is defense in depth ONLY: superuser/TRUNCATE/backup restore can bypass.
CREATE OR REPLACE FUNCTION nf_trusted_host.reject_receipt_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'TRUSTED HOST receipt deletion denied, external witness required';
    END IF;
    IF OLD.status <> 'UNKNOWN' OR NEW.status <> 'COMPLETED'
       OR NEW.receiver_file_sha256 IS NULL OR
       NEW.receiver_file_sha256 <> OLD.content_sha256 OR
       NEW.completed_at IS NULL OR
       NEW.task_id IS DISTINCT FROM OLD.task_id OR
       NEW.operation_id IS DISTINCT FROM OLD.operation_id OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.signed_scope_sha256 IS DISTINCT FROM OLD.signed_scope_sha256 OR
       NEW.target_sha256 IS DISTINCT FROM OLD.target_sha256 OR
       NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256 OR
       NEW.external_witness_root_sha256 IS DISTINCT FROM OLD.external_witness_root_sha256 OR
       NEW.external_witness_sequence IS DISTINCT FROM OLD.external_witness_sequence OR
       NEW.received_at IS DISTINCT FROM OLD.received_at THEN
        RAISE EXCEPTION 'TRUSTED HOST effect receipt immutable/UNKNOWN only';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS nf_receipt_no_rewrite ON nf_trusted_host.effect_receipt;
CREATE TRIGGER nf_receipt_no_rewrite
BEFORE UPDATE OR DELETE ON nf_trusted_host.effect_receipt
FOR EACH ROW EXECUTE FUNCTION nf_trusted_host.reject_receipt_mutation();

CREATE INDEX IF NOT EXISTS nf_host_lease_state_deadline
  ON nf_trusted_host.lease_register(state, lease_deadline);
CREATE INDEX IF NOT EXISTS nf_host_external_witness_sequence
  ON nf_trusted_host.effect_receipt(external_witness_sequence);

REVOKE ALL ON ALL TABLES IN SCHEMA nf_trusted_host FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA nf_trusted_host FROM PUBLIC;

COMMIT;
