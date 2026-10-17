-- Offline/ephemeral PostgreSQL CAS prototype ONLY.
-- NOT a deployed trusted issuer, production authorization service or publisher.
CREATE TABLE IF NOT EXISTS nf_task (
    task_id text PRIMARY KEY CHECK (task_id ~ '^NF-DEV-05-Q[0-9]{3}$'),
    project_id text NOT NULL CHECK (project_id ~ '^[a-z][a-z0-9-]{2,39}$'),
    input_core_sha40 text NOT NULL CHECK (input_core_sha40 ~ '^[0-9a-f]{40}$'),
    source_file_sha256 text NOT NULL CHECK (source_file_sha256 ~ '^[0-9a-f]{64}$'),
    input_task_sha256 text NOT NULL CHECK (input_task_sha256 ~ '^[0-9a-f]{64}$'),
    -- ONLY a trusted external issuer may eventually assert authorization.
    -- In prototype tests this column is populated by an ephemeral SQL fixture.
    fixture_authorized boolean NOT NULL DEFAULT false,
    phase text NOT NULL DEFAULT 'QUEUED'
       CHECK (phase IN ('QUEUED','LEASED','UNKNOWN','BLOCKED')),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    holder_id text,
    lease_request_id text,
    lease_token_sha256 text,
    lease_deadline timestamptz,
    CONSTRAINT nf_consistent_lease CHECK (
        (phase = 'LEASED' AND holder_id IS NOT NULL AND
         lease_request_id IS NOT NULL AND lease_token_sha256 IS NOT NULL AND
         lease_deadline IS NOT NULL)
        OR phase <> 'LEASED'
    )
);
CREATE TABLE IF NOT EXISTS nf_claim_request (
    request_id text PRIMARY KEY,
    task_id text NOT NULL REFERENCES nf_task(task_id),
    worker_id text NOT NULL,
    lease_epoch bigint NOT NULL CHECK(lease_epoch > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
