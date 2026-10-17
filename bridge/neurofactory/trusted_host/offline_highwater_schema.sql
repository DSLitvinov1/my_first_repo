-- OFFLINE TEST-ONLY monotonic checkpoint persistence candidate.
-- Its own DB administrator can still rewrite BOTH head and history; it is NOT
-- an externally anchored issuer, signed authorization or rollback-proof log.
CREATE TABLE IF NOT EXISTS nf_offline_chain_head (
    task_id text PRIMARY KEY REFERENCES nf_task(task_id),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK(last_sequence >= 0),
    last_digest_sha256 text NOT NULL DEFAULT repeat('0',64)
        CHECK(last_digest_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS nf_offline_chain_event (
    task_id text NOT NULL REFERENCES nf_task(task_id),
    sequence bigint NOT NULL CHECK(sequence > 0),
    prior_digest_sha256 text NOT NULL CHECK(prior_digest_sha256 ~ '^[0-9a-f]{64}$'),
    receipt_digest_sha256 text NOT NULL CHECK(receipt_digest_sha256 ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(task_id,sequence),
    UNIQUE(task_id,receipt_digest_sha256)
);
