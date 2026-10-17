-- STRICTLY EPHEMERAL nf_test role-boundary proof; NOT production migration.
-- SQL roles do not isolate against the database owner/superuser or OS admin.
-- This file only runs in an ephemeral PostgreSQL 16 GitHub Actions service.
DO $$
BEGIN
  IF current_database() <> 'nf_test' THEN
    RAISE EXCEPTION 'not an ephemeral database';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='nf_offline_checkpoint_writer') THEN
    CREATE ROLE nf_offline_checkpoint_writer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='nf_offline_checkpoint_reader') THEN
    CREATE ROLE nf_offline_checkpoint_reader NOLOGIN;
  END IF;
END $$;

-- Deny ordinary users history mutation even if a future grant broadens.
-- A real owner/superuser can disable triggers: not a trusted append-only log.
CREATE OR REPLACE FUNCTION nf_offline_deny_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'historical event is append-only in test-role boundary'
    USING ERRCODE='23514';
END $$;

DROP TRIGGER IF EXISTS nf_offline_event_no_mutation
  ON nf_offline_chain_event;
CREATE TRIGGER nf_offline_event_no_mutation
  BEFORE UPDATE OR DELETE ON nf_offline_chain_event
  FOR EACH ROW EXECUTE FUNCTION nf_offline_deny_event_mutation();

CREATE OR REPLACE FUNCTION nf_offline_require_next_head()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.task_id <> OLD.task_id OR
     NEW.last_sequence <> OLD.last_sequence+1 OR
     NEW.last_digest_sha256=OLD.last_digest_sha256 OR
     NOT EXISTS (
       SELECT 1 FROM nf_offline_chain_event AS e
       WHERE e.task_id=OLD.task_id AND
             e.sequence=NEW.last_sequence AND
             e.prior_digest_sha256=OLD.last_digest_sha256 AND
             e.receipt_digest_sha256=NEW.last_digest_sha256
     ) THEN
    RAISE EXCEPTION 'out-of-order or unsupported checkpoint head'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS nf_offline_head_forward_only
  ON nf_offline_chain_head;
CREATE TRIGGER nf_offline_head_forward_only
  BEFORE UPDATE ON nf_offline_chain_head
  FOR EACH ROW EXECUTE FUNCTION nf_offline_require_next_head();

-- Read-only projection is not an issuer, signer, approval or secret store.
GRANT USAGE ON SCHEMA public TO
  nf_offline_checkpoint_writer, nf_offline_checkpoint_reader;
GRANT SELECT ON nf_offline_chain_head, nf_offline_chain_event
  TO nf_offline_checkpoint_reader;
GRANT SELECT ON nf_offline_chain_head, nf_offline_chain_event
  TO nf_offline_checkpoint_writer;
GRANT SELECT (task_id) ON nf_task TO nf_offline_checkpoint_writer;
GRANT INSERT (task_id) ON nf_offline_chain_head TO nf_offline_checkpoint_writer;
GRANT UPDATE (last_sequence,last_digest_sha256)
  ON nf_offline_chain_head TO nf_offline_checkpoint_writer;
GRANT INSERT (task_id,sequence,prior_digest_sha256,receipt_digest_sha256)
  ON nf_offline_chain_event TO nf_offline_checkpoint_writer;
