"""REVIEW owned: PostgreSQL test-only roles/trigger isolation negative.

No production database, external issuer, model or user projects. Uses ephemeral
GitHub hosted nf_test, tests effective privileges with SET ROLE and controlled
direct SQL mutations by DB admin.
"""
from pathlib import Path
import os
import sys
import psycopg
from psycopg import errors

root=Path(sys.argv[1]).resolve()
dsn=os.environ["REVIEW_ONLY_EPHEMERAL_PG_DSN"]
with psycopg.connect(dsn,autocommit=True) as c:
    dbname=c.execute("SELECT current_database()").fetchone()[0]
    assert dbname=="nf_test",dbname
    assert c.execute("SELECT current_user").fetchone()[0]=="nf_review"
    c.execute((root/"schema_v1.sql").read_text())
    c.execute((root/"offline_highwater_schema.sql").read_text())
    c.execute((root/"offline_db_roles_guard.sql").read_text())
    task="NF-DEV-05-Q984"; genesis="0"*64; digest1="1"*64
    c.execute("""INSERT INTO nf_task(task_id,project_id,input_core_sha40,
            source_file_sha256,input_task_sha256) VALUES(%s,%s,%s,%s,%s)
            """,(task,"review-fixture","a"*40,"b"*64,"c"*64))
    c.execute("INSERT INTO nf_offline_chain_head(task_id) VALUES(%s)",(task,))

    def as_role(name, fn):
        c.execute("SET ROLE "+name)
        try:return fn()
        finally:c.execute("RESET ROLE")

    def denied(label,fn):
        try:fn()
        except (psycopg.errors.InsufficientPrivilege,psycopg.errors.CheckViolation,
                psycopg.errors.RaiseException) as exc:
            print("REVIEW_"+label+"=DENIED_"+exc.sqlstate)
        else:raise AssertionError("Untrusted operation succeeded: "+label)

    def reader_attacks():
        assert c.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==0
        denied("READER_INSERT_EVENT",lambda:c.execute(
            """INSERT INTO nf_offline_chain_event(task_id,sequence,prior_digest_sha256,receipt_digest_sha256)
               VALUES(%s,1,%s,%s)""",(task,genesis,digest1)))
        denied("READER_UPDATE_HEAD",lambda:c.execute(
            "UPDATE nf_offline_chain_head SET last_sequence=1 WHERE task_id=%s",(task,)))
        denied("READER_SWITCH_TO_WRITER",lambda:c.execute("SET ROLE nf_offline_checkpoint_writer"))
    as_role("nf_offline_checkpoint_reader",reader_attacks)

    def writer_attacks():
        denied("WRITER_DELETE_HISTORY",lambda:c.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s",(task,)))
        denied("WRITER_MANIPULATE_EMPTY_HEAD",lambda:c.execute(
            """UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s""",
            (digest1,task)))
        denied("WRITER_DISABLE_TRIGGER",lambda:c.execute(
            "ALTER TABLE nf_offline_chain_event DISABLE TRIGGER nf_offline_event_no_mutation"))
        c.execute("""INSERT INTO nf_offline_chain_event
          (task_id,sequence,prior_digest_sha256,receipt_digest_sha256)
          VALUES (%s,1,%s,%s)""",(task,genesis,digest1))
        c.execute("""UPDATE nf_offline_chain_head
          SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s""",(digest1,task))
        assert c.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==1
        print("REVIEW_WRITER_ALLOWED_MONOTONIC_TEST_HEAD=1")
        denied("WRITER_REVERSE_HEAD",lambda:c.execute(
          """UPDATE nf_offline_chain_head
             SET last_sequence=0,last_digest_sha256=%s WHERE task_id=%s""",(genesis,task)))
        denied("WRITER_UPDATE_HISTORY",lambda:c.execute(
          """UPDATE nf_offline_chain_event SET receipt_digest_sha256=%s WHERE task_id=%s AND sequence=1""",
          ("f"*64,task)))
        denied("WRITER_DELETE_HISTORY_AFTER_APPEND",lambda:c.execute(
          "DELETE FROM nf_offline_chain_event WHERE task_id=%s",(task,)))
    as_role("nf_offline_checkpoint_writer",writer_attacks)
    assert c.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==1
    print("REVIEW_SEPARATE_DB_READER_WRITER_RIGHTS=ISOLATED_IN_EPHEMERAL_POSTGRES")

    # A DB owner can disable all test-only triggers and rewrite history.
    # This is a boundary clarification, NOT a live system compromise.
    c.execute("ALTER TABLE nf_offline_chain_event DISABLE TRIGGER nf_offline_event_no_mutation")
    c.execute("ALTER TABLE nf_offline_chain_head DISABLE TRIGGER nf_offline_head_forward_only")
    c.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s",(task,))
    c.execute("""UPDATE nf_offline_chain_head
              SET last_sequence=0,last_digest_sha256=%s WHERE task_id=%s""",(genesis,task))
    assert c.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==0
    print("REVIEW_DB_OWNER_DISABLED_TRIGGERS_AND_REWROTE_HEAD=CONFIRMED")
    print("REVIEW_EXTERNAL_ATTESTED_MONOTONIC_PIN_OR_PROTECTED_SIGNER=ABSENT")
    print("REVIEW_SCOPE=EPHEMERAL_DB_ROLES_NOT_DEPLOYED_TRUSTED_HOST")
