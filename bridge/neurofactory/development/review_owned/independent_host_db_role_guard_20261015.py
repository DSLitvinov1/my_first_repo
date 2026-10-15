"""REVIEW owned: PostgreSQL ephemeral actual login role/trigger boundary negative.
A separate login is used for each non-admin test, never SET ROLE under superuser.
No production DB, model, issuer or real user data.
"""
from pathlib import Path
import os
import secrets
import sys
import psycopg
from psycopg import sql

root=Path(sys.argv[1]).resolve()
with psycopg.connect(os.environ["REVIEW_ONLY_EPHEMERAL_PG_DSN"],autocommit=True) as admin:
    assert admin.execute("SELECT current_database()").fetchone()[0]=="nf_test"
    assert admin.execute("SELECT current_user").fetchone()[0]=="nf_review"
    admin.execute((root/"schema_v1.sql").read_text())
    admin.execute((root/"offline_highwater_schema.sql").read_text())
    admin.execute((root/"offline_db_roles_guard.sql").read_text())
    task="NF-DEV-05-Q984"; genesis="0"*64; digest1="1"*64
    admin.execute("""INSERT INTO nf_task(task_id,project_id,input_core_sha40,
      source_file_sha256,input_task_sha256) VALUES(%s,%s,%s,%s,%s)
      """,(task,"review-fixture","a"*40,"b"*64,"c"*64))
    admin.execute("INSERT INTO nf_offline_chain_head(task_id) VALUES(%s)",(task,))

    auth={}
    for who,group in [
      ("nf_review_reader_login","nf_offline_checkpoint_reader"),
      ("nf_review_writer_login","nf_offline_checkpoint_writer")]:
        password=secrets.token_urlsafe(24)
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            sql.Identifier(who),sql.Literal(password)))
        admin.execute(sql.SQL("GRANT {} TO {}").format(
            sql.Identifier(group),sql.Identifier(who)))
        auth[who]=password

    def as_login(login,fn):
        with psycopg.connect(host="localhost",port=5432,dbname="nf_test",
                             user=login,password=auth[login],autocommit=True) as db:
            assert db.execute("SELECT current_user").fetchone()[0]==login
            assert db.execute("SELECT rolsuper FROM pg_roles WHERE rolname=current_user").fetchone()[0] is False
            fn(db)

    def denied(label,fn):
        try:fn()
        except (psycopg.errors.InsufficientPrivilege,psycopg.errors.CheckViolation,
                psycopg.errors.RaiseException) as exc:
            print("REVIEW_"+label+"=DENIED_"+exc.sqlstate)
        else:raise AssertionError("Untrusted operation succeeded: "+label)

    def reader_attacks(c):
        assert c.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==0
        denied("READER_INSERT_EVENT",lambda:c.execute(
            """INSERT INTO nf_offline_chain_event(task_id,sequence,prior_digest_sha256,receipt_digest_sha256)
               VALUES(%s,1,%s,%s)""",(task,genesis,digest1)))
        denied("READER_UPDATE_HEAD",lambda:c.execute(
            "UPDATE nf_offline_chain_head SET last_sequence=1 WHERE task_id=%s",(task,)))
        denied("READER_SWITCH_TO_WRITER",lambda:c.execute("SET ROLE nf_offline_checkpoint_writer"))
    as_login("nf_review_reader_login",reader_attacks)

    def writer_attacks(c):
        denied("WRITER_DELETE_HISTORY",lambda:c.execute(
            "DELETE FROM nf_offline_chain_event WHERE task_id=%s",(task,)))
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
          """UPDATE nf_offline_chain_head SET last_sequence=0,last_digest_sha256=%s
             WHERE task_id=%s""",(genesis,task)))
        denied("WRITER_UPDATE_HISTORY",lambda:c.execute(
          """UPDATE nf_offline_chain_event SET receipt_digest_sha256=%s
             WHERE task_id=%s AND sequence=1""",("f"*64,task)))
        denied("WRITER_DELETE_HISTORY_AFTER_APPEND",lambda:c.execute(
            "DELETE FROM nf_offline_chain_event WHERE task_id=%s",(task,)))
    as_login("nf_review_writer_login",writer_attacks)
    assert admin.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==1
    print("REVIEW_SEPARATE_UNPRIVILEGED_LOGIN_ROLES=EFFECTIVELY_ISOLATED")

    # The actual owner can disable triggers and coherently rewrite both records.
    admin.execute("ALTER TABLE nf_offline_chain_event DISABLE TRIGGER nf_offline_event_no_mutation")
    admin.execute("ALTER TABLE nf_offline_chain_head DISABLE TRIGGER nf_offline_head_forward_only")
    admin.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s",(task,))
    admin.execute("""UPDATE nf_offline_chain_head
      SET last_sequence=0,last_digest_sha256=%s WHERE task_id=%s""",(genesis,task))
    assert admin.execute("SELECT last_sequence FROM nf_offline_chain_head WHERE task_id=%s",(task,)).fetchone()[0]==0
    print("REVIEW_DATABASE_OWNER_DISABLED_TRIGGERS_AND_ROLLED_BACK_HISTORY=CONFIRMED")
    print("REVIEW_SIGNED_EXTERNAL_PIN_AND_SEPARATE_KEY_CUSTODY=NOT_IMPLEMENTED")
    print("REVIEW_SCOPE=EPHEMERAL_POSTGRES_ROLE_BOUNDARY_NOT_LIVE_HOST_DEPLOYMENT")
