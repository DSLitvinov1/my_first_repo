"""PostgreSQL16 migration regression in an EPHEMERAL CI database only.

Never target production. The SQL schema does not confer filesystem authority;
an authorized DB superuser can still restore/rollback the local DB. External
monotonic witness must independently stop duplicate effects.
"""
import os
from pathlib import Path
import unittest

import psycopg


DBNAME = "nf_schema_verify"
DSN = ("postgresql://nf_schema_ci:nf_schema_ephemeral_password@127.0.0.1:5432/"
       + DBNAME)
SCHEMA_PATH = Path(__file__).with_name("permanent_postgres_operator_migration.sql")


class PermanentDBSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NF_DB_SCHEMA_CI_ONLY") != "1":
            raise RuntimeError("migration test only on isolated GitHub disposable DB")
        cls.conn = psycopg.connect(DSN, autocommit=True, connect_timeout=4)
        if cls.conn.execute("SELECT current_database()").fetchone()[0] != DBNAME:
            raise RuntimeError("wrong or non-ephemeral database")
        cls.conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.addClassCleanup(cls.conn.close)

    def setUp(self):
        self.conn.execute("""TRUNCATE TABLE nf_trusted_host.effect_receipt,
                             nf_trusted_host.lease_register RESTART IDENTITY CASCADE""")
        self.sha = "a" * 64
        self.task = "NF-DEV-05-Q991"

    def lease(self,*,state="BLOCKED",epoch=0,fence=None,worker=None,expires=None):
        self.conn.execute(
            """INSERT INTO nf_trusted_host.lease_register(
               task_id,owner_id,repository_full_name,project_id,source_sha40,
               source_file_sha256,policy_sha256,approved_scope_sha256,
               worker_id,lease_epoch,fencing_token_sha256,lease_deadline,state)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (self.task,"owner-a","DSLitvinov1/my_first_repo",
             "nf-sandbox","a"*40,self.sha,self.sha,self.sha,
             worker,epoch,fence,expires,state))

    def receipt(self, *,task=None,key=None):
        return self.conn.execute(
            """INSERT INTO nf_trusted_host.effect_receipt(
                task_id, operation_id, idempotency_key, signed_scope_sha256,
                target_sha256, content_sha256, external_witness_root_sha256,
                external_witness_sequence)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
            (self.task if task is None else task,"op-one",
             key if key is not None else "b"*64,
             self.sha,"c"*64,"d"*64,"e"*64,10))

    def test_migration_is_idempotent_and_has_no_public_grants(self):
        self.conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
        n=self.conn.execute(
            "SELECT nspacl::text FROM pg_namespace WHERE nspname='nf_trusted_host'"
        ).fetchone()
        self.assertIsNotNone(n)
        self.assertNotIn("=U/",n[0] or "")
        kinds=self.conn.execute(
            """SELECT relname,relkind FROM pg_class WHERE relnamespace=
               'nf_trusted_host'::regnamespace AND relkind='r'
               ORDER BY relname"""
        ).fetchall()
        self.assertEqual(kinds,[("effect_receipt","r"),("lease_register","r")])

    def test_claimed_lease_requires_epoch_worker_deadline_fence(self):
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.lease(state="CLAIMED")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_trusted_host.lease_register"
        ).fetchone()[0],0)

    def test_valid_claimed_lease_and_unknown_intent_only(self):
        self.lease(state="CLAIMED",epoch=1,worker="worker-A",fence=self.sha,
                   expires="2030-01-01T00:00:00Z")
        self.receipt()
        row=self.conn.execute(
            "SELECT status, receiver_file_sha256 FROM nf_trusted_host.effect_receipt"
        ).fetchone()
        self.assertEqual(row,("UNKNOWN",None))

    def test_cannot_insert_completed_receipt_without_prior_unknown(self):
        self.lease()
        with self.assertRaises(psycopg.errors.RaiseException):
            self.conn.execute(
                """INSERT INTO nf_trusted_host.effect_receipt(
                    task_id, operation_id, idempotency_key, signed_scope_sha256,
                    target_sha256, content_sha256, external_witness_root_sha256,
                    external_witness_sequence, status, receiver_file_sha256,
                    completed_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'COMPLETED',%s,clock_timestamp())""",
                (self.task,"op-one","b"*64,self.sha,"c"*64,
                 "d"*64,"e"*64,10,"d"*64))
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_trusted_host.effect_receipt"
        ).fetchone()[0],0)

    def test_duplicate_task_or_idempotency_denied(self):
        self.lease()
        self.receipt()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.receipt()
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_trusted_host.effect_receipt"
        ).fetchone()[0],1)

    def test_unknown_can_complete_once_only_matching_content_sha(self):
        self.lease()
        self.receipt()
        row=self.conn.execute(
            """UPDATE nf_trusted_host.effect_receipt
               SET status='COMPLETED', receiver_file_sha256=%s,
                   completed_at=clock_timestamp() RETURNING status""",
            ("d"*64,)).fetchone()
        self.assertEqual(row[0],"COMPLETED")
        with self.assertRaises(psycopg.errors.RaiseException):
            self.conn.execute(
                "UPDATE nf_trusted_host.effect_receipt SET status='UNKNOWN'")

    def test_mismatched_file_digest_and_delete_denied(self):
        self.lease()
        self.receipt()
        with self.assertRaises(psycopg.errors.RaiseException):
            self.conn.execute(
                """UPDATE nf_trusted_host.effect_receipt
                   SET status='COMPLETED',receiver_file_sha256=%s,
                       completed_at=clock_timestamp()""",("f"*64,))
        with self.assertRaises(psycopg.errors.RaiseException):
            self.conn.execute("DELETE FROM nf_trusted_host.effect_receipt")

    def test_no_synthetic_fixture_authz_or_live_release_field(self):
        text=SCHEMA_PATH.read_text(encoding="utf-8")
        for phrase in ("nf_test_ephemeral_only","fixture_authorized",
                       "live_execution_allowed", "CREATE ROLE",
                       "CREATE DATABASE", "PASSWORD "):
            self.assertNotIn(phrase,text)
        self.assertIn("OFF-HOST durable witness",text)
        self.assertNotIn("GRANT ALL TO PUBLIC",text)

    def test_sql_backup_rollback_is_not_protected_by_local_triggers(self):
        # Explicitly document the limitation: trusted DBA TRUNCATE is possible
        # in this isolated temporary schema. No production authz may rely on it.
        self.lease()
        self.receipt()
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_trusted_host.effect_receipt"
        ).fetchone()[0],1)
        self.conn.execute("TRUNCATE nf_trusted_host.effect_receipt")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_trusted_host.effect_receipt"
        ).fetchone()[0],0)


if __name__=="__main__":
    unittest.main()
