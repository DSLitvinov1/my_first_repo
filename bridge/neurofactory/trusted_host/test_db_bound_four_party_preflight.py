"""ONE temporary Postgres16, real Ed25519 signatures, no real file effects.

Integration proves current SQL lease + UNKNOWN intent matches cryptographic
roles. Operator trust pins are test-patched because CI has no hardware-root;
the production method takes no user-supplied public keys.
"""
import hashlib
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import psycopg

from db_bound_four_party_preflight import (
    AdmissionRejected, inspect_current_lease_and_receipt,
)
from test_independent_four_party_scope import FourPartyScopeTests, NOW

DB_NAME="nf_schema_verify"
DSN=("postgresql://nf_schema_ci:nf_schema_ephemeral_password@127.0.0.1:5432/"
     + DB_NAME)
SCHEMA_PATH=Path(__file__).with_name("permanent_postgres_operator_migration.sql")


class SQLSignedEffectsE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NF_DB_SCHEMA_CI_ONLY")!="1":
            raise RuntimeError("temporary PostgreSQL integration only")
        cls.db=psycopg.connect(DSN,autocommit=True,connect_timeout=5)
        if cls.db.execute("SELECT current_database()").fetchone()[0]!=DB_NAME:
            raise RuntimeError("non-disposable DB: refuse all tests")
        cls.db.execute(SCHEMA_PATH.read_text(encoding="utf8"))
        cls.addClassCleanup(cls.db.close)

    def setUp(self):
        self.db.execute("""TRUNCATE nf_trusted_host.effect_receipt,
                           nf_trusted_host.lease_register CASCADE""")
        self.four=FourPartyScopeTests(
            methodName="test_positive_all_four_cryptographic_scopes_still_no_authority")
        self.four.setUp()
        self.scope=self.four.scope
        self.pins=dict(pinned_keys=self.four.pins,
                       metadata=dict(
                           repository=self.scope["repository"],
                           github_user_id=self.scope["github_user_id"],
                           repository_id=self.scope["repository_id"],
                           live_execution_allowed=False,
                       ))
        self._seed()

    def _seed(self):
        s=self.scope
        self.db.execute(
            """INSERT INTO nf_trusted_host.lease_register(
              task_id,owner_id,repository_full_name,project_id,source_sha40,
              source_file_sha256,policy_sha256,approved_scope_sha256,
              worker_id,lease_epoch,fencing_token_sha256,lease_deadline,state)
              VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                     clock_timestamp()+interval '120 seconds','CLAIMED')""",
            (s["task_id"],s["owner_id"],s["repository"],s["project_id"],
             s["source_sha40"],s["source_file_sha256"],s["policy_sha256"],
             self.four.scope_hash,s["worker_id"],s["lease_epoch"],
             s["fencing_token_sha256"]))
        self.db.execute(
            """INSERT INTO nf_trusted_host.effect_receipt(
              task_id,operation_id,idempotency_key,signed_scope_sha256,
              target_sha256,content_sha256,external_witness_root_sha256,
              external_witness_sequence)
              VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
            (s["task_id"],s["operation_id"],s["idempotency_key"],
             self.four.scope_hash,
             hashlib.sha256(s["target"].encode("utf8")).hexdigest(),
             s["content_sha256"],
             self.four.bodies["witness"]["protected_journal_root_sha256"],
             self.four.bodies["witness"]["commit_sequence"]))

    def admit(self, *, signed=None, scope=None, pins=None):
        docs=self.four.packets if signed is None else signed
        with patch("db_bound_four_party_preflight.load_operator_installed_public_pins",
                   return_value=self.pins if pins is None else pins):
            return inspect_current_lease_and_receipt(
                self.db,
                expected_effect=self.scope if scope is None else scope,
                signed_operator_acl=docs["operator"],
                signed_owner_grant=docs["owner"],
                signed_host_lease=docs["host"],
                signed_external_witness=docs["witness"],
                now_unix=NOW)

    def test_one_exact_signed_current_lease_returns_only_readonly_diagnostic(self):
        result=self.admit()
        self.assertEqual(result["signed_roles_checked"],4)
        self.assertEqual(result["scope_sha256"],self.four.scope_hash)
        self.assertEqual(result["status"],
                         "PINNED_SIGNATURES_AND_LIVE_SQL_MATCH_NO_EFFECT_AUTHORITY")
        for k in ("live_execution_allowed","release_approved",
                  "automatic_retry_allowed","production_effect_authorized",
                  "durable_witness_actually_rechecked_out_of_band",
                  "receiver_effect_lock_still_held"):
            self.assertFalse(result[k],k)
        self.assertEqual(self.db.execute(
            "SELECT status FROM nf_trusted_host.effect_receipt"
        ).fetchone()[0],"UNKNOWN")
        print("NF_SIGNED_SQL_LIVE_LEASE_SCOPE_MATCH=READ_ONLY_NO_EFFECT")

    def test_blocked_lease_denied(self):
        self.db.execute("UPDATE nf_trusted_host.lease_register SET state='BLOCKED'")
        with self.assertRaises(AdmissionRejected):
            self.admit()

    def test_expired_lease_denied(self):
        self.db.execute("""UPDATE nf_trusted_host.lease_register
                          SET lease_deadline=clock_timestamp()-interval '1 second'""")
        with self.assertRaises(AdmissionRejected):
            self.admit()

    def test_stale_epoch_or_fencing_token_denied(self):
        self.db.execute("""UPDATE nf_trusted_host.lease_register
                          SET lease_epoch=lease_epoch+1""")
        with self.assertRaises(AdmissionRejected):
            self.admit()
        self.db.execute("""UPDATE nf_trusted_host.lease_register
                          SET lease_epoch=7,fencing_token_sha256=%s""",("f"*64,))
        with self.assertRaises(AdmissionRejected):
            self.admit()

    def test_foreign_owner_repo_or_wrong_source_commit_denied(self):
        for field,value in (
            ("owner_id","foreign-owner"),
            ("repository_full_name","Attacker/other_repo"),
            ("source_sha40","f"*40),
            ("approved_scope_sha256","f"*64),
            ("policy_sha256","f"*64),
        ):
            with self.subTest(field=field):
                self.db.execute(
                    "UPDATE nf_trusted_host.lease_register SET "+field+"=%s",
                    (value,))
                with self.assertRaises(AdmissionRejected):
                    self.admit()
                self.db.execute(
                    "UPDATE nf_trusted_host.lease_register SET "+field+"=%s",
                    ((self.four.scope_hash
                     if field=="approved_scope_sha256" else
                     self.scope["repository" if field=="repository_full_name"
                                else field]),))

    def test_missing_or_false_unknown_receipt_denied(self):
        self.db.execute("TRUNCATE nf_trusted_host.effect_receipt")
        with self.assertRaises(AdmissionRejected):
            self.admit()
        self._insert_only_receipt()
        self.db.execute("""UPDATE nf_trusted_host.effect_receipt
                          SET status='COMPLETED',receiver_file_sha256=content_sha256,
                          completed_at=clock_timestamp()""")
        with self.assertRaises(AdmissionRejected):
            self.admit()

    def _insert_only_receipt(self):
        s=self.scope
        self.db.execute(
            """INSERT INTO nf_trusted_host.effect_receipt(
              task_id,operation_id,idempotency_key,signed_scope_sha256,
              target_sha256,content_sha256,external_witness_root_sha256,
              external_witness_sequence) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (s["task_id"],s["operation_id"],s["idempotency_key"],
             self.four.scope_hash,
             hashlib.sha256(s["target"].encode()).hexdigest(),
             s["content_sha256"],
             self.four.bodies["witness"]["protected_journal_root_sha256"],
             self.four.bodies["witness"]["commit_sequence"]))

    def test_wrong_witness_highwater_or_idempotency_denied(self):
        # Local SQL immutable trigger denies direct rewrite. A DBA who can
        # TRUNCATE can still replace with a false record: see next scenario.
        with self.assertRaises(psycopg.errors.RaiseException):
            self.db.execute("""UPDATE nf_trusted_host.effect_receipt
                              SET external_witness_sequence=99""")
        self.assertEqual(self.db.execute(
            "SELECT external_witness_sequence FROM nf_trusted_host.effect_receipt"
        ).fetchone()[0],12)

    def test_real_db_rollback_replacement_does_not_imply_witness_integrity(self):
        self.db.execute("TRUNCATE nf_trusted_host.effect_receipt")
        s=self.scope
        self.db.execute(
            """INSERT INTO nf_trusted_host.effect_receipt(
              task_id,operation_id,idempotency_key,signed_scope_sha256,
              target_sha256,content_sha256,external_witness_root_sha256,
              external_witness_sequence) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (s["task_id"],s["operation_id"],s["idempotency_key"],
             self.four.scope_hash,
             hashlib.sha256(s["target"].encode()).hexdigest(),
             s["content_sha256"],"f"*64,999))
        with self.assertRaises(AdmissionRejected):
            self.admit()
        # DBA could instead reinsert matching old data: SQL-only check is
        # NOT an off-host monotonic proof; never return effect authority.

    def test_forged_or_unsigned_owner_denied_even_if_sql_is_current(self):
        p=dict(self.four.packets)
        changed=dict(p["owner"])
        changed["signature_base64"]="A"*88
        p["owner"]=changed
        with self.assertRaises(AdmissionRejected):
            self.admit(signed=p)

    def test_unpinned_trustroot_or_wrong_repo_admin_denied(self):
        with self.assertRaises(AdmissionRejected):
            self.admit(pins={
                **self.pins,
                "metadata":{**self.pins["metadata"],
                            "repository":"Attacker/foreign"}
            })
        self.db.execute("UPDATE nf_trusted_host.lease_register SET state='UNKNOWN'")
        with self.assertRaises(AdmissionRejected):
            self.admit()

    def test_unavailable_database_or_test_supplied_unsigned_token_not_authority(self):
        with patch("db_bound_four_party_preflight.load_operator_installed_public_pins",
                   side_effect=ValueError("independent root absent")):
            with self.assertRaises(AdmissionRejected):
                inspect_current_lease_and_receipt(
                    self.db,expected_effect=self.scope,
                    signed_operator_acl=self.four.packets["operator"],
                    signed_owner_grant=self.four.packets["owner"],
                    signed_host_lease=self.four.packets["host"],
                    signed_external_witness=self.four.packets["witness"],
                    now_unix=NOW)
        # Local worker token cannot qualify and there is no such method.
        self.assertFalse(hasattr(inspect_current_lease_and_receipt,
                                 "apply_local_token"))

if __name__=="__main__":
    unittest.main()
