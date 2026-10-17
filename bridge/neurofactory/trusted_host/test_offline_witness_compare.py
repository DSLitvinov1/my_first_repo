"""Targeted isolated PostgreSQL + ephemeral Ed25519 witness negative cases."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest
import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_offline_highwater import open_fixture,TASK,ZERO,A,B
from offline_highwater import OfflineHighwater
from offline_witness_compare import (
    OfflineWitnessError,compare_signed_witness_to_ephemeral_postgres
)

class OfflineExternalWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin=open_fixture()
        for name in ("schema_v1.sql","offline_highwater_schema.sql"):
            cls.admin.execute((Path(__file__).parent/name).read_text())

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        self.cn=open_fixture()
        self.cn.execute(
            "TRUNCATE nf_offline_chain_event,nf_offline_chain_head,nf_claim_request,nf_task"
        )
        self.cn.execute(
            """INSERT INTO nf_task(task_id,project_id,input_core_sha40,
            source_file_sha256,input_task_sha256)
            VALUES (%s,'nf-sandbox',%s,%s,%s)""",
            (TASK,"a"*40,"b"*64,"c"*64)
        )
        self.store=OfflineHighwater(self.cn)
        self.store.append(TASK,1,ZERO,A)
        self.store.append(TASK,2,A,B)
        self.key=Ed25519PrivateKey.generate()
        self.expected=dict(
            expected_task_id=TASK,expected_project_id="nf-sandbox",
            expected_core_sha40="a"*40,
            expected_source_file_sha256="b"*64,
            expected_input_task_sha256="c"*64,
            expected_policy_sha256="d"*64,
            expected_witness_identity="separate-test-witness",
            expected_witness_key_id="test-only-key-01",
            externally_pinned_next_witness_sequence=7,
            externally_pinned_previous_witness_sha256="e"*64
        )
        self.payload=dict(
            schema="neurofactory.trusted_host.offline_external_witness.v1",
            task_id=TASK,project_id="nf-sandbox",
            input_core_sha40="a"*40,source_file_sha256="b"*64,
            input_task_sha256="c"*64,policy_sha256="d"*64,
            witness_identity="separate-test-witness",
            witness_key_id="test-only-key-01",witness_sequence=7,
            previous_witness_sha256="e"*64,
            checkpoint_sequence=2,checkpoint_sha256=B,
            issued_at_utc="2026-10-15T12:00:00Z",
            purpose="OFFLINE_CHECKPOINT_COMPARISON_ONLY"
        )

    def tearDown(self):
        self.cn.close()

    def signed(self,payload=None,key=None):
        payload=copy.deepcopy(self.payload if payload is None else payload)
        canonical=json.dumps(payload,sort_keys=True,separators=(",",":"),
                             ensure_ascii=True,allow_nan=False).encode("ascii")
        private=key if key is not None else self.key
        return {"payload":payload,
                "signature_base64":base64.b64encode(private.sign(canonical)).decode("ascii")}

    def check(self,receipt=None,conn=None,expected=None,key=None):
        return compare_signed_witness_to_ephemeral_postgres(
            self.cn if conn is None else conn,
            self.key.public_key() if key is None else key,
            self.signed() if receipt is None else receipt,
            **(self.expected if expected is None else expected)
        )

    def test_current_signed_witness_matches_but_never_authorizes(self):
        result=self.check()
        self.assertEqual(result["status"],"SIGNED_WITNESS_MATCHES_TEST_DB")
        self.assertEqual(result["checkpoint_matches_signed_witness"],True)
        for name in ("externally_pinned_key_provenance_attested",
                     "externally_pinned_witness_sequence_durably_protected",
                     "independent_host_operator_approval","live_execution_allowed",
                     "publication_allowed","automatic_retry_allowed"):
            self.assertIs(result[name],False)
        self.assertEqual(result["handoff"],"PAUSED_BY_USER")

    def test_db_admin_coherent_rollback_refused_by_original_signed_witness(self):
        self.cn.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s AND sequence=2",(TASK,))
        self.cn.execute(
            "UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s",
            (A,TASK)
        )
        result=self.check()
        self.assertEqual(result["status"],"UNKNOWN_OR_ROLLBACK")
        self.assertFalse(result["checkpoint_matches_signed_witness"])

    def test_db_admin_rewrite_new_second_receipt_detected(self):
        self.cn.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s AND sequence=2",(TASK,))
        self.cn.execute(
            "UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s",(A,TASK)
        )
        alternative="f"*64
        self.store.append(TASK,2,A,alternative)
        self.assertEqual(self.check()["status"],"UNKNOWN_OR_ROLLBACK")

    def test_fake_signer_denied(self):
        self.assertRaises(OfflineWitnessError,self.check,
                          receipt=self.signed(key=Ed25519PrivateKey.generate()))

    def test_signed_older_witness_denied_by_separate_sequence_pin(self):
        p=copy.deepcopy(self.payload)
        p["witness_sequence"]=6
        with self.assertRaises(OfflineWitnessError):
            self.check(receipt=self.signed(p))

    def test_attacker_self_updates_expected_sequence_not_proof_of_pin(self):
        p=copy.deepcopy(self.payload)
        p["witness_sequence"]=6
        e=dict(self.expected,externally_pinned_next_witness_sequence=6)
        result=self.check(receipt=self.signed(p),expected=e)
        self.assertEqual(result["status"],"SIGNED_WITNESS_MATCHES_TEST_DB")
        self.assertIs(result["externally_pinned_witness_sequence_durably_protected"],False)

    def test_payload_tamper_after_signing_denied(self):
        r=self.signed()
        r["payload"]["checkpoint_sha256"]="f"*64
        with self.assertRaises(OfflineWitnessError):
            self.check(receipt=r)

    def test_wrong_task_policy_or_project_external_pin_denied(self):
        for k,v in (("expected_task_id","NF-DEV-05-Q002"),
                    ("expected_policy_sha256","9"*64),
                    ("expected_project_id","different-project")):
            with self.subTest(k=k),self.assertRaises(OfflineWitnessError):
                self.check(expected=dict(self.expected,**{k:v}))

    def test_bool_and_float_witness_sequence_denied(self):
        for v in (True,7.0,"7"):
            p=copy.deepcopy(self.payload)
            p["witness_sequence"]=v
            with self.subTest(v=str(v)),self.assertRaises(OfflineWitnessError):
                self.check(receipt=self.signed(p))

    def test_unexpected_approval_field_and_unknown_purpose_denied(self):
        for extra in ("owner_approved","publisher_allowed","review_verdict"):
            p=copy.deepcopy(self.payload);p[extra]=True
            with self.subTest(key=extra),self.assertRaises(OfflineWitnessError):
                self.check(receipt=self.signed(p))
        p=copy.deepcopy(self.payload);p["purpose"]="AUTHORIZE_LIVE"
        with self.assertRaises(OfflineWitnessError):
            self.check(receipt=self.signed(p))

    def test_invalid_base64_and_wrong_public_key_denied(self):
        r=self.signed()
        r["signature_base64"]="wrong!"
        with self.assertRaises(OfflineWitnessError):self.check(receipt=r)
        with self.assertRaises(OfflineWitnessError):
            self.check(key=Ed25519PrivateKey.generate().public_key())

    def test_untrusted_db_session_rejected(self):
        raw=psycopg.connect(
            "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test",
            autocommit=True,connect_timeout=3)
        try:
            with self.assertRaises(OfflineWitnessError):
                self.check(conn=raw)
        finally:
            raw.close()

    def test_bad_witness_previous_digest_denied(self):
        p=copy.deepcopy(self.payload)
        p["previous_witness_sha256"]="f"*64
        with self.assertRaises(OfflineWitnessError):
            self.check(receipt=self.signed(p))

    def test_db_read_only_comparison_does_not_mutate_history(self):
        before=self.cn.execute(
            "SELECT last_sequence,last_digest_sha256 FROM nf_offline_chain_head WHERE task_id=%s",(TASK,)
        ).fetchone()
        count=self.cn.execute("SELECT COUNT(*) FROM nf_offline_chain_event WHERE task_id=%s",(TASK,)).fetchone()[0]
        self.check()
        after=self.cn.execute(
            "SELECT last_sequence,last_digest_sha256 FROM nf_offline_chain_head WHERE task_id=%s",(TASK,)
        ).fetchone()
        count2=self.cn.execute("SELECT COUNT(*) FROM nf_offline_chain_event WHERE task_id=%s",(TASK,)).fetchone()[0]
        self.assertEqual(before,after)
        self.assertEqual(count,count2)

if __name__=="__main__":
    unittest.main()
