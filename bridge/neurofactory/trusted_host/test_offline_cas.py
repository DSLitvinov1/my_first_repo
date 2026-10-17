"""Ephemeral PostgreSQL tests only; no production queue, model or publisher."""
import concurrent.futures
import hashlib
import os
import secrets
from pathlib import Path
import unittest
import psycopg

from offline_cas import OfflineCAS, OfflineBoundaryError

TEST_DSN = os.environ.get(
    "NF_EPHEMERAL_POSTGRES_DSN",
    "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"
)

def connect():
    conn = psycopg.connect(TEST_DSN, autocommit=True, connect_timeout=3)
    db = conn.execute("SELECT current_database()").fetchone()[0]
    if db != "nf_test":
        conn.close()
        raise RuntimeError("must never run tests against non-ephemeral database")
    conn.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return conn

class OfflineCASTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = connect()
        cls.admin.execute(Path(__file__).with_name("schema_v1.sql").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        self.conn = connect()
        self.conn.execute("TRUNCATE nf_claim_request, nf_task")
        self.db = OfflineCAS(self.conn)
        self.task_id = "NF-DEV-05-Q001"

    def tearDown(self):
        self.conn.close()

    def seed(self, authorized=True, task_id=None):
        task_id = task_id or self.task_id
        self.conn.execute(
            """INSERT INTO nf_task(
                   task_id, project_id, input_core_sha40,
                   source_file_sha256, input_task_sha256, fixture_authorized)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (task_id, "nf-sandbox", "a"*40, "b"*64, "c"*64, authorized)
        )

    def claim(self, worker="host-1", req=None):
        return self.db.claim(self.task_id, worker, req or secrets.token_hex(16))

    def test_missing_task_rejected(self):
        self.assertEqual(self.claim()["status"], "BLOCKED")
        self.assertEqual(self.db.public_state(self.task_id)["status"],"UNKNOWN")

    def test_not_authorized_cannot_be_claimed(self):
        self.seed(False)
        self.assertEqual(self.claim()["status"], "BLOCKED")

    def test_valid_test_fixture_claims_one_epoch(self):
        self.seed()
        result = self.claim()
        self.assertEqual(result["status"],"CLAIMED")
        self.assertEqual(result["lease_epoch"],1)
        self.assertEqual(self.db.public_state(self.task_id)["status"],"LEASED")
        self.assertEqual(self.db.public_state(self.task_id)["actions_allowed"],False)
        raw_hash = self.conn.execute(
            "SELECT lease_token_sha256 FROM nf_task WHERE task_id=%s",
            (self.task_id,)
        ).fetchone()[0]
        self.assertEqual(raw_hash,hashlib.sha256(result["fencing_token"].encode()).hexdigest())
        self.assertNotEqual(raw_hash,result["fencing_token"])

    def test_two_distinct_connections_one_winner(self):
        self.seed()
        def run(worker):
            with connect() as conn:
                return OfflineCAS(conn).claim(
                    self.task_id, worker, secrets.token_hex(16)
                )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(run,["pc-one","pc-two"]))
        self.assertEqual(sum(x["status"]=="CLAIMED" for x in result),1)
        self.assertEqual(sum(x["status"]=="NOT_CLAIMED" for x in result),1)
        self.assertEqual(self.db.public_state(self.task_id)["epoch"],1)

    def test_duplicate_request_id_never_reissues_token(self):
        self.seed()
        req=secrets.token_hex(16)
        first=self.db.claim(self.task_id,"pc-one",req)
        second=self.db.claim(self.task_id,"pc-one",req)
        self.assertEqual(first["status"],"CLAIMED")
        self.assertEqual(second["status"],"BLOCKED")
        self.assertNotIn("fencing_token",second)
        self.assertEqual(self.db.public_state(self.task_id)["epoch"],1)

    def test_different_worker_with_same_request_id_is_blocked(self):
        self.seed()
        req=secrets.token_hex(16)
        self.db.claim(self.task_id,"pc-one",req)
        self.assertEqual(self.db.claim(self.task_id,"pc-two",req)["status"],"BLOCKED")

    def test_lease_expiry_never_grants_automatic_reclaim(self):
        self.seed()
        self.db.claim(self.task_id,"pc-one",secrets.token_hex(16),lease_seconds=1)
        self.conn.execute(
            "UPDATE nf_task SET lease_deadline=clock_timestamp()-interval '10 seconds' WHERE task_id=%s",
            (self.task_id,)
        )
        self.assertEqual(self.claim("pc-two")["status"],"NOT_CLAIMED")
        self.assertEqual(self.db.public_state(self.task_id)["epoch"],1)

    def test_unknown_result_is_terminal(self):
        self.seed()
        held=self.claim("pc-one")
        self.assertTrue(self.db.mark_unknown(
            self.task_id,"pc-one",held["lease_epoch"],held["fencing_token"]
        ))
        self.assertEqual(self.db.public_state(self.task_id)["status"],"UNKNOWN")
        self.assertEqual(self.claim("pc-two")["status"],"NOT_CLAIMED")

    def test_wrong_holder_or_token_cannot_mark_unknown(self):
        self.seed()
        held=self.claim("pc-one")
        self.assertFalse(self.db.mark_unknown(self.task_id,"pc-two",1,held["fencing_token"]))
        self.assertFalse(self.db.mark_unknown(self.task_id,"pc-one",1,"wrong-token"))
        self.assertFalse(self.db.mark_unknown(self.task_id,"pc-one",2,held["fencing_token"]))
        self.assertEqual(self.db.public_state(self.task_id)["status"],"LEASED")

    def test_other_task_same_request_id_denied(self):
        self.seed()
        self.seed(task_id="NF-DEV-05-Q002")
        req=secrets.token_hex(16)
        self.db.claim(self.task_id,"pc-one",req)
        self.assertEqual(
            self.db.claim("NF-DEV-05-Q002","pc-two",req)["status"],"BLOCKED"
        )

    def test_invalid_lease_boolean_and_request_denied(self):
        self.seed()
        for task,worker,req,duration in (
            (self.task_id,"pc-one",secrets.token_hex(16),True),
            (self.task_id,"pc-one","wrong",30),
            ("NF-DEV-05-Q9999","pc-one",secrets.token_hex(16),30),
            (self.task_id,"bad worker",secrets.token_hex(16),30),
            (self.task_id,"pc-one",secrets.token_hex(16),0)
        ):
            with self.subTest(worker=worker,duration=duration),self.assertRaises(OfflineBoundaryError):
                self.db.claim(task,worker,req,lease_seconds=duration)
        self.assertEqual(self.db.public_state(self.task_id)["epoch"],0)

    def test_no_prior_signature_or_authorization_from_digest(self):
        self.seed(False)
        self.assertEqual(self.claim()["status"],"BLOCKED")
        self.assertEqual(self.db.public_state(self.task_id)["verified"],False)

    def test_reject_non_offline_connection(self):
        raw=psycopg.connect(TEST_DSN, autocommit=True, connect_timeout=3)
        try:
            with self.assertRaises(OfflineBoundaryError):
                OfflineCAS(raw)
        finally:
            raw.close()

    def test_duplicate_task_id_different_payload_rejected_by_database(self):
        self.seed()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.conn.execute(
                """INSERT INTO nf_task(task_id,project_id,input_core_sha40,source_file_sha256,input_task_sha256)
                   VALUES(%s,%s,%s,%s,%s)""",
                (self.task_id,"nf-sandbox","d"*40,"e"*64,"f"*64)
            )

if __name__=="__main__":
    unittest.main()
