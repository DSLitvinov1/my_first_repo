"""Ephemeral PostgreSQL persistence and replay checks, NOT external antirollback."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import unittest
import psycopg
from offline_highwater import OfflineHighwater,OfflineHighwaterError

DSN=os.environ.get(
    "NF_EPHEMERAL_POSTGRES_DSN",
    "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test")
TASK="NF-DEV-05-Q001"
ZERO="0"*64
A="a"*64
B="b"*64

def open_fixture():
    cn=psycopg.connect(DSN,autocommit=True,connect_timeout=3)
    if cn.execute("SELECT current_database()").fetchone()[0]!="nf_test":
        cn.close()
        raise RuntimeError("non-test database prohibited")
    cn.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return cn

class HighwaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin=open_fixture()
        directory=Path(__file__).parent
        cls.admin.execute((directory/"schema_v1.sql").read_text())
        cls.admin.execute((directory/"offline_highwater_schema.sql").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        self.cn=open_fixture()
        self.cn.execute("TRUNCATE nf_offline_chain_event,nf_offline_chain_head,nf_claim_request,nf_task")
        self.cn.execute(
            """INSERT INTO nf_task(task_id,project_id,input_core_sha40,
               source_file_sha256,input_task_sha256,fixture_authorized)
               VALUES(%s,'nf-sandbox',%s,%s,%s,FALSE)""",
            (TASK,"d"*40,"e"*64,"f"*64))
        self.store=OfflineHighwater(self.cn)

    def tearDown(self):
        self.cn.close()

    def test_initial_record_and_cross_connection_persistence(self):
        x=self.store.append(TASK,1,ZERO,A)
        self.assertEqual(x["status"],"RECORDED_TEST_ONLY")
        self.assertFalse(x["live_authorization"])
        with open_fixture() as second:
            y=OfflineHighwater(second).observe(TASK,1,A)
            self.assertTrue(y["reported_head_matches_supplied_pin"])
            self.assertFalse(y["publisher_allowed"])

    def test_strict_next_sequence_and_matching_parent(self):
        self.store.append(TASK,1,ZERO,A)
        self.assertEqual(self.store.append(TASK,3,A,B)["status"],"BLOCKED")
        self.assertEqual(self.store.append(TASK,2,B,B)["status"],"BLOCKED")
        self.assertEqual(self.store.append(TASK,2,A,B)["status"],"RECORDED_TEST_ONLY")

    def test_replayed_receipt_never_appends_again(self):
        self.store.append(TASK,1,ZERO,A)
        self.assertEqual(self.store.append(TASK,1,ZERO,A)["status"],"BLOCKED")
        self.assertEqual(self.store.append(TASK,2,A,A)["status"],"BLOCKED")
        self.assertEqual(self.cn.execute("SELECT COUNT(*) FROM nf_offline_chain_event").fetchone()[0],1)

    def test_two_connections_compete_one_wins_next_sequence(self):
        def append_from_second():
            with open_fixture() as conn:
                return OfflineHighwater(conn).append(TASK,1,ZERO,A)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            x=list(pool.map(lambda _:append_from_second(),range(2)))
        self.assertEqual(sum(v["status"]=="RECORDED_TEST_ONLY" for v in x),1)
        self.assertEqual(sum(v["status"]=="BLOCKED" for v in x),1)
        self.assertEqual(self.cn.execute("SELECT COUNT(*) FROM nf_offline_chain_event").fetchone()[0],1)

    def test_missing_task_denies_append(self):
        self.assertEqual(self.store.append("NF-DEV-05-Q002",1,ZERO,A)["status"],"BLOCKED")

    def test_boolean_or_float_seq_denied(self):
        for bad in (True,1.0,"1",0,-1):
            with self.subTest(value=str(bad)),self.assertRaises(OfflineHighwaterError):
                self.store.append(TASK,bad,ZERO,A)

    def test_invalid_digest_or_task_denied(self):
        for task,prior in ((TASK,"A"*64),(TASK,"x"),("bad task",ZERO)):
            with self.subTest(task=task),self.assertRaises(OfflineHighwaterError):
                self.store.append(task,1,prior,A)

    def test_stale_external_checkpoint_observation_cannot_authorize(self):
        self.store.append(TASK,1,ZERO,A)
        self.store.append(TASK,2,A,B)
        stale=self.store.observe(TASK,1,A)
        self.assertEqual(stale["status"],"UNKNOWN_OR_MISMATCH")
        self.assertFalse(stale["independent_pin_source_authenticated"])
        self.assertFalse(stale["automatic_retry_allowed"])

    def test_coherent_database_admin_mutation_is_not_falsely_attested(self):
        self.store.append(TASK,1,ZERO,A)
        self.store.append(TASK,2,A,B)
        # DB admin CAN rewrite both, so this module cannot claim real antirollback.
        self.cn.execute("UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s",(A,TASK))
        self.cn.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s AND sequence=2",(TASK,))
        self.assertEqual(self.store.observe(TASK,2,B)["status"],"UNKNOWN_OR_MISMATCH")
        self.assertFalse(self.store.observe(TASK,1,A)["independent_pin_source_authenticated"])

    def test_missing_offline_fixture_context_denied(self):
        raw=psycopg.connect(DSN,autocommit=True,connect_timeout=3)
        try:
            with self.assertRaises(OfflineHighwaterError):
                OfflineHighwater(raw)
        finally:
            raw.close()

    def test_empty_observation_is_unknown_not_approval(self):
        s=self.store.observe(TASK,0,ZERO)
        self.assertEqual(s["status"],"UNKNOWN_OR_MISMATCH")
        self.assertFalse(s["publisher_allowed"])

    def test_separate_task_cannot_overwrite_other_head(self):
        self.store.append(TASK,1,ZERO,A)
        self.cn.execute(
            """INSERT INTO nf_task(task_id,project_id,input_core_sha40,
            source_file_sha256,input_task_sha256) VALUES(%s,'nf-sandbox',%s,%s,%s)""",
            ("NF-DEV-05-Q002","d"*40,"e"*64,"f"*64))
        self.assertEqual(self.store.append("NF-DEV-05-Q002",1,ZERO,B)["status"],"RECORDED_TEST_ONLY")
        self.assertTrue(self.store.observe(TASK,1,A)["reported_head_matches_supplied_pin"])
        self.assertTrue(self.store.observe("NF-DEV-05-Q002",1,B)["reported_head_matches_supplied_pin"])

if __name__=="__main__":
    unittest.main()
