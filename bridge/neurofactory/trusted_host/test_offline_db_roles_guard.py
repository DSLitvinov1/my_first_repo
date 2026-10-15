"""Ephemeral PostgreSQL DB privilege test; NOT host OS or issuer attestation."""
import pathlib
import unittest
import psycopg

from test_offline_highwater import open_fixture, TASK, ZERO, A, B
from offline_highwater import OfflineHighwater

HERE = pathlib.Path(__file__).parent

class DBRoleBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin=open_fixture()
        for file in ("schema_v1.sql","offline_highwater_schema.sql",
                     "offline_db_roles_guard.sql"):
            cls.admin.execute((HERE/file).read_text())

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        self.cn=open_fixture()
        self.cn.execute("TRUNCATE nf_offline_chain_event,nf_offline_chain_head,nf_claim_request,nf_task")
        self.cn.execute(
            """INSERT INTO nf_task(task_id,project_id,input_core_sha40,
               source_file_sha256,input_task_sha256)
               VALUES(%s,'nf-sandbox',%s,%s,%s)""",
            (TASK,"d"*40,"e"*64,"f"*64))

    def tearDown(self):
        self.cn.close()

    def as_reader(self,sql,args=()):
        with self.cn.transaction():
            self.cn.execute("SET LOCAL ROLE nf_offline_checkpoint_reader")
            return self.cn.execute(sql,args).fetchall()

    def as_writer(self,fn):
        with self.cn.transaction():
            self.cn.execute("SET LOCAL ROLE nf_offline_checkpoint_writer")
            return fn()

    def test_reader_can_observe_empty_head_only(self):
        self.assertEqual(self.as_reader("SELECT * FROM nf_offline_chain_head"),[])
        self.assertEqual(self.as_reader("SELECT * FROM nf_offline_chain_event"),[])

    def test_reader_cannot_create_head(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.as_reader("INSERT INTO nf_offline_chain_head(task_id) VALUES(%s) RETURNING task_id",(TASK,))

    def test_reader_cannot_write_event(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.as_reader(
                """INSERT INTO nf_offline_chain_event(task_id,sequence,prior_digest_sha256,receipt_digest_sha256)
                   VALUES (%s,1,%s,%s) RETURNING task_id""",(TASK,ZERO,A))

    def test_restricted_writer_can_use_existing_offline_append(self):
        def perform():
            return OfflineHighwater(self.cn).append(TASK,1,ZERO,A)
        first=self.as_writer(perform)
        self.assertEqual(first["status"],"RECORDED_TEST_ONLY")
        self.assertIs(first["live_authorization"],False)
        self.assertEqual(self.as_reader("SELECT last_sequence FROM nf_offline_chain_head"),[(1,)])

    def test_restricted_writer_cannot_delete_historical_event(self):
        OfflineHighwater(self.cn).append(TASK,1,ZERO,A)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.as_writer(lambda:self.cn.execute(
                "DELETE FROM nf_offline_chain_event WHERE task_id=%s",(TASK,)))

    def test_restricted_writer_cannot_rollback_head(self):
        store=OfflineHighwater(self.cn)
        store.append(TASK,1,ZERO,A)
        store.append(TASK,2,A,B)
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.as_writer(lambda:self.cn.execute(
                "UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s",(A,TASK)))
        self.assertEqual(self.as_reader("SELECT last_sequence FROM nf_offline_chain_head"),[(2,)])

    def test_restricted_writer_cannot_skip_ahead(self):
        OfflineHighwater(self.cn).append(TASK,1,ZERO,A)
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.as_writer(lambda:self.cn.execute(
                "UPDATE nf_offline_chain_head SET last_sequence=8,last_digest_sha256=%s WHERE task_id=%s",(B,TASK)))

    def test_restricted_writer_cannot_forge_task_authorization(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.as_writer(lambda:self.cn.execute(
                "UPDATE nf_task SET fixture_authorized=TRUE WHERE task_id=%s",(TASK,)))
        self.assertFalse(self.cn.execute(
            "SELECT fixture_authorized FROM nf_task WHERE task_id=%s",(TASK,)
        ).fetchone()[0])

    def test_restricted_writer_duplicate_receipt_is_rejected(self):
        OfflineHighwater(self.cn).append(TASK,1,ZERO,A)
        result=self.as_writer(lambda:OfflineHighwater(self.cn).append(TASK,1,ZERO,A))
        self.assertEqual(result["status"],"BLOCKED")

    def test_reader_cannot_promote_role(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.cn.transaction():
                self.cn.execute("SET LOCAL ROLE nf_offline_checkpoint_reader")
                self.cn.execute("SET LOCAL ROLE nf_offline_checkpoint_writer")
           
    def test_table_owner_can_disable_guard_so_not_real_antirollback(self):
        store=OfflineHighwater(self.cn)
        store.append(TASK,1,ZERO,A)
        store.append(TASK,2,A,B)
        with self.cn.transaction():
            self.cn.execute("ALTER TABLE nf_offline_chain_head DISABLE TRIGGER nf_offline_head_forward_only")
            self.cn.execute("ALTER TABLE nf_offline_chain_event DISABLE TRIGGER nf_offline_event_no_mutation")
            self.cn.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s AND sequence=2",(TASK,))
            self.cn.execute("UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s",(A,TASK))
            self.cn.execute("ALTER TABLE nf_offline_chain_head ENABLE TRIGGER nf_offline_head_forward_only")
            self.cn.execute("ALTER TABLE nf_offline_chain_event ENABLE TRIGGER nf_offline_event_no_mutation")
        observed=store.observe(TASK,2,B)
        self.assertEqual(observed["status"],"UNKNOWN_OR_MISMATCH")
        self.assertFalse(observed["independent_pin_source_authenticated"])

if __name__=="__main__":
    unittest.main()
