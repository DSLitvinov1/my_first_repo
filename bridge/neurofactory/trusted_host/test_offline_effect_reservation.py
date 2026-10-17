"""Targeted ephemeral PostgreSQL tests, no real effect or protected issuer."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import secrets
import unittest

import psycopg

from offline_cas import OfflineCAS
from offline_effect_reservation import (
    OfflineEffectReservation, OfflineEffectBoundaryError,
)

DSN = os.environ.get(
    "NF_EPHEMERAL_POSTGRES_DSN",
    "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test",
)
TASK = "NF-DEV-05-Q901"
PROJECT = "nf-sandbox"
SOURCE = "a" * 40
FILE = "b" * 64
INPUT = "c" * 64
POLICY = "d" * 64
TARGET = "bridge/neurofactory/development/core_owned/one_synthetic_transaction.py"


def connect():
    conn = psycopg.connect(DSN, autocommit=True, connect_timeout=3)
    if conn.execute("SELECT current_database()").fetchone()[0] != "nf_test":
        conn.close()
        raise RuntimeError("ephemeral nf_test database only")
    conn.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return conn


class OfflineEffectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with connect() as c:
            c.execute(Path(__file__).with_name("schema_v1.sql").read_text())
            c.execute(Path(__file__).with_name(
                "offline_effect_reservation_schema.sql").read_text())

    def setUp(self):
        self.conn = connect()
        self.conn.execute("TRUNCATE nf_effect_intent,nf_effect_scope_fixture,"
                          "nf_claim_request,nf_task")
        self.cas = OfflineCAS(self.conn)
        self.gate = OfflineEffectReservation(self.conn)

    def tearDown(self):
        self.conn.close()

    def seed(self, task=TASK, *, task_authorized=True,
             scope_authorized=True):
        self.conn.execute(
            """INSERT INTO nf_task(task_id,project_id,input_core_sha40,
                 source_file_sha256,input_task_sha256,fixture_authorized)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (task, PROJECT, SOURCE, FILE, INPUT, task_authorized))
        self.conn.execute(
            """INSERT INTO nf_effect_scope_fixture
                 (task_id,project_id,input_core_sha40,source_file_sha256,
                  input_task_sha256,target,policy_sha256,fixture_authorized)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (task, PROJECT, SOURCE, FILE, INPUT, TARGET, POLICY,
             scope_authorized))

    def claim(self, task=TASK, worker="worker-1"):
        return self.cas.claim(task, worker, secrets.token_hex(16))

    def args(self, claim, *, task=TASK, worker="worker-1", **changes):
        values = dict(task_id=task, project_id=PROJECT, source_sha40=SOURCE,
                      source_file_sha256=FILE, input_task_sha256=INPUT,
                      target=TARGET, policy_sha256=POLICY, worker_id=worker,
                      lease_epoch=claim["lease_epoch"],
                      fencing_token=claim["fencing_token"],
                      idempotency_key=secrets.token_hex(32))
        values.update(changes)
        return values

    def test_one_reservation_is_not_execution_authorization(self):
        self.seed()
        claim = self.claim()
        got = self.gate.reserve_once(**self.args(claim))
        self.assertEqual(got["status"], "RESERVED_OFFLINE_TEST_ONLY")
        self.assertFalse(got["execution_allowed"])
        self.assertFalse(got["real_owner_authenticated"])
        self.assertFalse(got["real_recipient_fencing"])
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0], 1)

    def test_host_blocked_cannot_reserve(self):
        self.seed(task_authorized=False)
        # A forged client-supplied token cannot manufacture a lease.
        bad = dict(task_id=TASK, project_id=PROJECT, source_sha40=SOURCE,
                   source_file_sha256=FILE, input_task_sha256=INPUT,
                   target=TARGET, policy_sha256=POLICY, worker_id="worker-1",
                   lease_epoch=1, fencing_token="x"*40,
                   idempotency_key="f"*64)
        self.assertEqual(self.gate.reserve_once(**bad)["status"], "DENIED")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0], 0)

    def test_host_unknown_denies_reservation(self):
        self.seed()
        claimed = self.claim()
        self.assertTrue(self.cas.mark_unknown(TASK, "worker-1",
                        claimed["lease_epoch"], claimed["fencing_token"]))
        self.assertEqual(self.gate.reserve_once(
            **self.args(claimed))["reason"], "HOST_NOT_LEASED_OR_UNKNOWN")

    def test_expired_lease_denies_pre_effect(self):
        self.seed()
        claimed = self.claim()
        self.conn.execute(
            "UPDATE nf_task SET lease_deadline=clock_timestamp()-interval '2 seconds' "
            "WHERE task_id=%s", (TASK,))
        self.assertEqual(self.gate.reserve_once(
            **self.args(claimed))["reason"], "LEASE_EXPIRED")

    def test_loser_worker_stale_epoch_and_wrong_token_denied(self):
        self.seed()
        claimed = self.claim()
        for change in ({"worker_id":"worker-2"},
                       {"lease_epoch":2},
                       {"fencing_token":"z"*40}):
            with self.subTest(change=change):
                result = self.gate.reserve_once(
                    **self.args(claimed, **change))
                self.assertEqual(result["reason"], "STALE_OR_FORGED_LEASE")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0], 0)

    def test_same_task_retry_and_changed_idempotency_denied(self):
        self.seed()
        claimed = self.claim()
        once = self.args(claimed)
        self.assertEqual(self.gate.reserve_once(
            **once)["status"], "RESERVED_OFFLINE_TEST_ONLY")
        self.assertEqual(self.gate.reserve_once(
            **once)["reason"], "EFFECT_INTENT_ALREADY_CONSUMED")
        self.assertEqual(self.gate.reserve_once(
            **self.args(claimed))["reason"], "EFFECT_INTENT_ALREADY_CONSUMED")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0], 1)

    def test_cross_task_duplicate_idempotency_denied(self):
        self.seed()
        self.seed(task="NF-DEV-05-Q902")
        a = self.claim()
        b = self.claim(task="NF-DEV-05-Q902", worker="worker-2")
        key = "e"*64
        self.assertEqual(self.gate.reserve_once(
            **self.args(a,idempotency_key=key))["status"],
            "RESERVED_OFFLINE_TEST_ONLY")
        self.assertEqual(self.gate.reserve_once(
            **self.args(b,task="NF-DEV-05-Q902",worker="worker-2",
                        idempotency_key=key))["reason"],
            "EFFECT_INTENT_ALREADY_CONSUMED")

    def test_wrong_source_project_scope_target_policy_denied(self):
        self.seed()
        claimed = self.claim()
        for change in ({"project_id":"evil-project"},
                       {"source_sha40":"e"*40},
                       {"source_file_sha256":"e"*64},
                       {"input_task_sha256":"e"*64},
                       {"policy_sha256":"e"*64},
                       {"target":"bridge/neurofactory/development/core_owned/other.py"}):
            with self.subTest(change=change):
                self.assertEqual(
                    self.gate.reserve_once(**self.args(claimed, **change))["reason"],
                    "SOURCE_OR_SCOPE_NOT_MATCHED")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0], 0)

    def test_unapproved_scope_fixture_denied(self):
        self.seed(scope_authorized=False)
        claimed = self.claim()
        self.assertEqual(self.gate.reserve_once(
            **self.args(claimed))["reason"], "SOURCE_OR_SCOPE_NOT_MATCHED")

    def test_two_actual_pg_connections_race_for_one_intent(self):
        self.seed()
        claimed = self.claim()
        def attempt(_):
            with connect() as c:
                return OfflineEffectReservation(c).reserve_once(
                    **self.args(claimed))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            out = list(pool.map(attempt, [1,2]))
        self.assertEqual(sum(x["status"]=="RESERVED_OFFLINE_TEST_ONLY" for x in out),1)
        self.assertEqual(sum(x["status"]=="DENIED" for x in out),1)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0], 1)

    def test_boolean_epoch_and_invalid_path_fail_closed(self):
        self.seed()
        claimed = self.claim()
        for change in ({"lease_epoch":True},
                       {"target":"../../secret.txt"},
                       {"idempotency_key":"approved"},
                       {"fencing_token":True},
                       {"target":"bridge/neurofactory/development/core_owned/CON.py"}):
            with self.subTest(change=change):
                with self.assertRaises(OfflineEffectBoundaryError):
                    self.gate.reserve_once(**self.args(claimed,**change))
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],0)

    def test_non_ephemeral_or_no_fixture_mode_rejected(self):
        raw = psycopg.connect(DSN, autocommit=True, connect_timeout=3)
        try:
            with self.assertRaises(OfflineEffectBoundaryError):
                OfflineEffectReservation(raw)
        finally:
            raw.close()

    def test_unknown_after_reserved_does_not_free_intent(self):
        self.seed()
        claimed = self.claim()
        self.assertEqual(self.gate.reserve_once(
            **self.args(claimed))["status"],"RESERVED_OFFLINE_TEST_ONLY")
        self.assertTrue(self.cas.mark_unknown(
            TASK, "worker-1",claimed["lease_epoch"],claimed["fencing_token"]))
        self.assertEqual(self.gate.reserve_once(
            **self.args(claimed))["status"], "DENIED")
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],1)


if __name__ == "__main__":
    unittest.main()
