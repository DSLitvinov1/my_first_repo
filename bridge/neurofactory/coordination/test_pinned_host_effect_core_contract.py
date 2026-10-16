"""Cross-component check of exact pinned new HOST intent vs unchanged CORE.

This is COORD-owned, read-only to HOST/CORE sources, nf_test-only.
No task execution, sandbox writes, real signer, HTTP, model or publisher.
"""
import hashlib
import importlib.util
import inspect
import os
from pathlib import Path
import secrets
import subprocess
import unittest

import psycopg

CORE_SHA = "ce6191153d0a0c1d742de6233897186a0b46896b"
HOST_SHA = "5c0132d1c53d3d569dd66967915203069e2a25e8"
TASK = "NF-DEV-05-Q951"
PROJECT = "nf-sandbox"
SOURCE = "a"*40
FILE = "b"*64
INPUT = "c"*64
POLICY = "d"*64
TARGET = "bridge/neurofactory/development/core_owned/one_synthetic_transaction.py"
DSN = "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"


def git(directory, *args):
    return subprocess.check_output(
        ["git", "-C", str(directory), *args],
        text=True, stderr=subprocess.PIPE, timeout=12).strip()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing pinned source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def db():
    c = psycopg.connect(DSN, autocommit=True, connect_timeout=3)
    if c.execute("SELECT current_database()").fetchone()[0] != "nf_test":
        c.close()
        raise RuntimeError("non-fixture database denied")
    c.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return c


class PinnedContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NF_COORD_OFFLINE_ONLY") != "1" or os.name != "posix":
            raise RuntimeError("must be isolated Linux offline test")
        root = Path(__file__).resolve().parents[3] / "_pinned_fixture"
        core = root / "core"
        host = root / "host"
        if git(core, "rev-parse", "HEAD") != CORE_SHA:
            raise RuntimeError("CORE source SHA changed")
        if git(host, "rev-parse", "HEAD") != HOST_SHA:
            raise RuntimeError("HOST source SHA changed")
        cls.core = load("pinned_core_contract", core /
            "bridge/neurofactory/development/core_owned/one_task_core.py")
        cls.host_cas = load("pinned_host_cas_contract", host /
            "bridge/neurofactory/trusted_host/offline_cas.py")
        cls.host_effect = load("pinned_host_effect_contract", host /
            "bridge/neurofactory/trusted_host/offline_effect_reservation.py")
        with db() as c:
            c.execute((host / "bridge/neurofactory/trusted_host/schema_v1.sql").read_text())
            c.execute((host /
                "bridge/neurofactory/trusted_host/offline_effect_reservation_schema.sql").read_text())

    def setUp(self):
        self.c = db()
        self.addCleanup(self.c.close)
        self.c.execute("TRUNCATE nf_effect_intent,nf_effect_scope_fixture,"
                       "nf_claim_request,nf_task")
        self.cas = self.host_cas.OfflineCAS(self.c)
        self.effect = self.host_effect.OfflineEffectReservation(self.c)
        self.c.execute(
            "INSERT INTO nf_task(task_id,project_id,input_core_sha40,"
            "source_file_sha256,input_task_sha256,fixture_authorized)"
            "VALUES (%s,%s,%s,%s,%s,TRUE)",
            (TASK, PROJECT, SOURCE, FILE, INPUT))
        self.c.execute(
            "INSERT INTO nf_effect_scope_fixture(task_id,project_id,"
            "input_core_sha40,source_file_sha256,input_task_sha256,"
            "target,policy_sha256,fixture_authorized)"
            "VALUES(%s,%s,%s,%s,%s,%s,%s,TRUE)",
            (TASK,PROJECT,SOURCE,FILE,INPUT,TARGET,POLICY))

    def claim(self):
        return self.cas.claim(TASK, "fixture-worker", secrets.token_hex(16))

    def inputs(self, lease, **updates):
        args = dict(task_id=TASK,project_id=PROJECT,source_sha40=SOURCE,
                    source_file_sha256=FILE,input_task_sha256=INPUT,
                    target=TARGET,policy_sha256=POLICY,
                    worker_id="fixture-worker",lease_epoch=lease["lease_epoch"],
                    fencing_token=lease["fencing_token"],
                    idempotency_key=secrets.token_hex(32))
        args.update(updates)
        return args

    def test_new_host_denies_blocked_without_lease(self):
        forged = dict(task_id=TASK,project_id=PROJECT,source_sha40=SOURCE,
                      source_file_sha256=FILE,input_task_sha256=INPUT,
                      target=TARGET,policy_sha256=POLICY,
                      worker_id="fixture-worker",lease_epoch=1,
                      fencing_token="x"*40,idempotency_key=secrets.token_hex(32))
        self.assertEqual(self.effect.reserve_once(**forged)["status"],"DENIED")
        self.assertEqual(self.c.execute("SELECT count(*) FROM nf_effect_intent").fetchone()[0],0)

    def test_new_host_denies_unknown(self):
        lease=self.claim()
        self.assertTrue(self.cas.mark_unknown(TASK,"fixture-worker",
                        lease["lease_epoch"],lease["fencing_token"]))
        self.assertEqual(self.effect.reserve_once(
            **self.inputs(lease))["reason"],"HOST_NOT_LEASED_OR_UNKNOWN")

    def test_new_host_denies_expired(self):
        lease=self.claim()
        self.c.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()"
                       "-INTERVAL '3 seconds' WHERE task_id=%s",(TASK,))
        self.assertEqual(self.effect.reserve_once(
            **self.inputs(lease))["reason"],"LEASE_EXPIRED")

    def test_new_host_denies_stale_worker_and_epoch(self):
        lease=self.claim()
        for update in ({"worker_id":"loser-worker"},{"lease_epoch":2},
                       {"fencing_token":"z"*40}):
            with self.subTest(update=update):
                self.assertEqual(self.effect.reserve_once(
                    **self.inputs(lease,**update))["status"],"DENIED")

    def test_new_host_denies_duplicate_operation(self):
        lease=self.claim()
        inputs=self.inputs(lease)
        first=self.effect.reserve_once(**inputs)
        self.assertEqual(first["status"],"RESERVED_OFFLINE_TEST_ONLY")
        self.assertFalse(first["execution_allowed"])
        self.assertEqual(self.effect.reserve_once(
            **inputs)["reason"],"EFFECT_INTENT_ALREADY_CONSUMED")
        self.assertEqual(self.effect.reserve_once(
            **self.inputs(lease))["reason"],"EFFECT_INTENT_ALREADY_CONSUMED")

    def test_core_receiver_still_has_no_protected_host_effect_parameter(self):
        signature=inspect.signature(self.core.OneTaskCore.apply_offline_test)
        self.assertEqual(tuple(signature.parameters),
                         ("self","task_id","token","proposal","now"))
        self.assertNotIn("idempotency_key",signature.parameters)
        self.assertNotIn("host_fence",signature.parameters)
        self.assertNotIn("signed_owner_approval",signature.parameters)
        print("NF_CORE_NEW_HOST_EFFECT_NOT_CONSUMED=CONFIRMED_TEST_ONLY")

    def test_positive_host_reservation_still_forbids_live_execution(self):
        lease=self.claim()
        reserved=self.effect.reserve_once(**self.inputs(lease))
        self.assertEqual(reserved["status"],"RESERVED_OFFLINE_TEST_ONLY")
        for key in ("execution_allowed","publication_allowed",
                    "real_owner_authenticated","real_recipient_fencing",
                    "release_approved","automatic_retry_allowed"):
            self.assertIs(reserved[key],False)


if __name__=="__main__":
    unittest.main()
