"""Six CORE-owned exact-source pinned isolated HOST/CORE integration cases."""
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest

import psycopg
import one_task_core
from fenced_offline_core import FencedOfflineTestBridge, FencedOfflineBoundaryError

CORE_SHA = "ce6191153d0a0c1d742de6233897186a0b46896b"
HOST_SHA = "5c0132d1c53d3d569dd66967915203069e2a25e8"
TASK = "NF-DEV-05-Q972"
TARGET = "bridge/neurofactory/development/core_owned/one_synthetic_transaction.py"
POLICY = "d"*64
DB = "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"
WORKER = "worker-one"

def git(repo,*args):
    return subprocess.check_output(["git","-C",str(repo),*args],
        stderr=subprocess.PIPE,text=True,timeout=12).strip()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned file not found")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def connect():
    c=psycopg.connect(DB,autocommit=True,connect_timeout=3)
    if c.execute("SELECT current_database()").fetchone()[0]!="nf_test":
        c.close()
        raise RuntimeError("test DB only")
    c.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return c

class RealPinnedTestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "posix" or os.environ.get("NF_CORE_FENCED_TEST_ONLY")!="1":
            raise RuntimeError("test-only guard")
        root=Path(__file__).resolve().parents[4]
        self_sha=git(root,"rev-parse","HEAD")
        # CORE source is checked from its EXACT own tested branch commit.
        # The test runner may contain later test-only commits, so verify its
        # physical source Git blob matches its latest source-pinned baseline.
        core_path="bridge/neurofactory/development/core_owned/one_task_core.py"
        # GitHub checkout is shallow; compare the verified physical source
        # blob from CORE exact ce619... without depending on ancestor fetch.
        current_blob=git(root,"hash-object",core_path)
        if current_blob!="ab1471813c6da29407c913b974a2209467a4b961":
            raise RuntimeError("CORE source changed unexpectedly")
        host=root/"_pinned_fixture"/"host"
        if git(host,"rev-parse","HEAD")!=HOST_SHA:
            raise RuntimeError("wrong HOST exact executable checkout")
        cls.hostcas=load("pinned_host_cas_for_core",
            host/"bridge/neurofactory/trusted_host/offline_cas.py")
        cls.hosteffect=load("pinned_host_effect_for_core",
            host/"bridge/neurofactory/trusted_host/offline_effect_reservation.py")
        with connect() as c:
            c.execute((host/"bridge/neurofactory/trusted_host/schema_v1.sql").read_text())
            c.execute((host/"bridge/neurofactory/trusted_host/offline_effect_reservation_schema.sql").read_text())

    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix="nf-core-fenced-test-")
        self.addCleanup(self.t.cleanup)
        self.base=Path(self.t.name)
        self.repo=self.base/"fixture"
        self.repo.mkdir(mode=0o700)
        git(self.repo,"init","-q")
        git(self.repo,"config","user.name","ephemeral")
        git(self.repo,"config","user.email","ephemeral@example.invalid")
        (self.repo/"README.md").write_text("Fixture\\n",encoding="utf8")
        git(self.repo,"add","README.md")
        git(self.repo,"commit","-qm","test fixture")
        source=git(self.repo,"rev-parse","HEAD")
        ws=self.base/"workspace"
        ws.mkdir(mode=0o700)
        self.core=one_task_core.OneTaskCore(ws,self.repo)
        self.spec=dict(schema="neurofactory.core.task.v1",task_id=TASK,
            project_id="nf-sandbox",target=TARGET,
            objective="Write one synthetic inert file only for testing.",
            source_sha=source,source_sha256=one_task_core.EMPTY_SHA,
            approval_commit=source,model="qwen2.5-coder:1.5b",reserved_units=1)
        self.c=connect()
        self.addCleanup(self.c.close)
        self.c.execute("TRUNCATE nf_effect_intent,nf_effect_scope_fixture,"
                       "nf_claim_request,nf_task")
        digest=hashlib.sha256(one_task_core._canonical(self.spec)).hexdigest()
        self.c.execute(
            "INSERT INTO nf_task(task_id,project_id,input_core_sha40,"
            "source_file_sha256,input_task_sha256,fixture_authorized)"
            "VALUES(%s,%s,%s,%s,%s,TRUE)",
            (TASK,self.spec["project_id"],source,
             self.spec["source_sha256"],digest))
        self.c.execute(
            "INSERT INTO nf_effect_scope_fixture(task_id,project_id,"
            "input_core_sha40,source_file_sha256,input_task_sha256,"
            "target,policy_sha256,fixture_authorized)"
            "VALUES(%s,%s,%s,%s,%s,%s,%s,TRUE)",
            (TASK,self.spec["project_id"],source,self.spec["source_sha256"],
             digest,TARGET,POLICY))
        self.cas=self.hostcas.OfflineCAS(self.c)
        self.gate=self.hosteffect.OfflineEffectReservation(self.c)
        self.adapter=FencedOfflineTestBridge(self.core,self.gate)
        self.core.enqueue(self.spec,trusted_approval_check=lambda s:s==self.spec)
        self.local=self.core.claim(WORKER,now=100,lease_seconds=400)
        data="ONE_SYNTHETIC_HOST_FENCED_TEST = True\\n"
        self.proposal=dict(schema="neurofactory.core.proposal.v1",
            target=TARGET,content=data,
            content_sha256=hashlib.sha256(data.encode()).hexdigest(),
            mode="OFFLINE_TEST")

    def claim(self):
        return self.cas.claim(TASK,WORKER,secrets.token_hex(16),lease_seconds=240)

    def run_bridge(self,host_claim,**changes):
        arg=dict(task_id=TASK,core_token=self.local["token"],
            proposal=self.proposal,worker_id=WORKER,
            host_claim=host_claim,policy_sha256=POLICY,
            idempotency_key=secrets.token_hex(32),now=101)
        arg.update(changes)
        return self.adapter.apply_once(**arg)

    def no_write(self):
        self.assertFalse((self.core.sandbox/TARGET).exists())
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_unfenced_legacy_core_entrypoint_denies_even_with_valid_local_claim(self):
        with self.assertRaisesRegex(one_task_core.CoreSafetyError,
                                    "LEGACY_WRITE_DISABLED"):
            self.core.apply_offline_test(
                TASK, self.local["token"], self.proposal, now=101)
        self.no_write()

    def test_denied_host_claim_zero_write(self):
        with self.assertRaises(FencedOfflineBoundaryError):
            self.run_bridge({"status":"BLOCKED"})
        self.no_write()

    def test_host_unknown_zero_write(self):
        held=self.claim()
        self.assertTrue(self.cas.mark_unknown(
            TASK,WORKER,held["lease_epoch"],held["fencing_token"]))
        with self.assertRaises(FencedOfflineBoundaryError):
            self.run_bridge(held)
        self.no_write()

    def test_expired_host_lease_zero_write(self):
        held=self.claim()
        self.c.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()-"
                       "INTERVAL '5 seconds' WHERE task_id=%s",(TASK,))
        with self.assertRaises(FencedOfflineBoundaryError):
            self.run_bridge(held)
        self.no_write()

    def test_stale_worker_or_epoch_zero_write(self):
        held=self.claim()
        for change in ({"worker_id":"loser-worker"},
                       {"host_claim":dict(held,lease_epoch=held["lease_epoch"]+1)}):
            with self.subTest(change=str(change)[:20]):
                with self.assertRaises(FencedOfflineBoundaryError):
                    self.run_bridge(change.get("host_claim",held),**{k:v for k,v in change.items() if k!="host_claim"})
        self.no_write()

    def test_duplicate_reserved_intent_zero_write(self):
        held=self.claim()
        key=secrets.token_hex(32)
        result=self.gate.reserve_once(task_id=TASK,
            project_id=self.spec["project_id"],
            source_sha40=self.spec["source_sha"],
            source_file_sha256=self.spec["source_sha256"],
            input_task_sha256=hashlib.sha256(
                one_task_core._canonical(self.spec)).hexdigest(),
            target=TARGET,policy_sha256=POLICY,worker_id=WORKER,
            lease_epoch=held["lease_epoch"],
            fencing_token=held["fencing_token"],idempotency_key=key)
        self.assertEqual(result["status"],"RESERVED_OFFLINE_TEST_ONLY")
        with self.assertRaises(FencedOfflineBoundaryError):
            self.run_bridge(held,idempotency_key=key)
        self.no_write()

    def test_one_synthetic_file_with_matching_host_intent(self):
        held=self.claim()
        receipt=self.run_bridge(held)
        p=self.core.sandbox/TARGET
        self.assertTrue(p.is_file())
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),
                         receipt["result_sha256"])
        self.assertEqual(self.core.snapshot()["state"],"CHECKPOINTED_TEST")
        self.assertEqual(self.core.snapshot()["attempts"],1)
        self.assertEqual(self.c.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],1)
        self.assertFalse(receipt["model_invoked"])
        self.assertFalse(receipt["published"])
        self.assertEqual(receipt["api_cost_usd"],0)
        with self.assertRaises(FencedOfflineBoundaryError):
            self.run_bridge(held)
        self.assertEqual(self.c.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],1)
        print("NF_CORE_HOST_SYNTHETIC_ONE_FILE_CHECKPOINT=PASS_TEST_ONLY")
        print("NF_REAL_AUTHENTICATED_RECIPIENT_FENCING=NOT_DEPLOYED")

if __name__=="__main__":
    unittest.main()
