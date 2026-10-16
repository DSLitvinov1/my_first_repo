"""Coordinator-owned exact-pinned CORE+HOST synthetic smoke. NEVER deploy as a queue.

Runs only in disposable GitHub-hosted nf_test PostgreSQL + temporary Git/CORE
sandbox. HOST synthetic fixture_authorized and CORE lambda are NOT approvals.
The CAS token is NOT actually fenced by CORE's recipient. No production E2E.
"""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest

import psycopg

CORE_SHA = "ce6191153d0a0c1d742de6233897186a0b46896b"
HOST_SHA = "02646ccb71b3892dc08f68a76525937cfe2ed194"
TASK = "NF-DEV-05-Q571"
TARGET = "bridge/neurofactory/development/core_owned/one_synthetic_transaction.py"
POSTGRES = "postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"

def _git(dirpath, *args):
    return subprocess.check_output(
        ["git", "-C", str(dirpath), *args], stderr=subprocess.PIPE,
        timeout=10, text=True).strip()

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing pinned source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def _db():
    con = psycopg.connect(POSTGRES, autocommit=True, connect_timeout=3)
    if con.execute("SELECT current_database()").fetchone()[0] != "nf_test":
        con.close()
        raise RuntimeError("only an ephemeral nf_test database is allowed")
    con.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return con

class ExactPinnedOneTask(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NF_COORD_OFFLINE_ONLY") != "1" or os.name != "posix":
            raise RuntimeError("synthetic Linux GitHub offline-only gate absent")
        root = Path(__file__).resolve().parents[3]
        base = root / "_pinned_fixture"
        core = base / "core"
        host = base / "host"
        if _git(core, "rev-parse", "HEAD") != CORE_SHA:
            raise RuntimeError("CORE source checkout SHA mismatch")
        if _git(host, "rev-parse", "HEAD") != HOST_SHA:
            raise RuntimeError("TRUSTED HOST source checkout SHA mismatch")
        cpath = core / "bridge/neurofactory/development/core_owned/one_task_core.py"
        hpath = host / "bridge/neurofactory/trusted_host/offline_cas.py"
        cls.core = _load("nf_exact_core", cpath)
        cls.host = _load("nf_exact_host", hpath)
        cls.sql = (host / "bridge/neurofactory/trusted_host/schema_v1.sql").read_text("utf8")
        with _db() as con:
            con.execute(cls.sql)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nf-one-offline-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "synthetic-git"
        self.repo.mkdir(mode=0o700)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.name", "isolated-test")
        _git(self.repo, "config", "user.email", "isolated@example.invalid")
        (self.repo / "README.md").write_text("Test source only\n", encoding="utf8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "offline preimage")
        sha = _git(self.repo, "rev-parse", "HEAD")
        self.workspace = self.base / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.q = self.core.OneTaskCore(self.workspace, self.repo)
        self.spec = {
            "schema":"neurofactory.core.task.v1", "task_id":TASK,
            "project_id":"nf-sandbox", "target":TARGET,
            "objective":"Write one immutable synthetic text fixture for a test.",
            "source_sha":sha, "source_sha256":self.core.EMPTY_SHA,
            "approval_commit":sha, "model":"qwen2.5-coder:1.5b",
            "reserved_units":10}
        self.db = _db()
        self.addCleanup(self.db.close)
        self.db.execute("TRUNCATE nf_claim_request,nf_task")
        self.hostcas = self.host.OfflineCAS(self.db)
        self.digest = hashlib.sha256(self.core._canonical(self.spec)).hexdigest()

    def seed(self, authorized=True, source_sha=None):
        self.db.execute("""INSERT INTO nf_task
            (task_id,project_id,input_core_sha40,source_file_sha256,
             input_task_sha256,fixture_authorized)
            VALUES (%s,%s,%s,%s,%s,%s)""",
            (TASK,self.spec["project_id"],source_sha or self.spec["source_sha"],
             self.spec["source_sha256"],self.digest,authorized))

    def _report(self):
        return {
            "local_core_state":self.q.snapshot()["state"],
            "central_test_phase":self.hostcas.public_state(TASK)["status"],
            "real_external_owner_approval":False,
            "real_signed_issuer_deployed":False,
            "real_recipient_fencing":False,
            "real_two_physical_hosts":False,
            "model_invoked":False,
            "publication_allowed":False,
            "handoff":"PAUSED_BY_USER",
            "release":"BLOCKED_TEST_ONLY"}

    def test_one_pg_winner_then_exact_core_one_file_checkpoint(self):
        self.seed()
        self.assertEqual(self.q.enqueue(self.spec, trusted_approval_check=lambda x:x == self.spec)["state"],"QUEUED")
        def request(w):
            with _db() as con:
                return w,self.host.OfflineCAS(con).claim(TASK,w,secrets.token_hex(16))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(request,["pc-synthetic-a","pc-synthetic-b"]))
        winners=[(w,r) for w,r in outcomes if r["status"]=="CLAIMED"]
        losers=[(w,r) for w,r in outcomes if r["status"]=="NOT_CLAIMED"]
        self.assertEqual((len(winners),len(losers)),(1,1))
        winner,result=winners[0]
        self.assertEqual(result["lease_epoch"],1)
        self.assertNotIn("fencing_token",losers[0][1])
        claim=self.q.claim(winner,now=1000,lease_seconds=90)
        content="SYNTHETIC_ONLY = True\n"
        proposal={"schema":"neurofactory.core.proposal.v1",
                  "target":TARGET,"content":content,
                  "content_sha256":hashlib.sha256(content.encode()).hexdigest(),
                  "mode":"OFFLINE_TEST"}
        receipt=self.q.apply_offline_test(TASK,claim["token"],proposal,now=1001)
        output=self.q.sandbox/TARGET
        self.assertEqual(output.read_text("utf8"),content)
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),receipt["result_sha256"])
        self.assertEqual(self.q.snapshot()["state"],"CHECKPOINTED_TEST")
        self.assertFalse(receipt["model_invoked"])
        self.assertFalse(receipt["review_approved"])
        self.assertFalse(receipt["published"])
        self.assertEqual(receipt["api_cost_usd"],0)
        with self.assertRaises(self.core.CoreSafetyError):
            self.q.claim(losers[0][0],now=1002)
        with self.assertRaises(self.core.CoreSafetyError):
            self.q.apply_offline_test(TASK,claim["token"],proposal,now=1002)
        self.assertEqual(self.hostcas.claim(TASK,"pc-synthetic-c",secrets.token_hex(16))["status"],
                         "NOT_CLAIMED")
        self.assertEqual(self.q.snapshot()["attempts"],1)
        self.assertEqual(self._report()["release"],"BLOCKED_TEST_ONLY")
        self.assertFalse(self._report()["real_recipient_fencing"])
        print("NF_ONE_TASK_CHECKPOINT=ONE_FILE_ONCE_OFFLINE_TEST")
        print("NF_PG_DISTINCT_CONNECTIONS=ONE_WINNER_ONE_DENIED")
        print("NF_REAL_CAS_FENCED_RECIPIENT=NOT_IMPLEMENTED")

    def test_denied_host_fixture_not_admitted(self):
        self.seed(False)
        self.assertEqual(self.hostcas.claim(TASK,"pc-synthetic-a",secrets.token_hex(16))["status"],
                         "BLOCKED")
        with self.assertRaises(self.core.CoreSafetyError):
            self.q.enqueue(self.spec, trusted_approval_check=lambda x:False)
        self.assertEqual(self.q.snapshot()["state"],"EMPTY")
        self.assertFalse((self.q.sandbox/TARGET).exists())

    def test_unknown_host_does_not_reclaim_or_write(self):
        self.seed(True)
        claimed=self.hostcas.claim(TASK,"pc-synthetic-a",secrets.token_hex(16))
        self.assertEqual(claimed["status"],"CLAIMED")
        self.assertTrue(self.hostcas.mark_unknown(TASK,"pc-synthetic-a",
                                                   claimed["lease_epoch"],claimed["fencing_token"]))
        self.assertEqual(self.hostcas.public_state(TASK)["status"],"UNKNOWN")
        self.assertEqual(self.hostcas.claim(TASK,"pc-synthetic-b",secrets.token_hex(16))["status"],
                         "NOT_CLAIMED")
        self.assertEqual(self.q.snapshot()["state"],"EMPTY")
        self.assertFalse((self.q.sandbox/TARGET).exists())

    def test_duplicate_request_never_reissues_host_fencing_token(self):
        self.seed(True)
        request_id=secrets.token_hex(16)
        self.assertEqual(self.hostcas.claim(TASK,"pc-synthetic-a",request_id)["status"],"CLAIMED")
        retry=self.hostcas.claim(TASK,"pc-synthetic-a",request_id)
        self.assertEqual(retry["status"],"BLOCKED")
        self.assertNotIn("fencing_token",retry)
        self.assertEqual(self.hostcas.public_state(TASK)["epoch"],1)

    def test_forged_authorization_and_git_source_still_denied(self):
        self.seed(True,source_sha="e"*40)
        self.assertEqual(self.hostcas.claim(TASK,"pc-synthetic-a",secrets.token_hex(16))["status"],
                         "CLAIMED")
        with self.assertRaises(self.core.CoreSafetyError):
            self.q.enqueue(self.spec, trusted_approval_check=lambda x:False)
        tampered=dict(self.spec,source_sha="e"*40)
        with self.assertRaises(self.core.CoreSafetyError):
            self.q.enqueue(tampered,trusted_approval_check=lambda x:True)
        self.assertEqual(self.q.snapshot()["state"],"EMPTY")
        self.assertFalse((self.q.sandbox/TARGET).exists())

    def _explicitly_untrusted_offline_write(self):
        """Deliberate test-only callback; proves absence of HOST->CORE fencing."""
        self.assertEqual(self.q.enqueue(
            self.spec, trusted_approval_check=lambda task: task == self.spec)["state"], "QUEUED")
        lease = self.q.claim("synthetic-local-only", now=1000, lease_seconds=90)
        content = "DIAGNOSTIC_UNFENCED_LOCAL_WRITE = True\\n"
        proposal = {
            "schema": "neurofactory.core.proposal.v1", "target": TARGET,
            "content": content,
            "content_sha256": hashlib.sha256(content.encode("utf8")).hexdigest(),
            "mode": "OFFLINE_TEST",
        }
        receipt = self.q.apply_offline_test(TASK, lease["token"], proposal, now=1001)
        self.assertEqual((self.q.sandbox / TARGET).read_text("utf8"), content)
        self.assertEqual(receipt["result_sha256"], hashlib.sha256(content.encode()).hexdigest())
        self.assertFalse(receipt["published"])
        self.assertFalse(receipt["model_invoked"])
        self.assertFalse(receipt["review_approved"])
        self.assertFalse(self._report()["real_recipient_fencing"])
        self.assertEqual(self._report()["release"], "BLOCKED_TEST_ONLY")

    def test_host_rejected_task_still_writable_by_independent_core_test_callback(self):
        """Negative integration witness, NOT authorization or a deployed exploit."""
        self.seed(False)
        denied = self.hostcas.claim(TASK, "synthetic-host-client", secrets.token_hex(16))
        self.assertEqual(denied["status"], "BLOCKED")
        self._explicitly_untrusted_offline_write()
        print("NF_INTEGRATION_GAP_HOST_BLOCK_CORE_LOCAL_TEST_WROTE=CONFIRMED")
        print("NF_PRODUCTION_EXECUTION_PERMISSION=FALSE")

    def test_host_unknown_still_writable_by_independent_core_test_callback(self):
        """UNKNOWN cannot fence the current test-only CORE recipient."""
        self.seed(True)
        central = self.hostcas.claim(TASK, "synthetic-host-client", secrets.token_hex(16))
        self.assertEqual(central["status"], "CLAIMED")
        self.assertTrue(self.hostcas.mark_unknown(
            TASK, "synthetic-host-client", central["lease_epoch"], central["fencing_token"]))
        self.assertEqual(self.hostcas.public_state(TASK)["status"], "UNKNOWN")
        self._explicitly_untrusted_offline_write()
        self.assertEqual(self.hostcas.public_state(TASK)["status"], "UNKNOWN")
        print("NF_INTEGRATION_GAP_HOST_UNKNOWN_CORE_LOCAL_TEST_WROTE=CONFIRMED")
        print("NF_AUTOMATIC_RECOVERY_OR_LIVE_ADMISSION=FALSE")

    def test_host_expired_lease_cannot_reclaim_but_local_test_recipient_still_writes(self):
        """Prove absent shared expiry admission (test-only; NEVER a live write)."""
        self.seed(True)
        worker = "synthetic-host-client"
        first = self.hostcas.claim(TASK, worker, secrets.token_hex(16),
                                   lease_seconds=1)
        self.assertEqual(first["status"], "CLAIMED")
        self.assertEqual(first["lease_epoch"], 1)
        # Ephemeral nf_test database fixture only: model time advancing without
        # sleep. OfflineCAS correctly refuses a second claim after expiry.
        self.db.execute(
            "UPDATE nf_task SET lease_deadline=clock_timestamp() - INTERVAL '2 seconds' "
            "WHERE task_id=%s", (TASK,))
        self.assertEqual(
            self.hostcas.claim(TASK, "synthetic-other-worker", secrets.token_hex(16))["status"],
            "NOT_CLAIMED")
        self.assertEqual(self.hostcas.public_state(TASK)["epoch"], 1)
        self.assertEqual(self.hostcas.public_state(TASK)["status"], "LEASED")
        # Local CORE ignores the HOST deadline entirely when the synthetic,
        # independently provided positive callback is used. This must NOT be
        # confused with a stale fencing token accepted by an actual HOST API.
        self._explicitly_untrusted_offline_write()
        print("NF_INTEGRATION_GAP_HOST_EXPIRED_CORE_LOCAL_TEST_WROTE=CONFIRMED")
        print("NF_CURRENT_SHARED_RECEIVER_EXPIRY_PROOF=ABSENT")

    def test_cas_result_is_not_real_core_exclusive_authorization(self):
        self.seed(True)
        host_lease=self.hostcas.claim(TASK,"pc-synthetic-a",secrets.token_hex(16))
        self.assertEqual(host_lease["status"],"CLAIMED")
        self.assertEqual(self.q.snapshot()["state"],"EMPTY")
        self.assertFalse(self.hostcas.public_state(TASK)["actions_allowed"])
        self.assertFalse(self._report()["real_external_owner_approval"])
        self.assertFalse(self._report()["real_recipient_fencing"])
        self.assertEqual(self._report()["release"],"BLOCKED_TEST_ONLY")

if __name__=="__main__":
    unittest.main()
