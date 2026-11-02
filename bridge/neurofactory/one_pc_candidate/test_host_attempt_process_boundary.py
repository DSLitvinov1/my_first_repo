"""Actual separate OS process/crash/concurrency proof for the offline HOST ledger.

No network, model or protected Windows service starts in this test. The
fixture operator provisions a disposable directory; it is not a custody proof.
"""
import concurrent.futures
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from protected_host_attempt_ledger import (
    AttemptLedgerDenied, provision_empty_attempt_ledger_offline,
    reserve_attempt_once,
)

DB_FILE = "signed-witness-attempts.sqlite3"

def digest(s):
    return sha256(s.encode("ascii")).hexdigest()

def child(argv):
    root = Path(argv[0])
    claim = json.loads(argv[1])
    crash = argv[2] == "crash-after-commit"
    try:
        reserve_attempt_once(root, claim=claim)
    except AttemptLedgerDenied:
        return 42
    if crash:
        # Simulate actual abrupt service death AFTER durable SQLite COMMIT,
        # BEFORE any remote send/ACK. A successor must still deny replay.
        os._exit(53)
    return 0

class PhysicalProcessBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-p0-process-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        provision_empty_attempt_ledger_offline(self.root)
        self.claim={
            "schema":"nf.host.one_effect_scope.v1",
            "task_id":"verified-process-task",
            "operation_sha256":digest("owner-scoped-operation"),
            "nonce":secrets.token_hex(32),
            "source_sha40":"c"*40,
            "external_epoch":137,
        }

    def invoke(self, mode="normal", claim=None):
        proc=subprocess.run(
            [sys.executable,"-B",str(Path(__file__).resolve()),
             "--child",str(self.root),json.dumps(
                self.claim if claim is None else claim,
                sort_keys=True,separators=(",",":")),mode],
            capture_output=True,text=True,timeout=12,
            check=False,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},
        )
        return proc.returncode

    def count(self):
        with closing(sqlite3.connect(
                str(self.root/DB_FILE),timeout=4)) as db:
            return db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]

    def test_abrupt_real_child_process_exit_never_reenables_replay(self):
        self.assertEqual(self.invoke("crash-after-commit"),53)
        self.assertEqual(self.count(),1)
        self.assertEqual(self.invoke(),42)
        self.assertEqual(self.count(),1)

    def test_four_actual_racing_processes_commit_at_most_one(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            out=list(pool.map(lambda _: self.invoke(),range(4)))
        self.assertEqual(sorted(out),[0,42,42,42])
        self.assertEqual(self.count(),1)

    def test_deleted_previous_database_never_silently_recreated(self):
        self.assertEqual(self.invoke(),0)
        (self.root/DB_FILE).unlink()
        self.assertEqual(self.invoke(),42)
        self.assertFalse((self.root/DB_FILE).exists())

    def test_separately_signed_other_operation_same_epoch_denied(self):
        self.assertEqual(self.invoke(),0)
        new_claim={**self.claim,
                   "task_id":"second-approved-claim",
                   "nonce":secrets.token_hex(32),
                   "operation_sha256":digest("different-approved-operation")}
        self.assertEqual(self.invoke(claim=new_claim),42)
        self.assertEqual(self.count(),1)

if __name__=="__main__":
    if len(sys.argv)==5 and sys.argv[1]=="--child":
        sys.exit(child(sys.argv[2:]))
    unittest.main()
