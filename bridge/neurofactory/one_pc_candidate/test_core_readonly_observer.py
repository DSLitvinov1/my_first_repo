"""Addressed CORE telemetry tests with REAL integration CORE SQLite.

No local model, no effects, no SCM service, no live queue activation.
"""
from __future__ import annotations

import hashlib
from http.server import HTTPServer
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bridge/neurofactory/development/core_owned"))
from one_task_core import OneTaskCore, EMPTY_SHA
from core_readonly_observer import observe_core, unavailable_core, CoreObservationDenied
from local_workspace import WorkspaceStore, handler


class CoreReadOnlyIntegration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nf-core-observe-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "git"
        self.repo.mkdir()
        for args in (
            ("init", "-q"),
            ("config", "user.name", "NF Disposable Test"),
            ("config", "user.email", "ci@example.invalid"),
        ):
            subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                           capture_output=True)
        (self.repo / "README.md").write_text("test only\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "README.md"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-m", "test"],
                       check=True, capture_output=True)
        sha = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        core_root = self.root / "core"
        core_root.mkdir(mode=0o700)
        self.core = OneTaskCore(core_root, self.repo)
        self.state = core_root / "state"
        self.spec = {
            "schema": "neurofactory.core.task.v1",
            "task_id": "NF-DEV-05-Q938",
            "project_id": "core-readonly",
            "target": "bridge/neurofactory/development/core_owned/observer.txt",
            "objective": "Create one harmless test fixture without actual execution.",
            "source_sha": sha,
            "source_sha256": EMPTY_SHA,
            "approval_commit": sha,
            "model": "qwen2.5-coder:1.5b",
            "reserved_units": 10,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def enqueue(self):
        self.core.enqueue(self.spec, trusted_approval_check=lambda _: True)

    def test_genuine_core_sqlite_queued_claimed_and_restart(self):
        before = observe_core(self.state)
        self.assertEqual(before["reported_state"], "EMPTY")
        self.enqueue()
        after = observe_core(self.state)
        self.assertEqual(after["reported_state"], "QUEUED")
        self.assertEqual(after["task"]["task_id"], self.spec["task_id"])
        self.assertFalse(after["execution_allowed"])
        self.assertFalse(after["independently_verified"])
        claim = self.core.claim("observer-worker")
        observed = observe_core(self.state)
        self.assertEqual(observed["reported_state"], "CLAIMED")
        self.assertEqual(observed["task"]["attempts"], 1)
        self.assertEqual(observed["task"]["model"], "qwen2.5-coder:1.5b")
        self.assertNotIn(claim["token"], json.dumps(observed))
        self.assertNotIn("owner", json.dumps(observed))
        self.assertNotIn('"receipt":', json.dumps(observed))
        reopened = observe_core(self.state)
        self.assertEqual(reopened["task"], observed["task"])
        print("NF_CORE_REAL_SQLITE_READONLY_QUEUE_CLAIM_RESTART=PASS")

    def test_tampered_actual_core_digest_rejected_without_rewrite(self):
        self.enqueue()
        db = self.state / "queue.sqlite3"
        original = db.read_bytes()
        with self.core._connect() as conn:
            conn.execute("UPDATE single_job SET spec_sha256=? WHERE singleton=1",
                         ("0" * 64,))
            conn.commit()
        changed = db.read_bytes()
        with self.assertRaises(CoreObservationDenied):
            observe_core(self.state)
        self.assertEqual(db.read_bytes(), changed)
        self.assertNotEqual(changed, original)
        print("NF_CORE_TAMPERED_DIGEST_FAIL_CLOSED_NO_WRITE=PASS")

    def test_foreign_core_state_and_symlink_denied(self):
        with self.assertRaises(CoreObservationDenied):
            observe_core(self.root / "absent")
        self.assertFalse(unavailable_core()["configured"])
        linked = self.root / "linked-state"
        try:
            linked.symlink_to(self.state, target_is_directory=True)
        except (OSError, NotImplementedError):
            pass
        else:
            with self.assertRaises(CoreObservationDenied):
                observe_core(linked)
        self.assertEqual(list(self.state.glob("*")), [self.state / "queue.sqlite3"])

    def test_local_http_reflects_genuine_core_without_writer(self):
        self.enqueue()
        ui = ROOT / "bridge/neurofactory/control_ui"
        store = WorkspaceStore(self.root / "workspace")
        with HTTPServer(("127.0.0.1", 0), handler(store, ui, "ci-token", 0)) as srv:
            srv.RequestHandlerClass = handler(
                store, ui, "ci-token", srv.server_port, core_state_dir=self.state)
            t = Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                c = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
                c.request("GET", "/api/core/status",
                          headers={"Host": f"127.0.0.1:{srv.server_port}"})
                response = c.getresponse()
                result = json.loads(response.read())
                c.close()
                self.assertEqual(response.status, 200)
                self.assertEqual(result["reported_state"], "QUEUED")
                self.assertFalse(result["execution_allowed"])
                self.assertEqual(result["task"]["task_id"], self.spec["task_id"])
                c = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=5)
                c.request("POST", "/api/core/status", b"{}",
                          headers={"Host": f"127.0.0.1:{srv.server_port}",
                                   "X-NF-Local-Token": "ci-token",
                                   "Content-Type": "application/json"})
                resp = c.getresponse()
                resp.read()
                self.assertEqual(resp.status, 404)
                c.close()
            finally:
                srv.shutdown()
                t.join(timeout=4)
        self.assertEqual(self.core.snapshot()["state"], "QUEUED")
        print("NF_CORE_REAL_READONLY_HTTP_AND_MUTATION_DENIED=PASS")


if __name__ == "__main__":
    unittest.main()
