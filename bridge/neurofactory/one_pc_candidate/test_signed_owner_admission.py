"""Targeted signed owner -> real SQLite CORE admission tests.

Ephemeral signer exists ONLY in test process, never HTTP or Windows installer.
No Qwen, HOST effect, claim, SKILLS, production queue or owner PC touched.
"""
from __future__ import annotations

import base64
from http.server import HTTPServer
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from threading import Thread
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bridge/neurofactory/development/core_owned"))
from one_task_core import OneTaskCore, EMPTY_SHA
from local_workspace import WorkspaceStore, handler
from signed_owner_admission import (
    prepare_draft_request, admit_signed_draft, AdmissionDenied, _canon,
)
from core_readonly_observer import observe_core


class SignedRealCoreAdmission(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nf-signed-core-ci-")
        self.root = Path(self.tmp.name)
        self.git = self.root / "git"
        self.git.mkdir(mode=0o700)
        for args in (
            ("init", "-q"), ("config", "user.name", "NF Signed CI"),
            ("config", "user.email", "ci@example.invalid"),
        ):
            subprocess.run(["git", "-C", str(self.git), *args],
                           check=True, capture_output=True)
        (self.git / "README.md").write_text("disposable fixture\n", encoding="utf-8")
        for args in (("add", "README.md"), ("commit", "-m", "CI baseline")):
            subprocess.run(["git", "-C", str(self.git), *args],
                           check=True, capture_output=True)
        self.sha = subprocess.check_output(
            ["git", "-C", str(self.git), "rev-parse", "HEAD"], text=True).strip()
        self.workspace = WorkspaceStore(self.root / "workspace")
        self.project = self.workspace.create_project({
            "name": "Project owned in disposable CI", "description": ""})
        self.draft = self.workspace.create_task({
            "project_id": self.project["id"],
            "objective": "Prepare one permitted inert text file in CORE CI sandbox.",
            "model_preference": "qwen2.5-coder:1.5b",
        })
        self.preview = prepare_draft_request(self.workspace, self.draft["id"])
        core_root = self.root / "core"
        core_root.mkdir(mode=0o700)
        self.core = OneTaskCore(core_root, self.git)
        self.owner = Ed25519PrivateKey.generate()
        self.owner_public_raw = self.owner.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.now = int(time.time())

    def tearDown(self):
        self.tmp.cleanup()

    def permit(self, *, preview=None, spec=None, private=None, issued=None, expires=None):
        preview = self.preview if preview is None else preview
        if spec is None:
            spec = {
                "schema": "neurofactory.core.task.v1",
                "task_id": "NF-DEV-05-Q948",
                "project_id": "p-" + self.project["id"],
                "target": "bridge/neurofactory/development/core_owned/approved.txt",
                "objective": self.draft["objective"],
                "source_sha": self.sha,
                "source_sha256": EMPTY_SHA,
                "model": "qwen2.5-coder:1.5b",
                "reserved_units": 100,
                "approval_commit": self.sha,
            }
        body = {
            "schema": "nf.onepc.owner_core_admission.v1",
            "scope": "OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
            "draft": preview, "spec": spec,
            "nonce": "a" * 32,
            "issued_at": self.now - 2 if issued is None else issued,
            "expires_at": self.now + 180 if expires is None else expires,
        }
        private = self.owner if private is None else private
        signature = private.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00" + _canon(body))
        return {**body, "owner_signature": base64.b64encode(signature).decode("ascii")}

    def test_real_owner_signature_admits_exact_draft_once(self):
        receipt = admit_signed_draft(self.workspace, self.core, self.permit(),
                                     owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertTrue(receipt["operator_verified_signed_permit"])
        self.assertFalse(receipt["queue_claim_allowed"])
        self.assertFalse(receipt["host_execution_allowed"])
        self.assertFalse(receipt["production_release"])
        self.assertEqual(self.core.snapshot()["state"], "QUEUED")
        self.assertEqual(observe_core(self.core.state)["reported_state"], "QUEUED")
        self.assertEqual(observe_core(self.core.state)["task"]["project_id"],
                         "p-" + self.project["id"])
        self.assertEqual(self.workspace.list_tasks()[0]["state"],
                         "DRAFT_PENDING_OWNER_AUTH")
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, self.permit(),
                               owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertEqual(self.core.snapshot()["state"], "QUEUED")
        print("NF_SIGNED_OWNER_REAL_CORE_QUEUED_ONCE=PASS_CI_ONLY")

    def test_browser_may_prepare_but_cannot_admit_or_sign(self):
        ui = ROOT / "bridge/neurofactory/control_ui"
        server = HTTPServer(("127.0.0.1", 0), handler(
            self.workspace, ui, "ci-draft-local-token", 0))
        server.RequestHandlerClass = handler(
            self.workspace, ui, "ci-draft-local-token", server.server_port,
            core_state_dir=self.core.state)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def call(method, path, payload=None, token=None):
                conn = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=6)
                headers = {"Host": f"127.0.0.1:{server.server_port}"}
                if token:
                    headers["X-NF-Local-Token"] = token
                if payload is not None:
                    headers["Content-Type"] = "application/json"
                conn.request(method, path, body=json.dumps(payload).encode()
                             if payload is not None else None, headers=headers)
                response = conn.getresponse()
                data = json.loads(response.read())
                status = response.status
                conn.close()
                return status, data

            url = f"/api/tasks/{self.draft['id']}/admission-request"
            code, data = call("GET", url)
            self.assertEqual(code, 200)
            self.assertEqual(data, self.preview)
            self.assertFalse(data["owner_signed"])
            self.assertFalse(data["queue_mutation_allowed"])
            self.assertEqual(call("GET", url + "?inject=1")[0], 404)
            self.assertEqual(call("GET", "/api/tasks/" + "f" * 32 +
                                  "/admission-request")[0], 404)
            self.assertEqual(call("POST", "/api/core/admit", self.permit(),
                                  "ci-draft-local-token")[0], 404)
            self.assertEqual(call("POST", url, self.permit(),
                                  "ci-draft-local-token")[0], 404)
            self.assertEqual(self.core.snapshot()["state"], "EMPTY")
            print("NF_BROWSER_CAN_PREPARE_CANNOT_SIGN_ENQUEUE_OR_APPLY=PASS")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_reject_foreign_or_tampered_project_objective_model(self):
        spec = self.permit()["spec"]
        for field, bad in (
            ("project_id", "p-" + "f" * 32),
            ("objective", "Replace the signed approved objective without consent."),
            ("model", "qwen3:4b"),
        ):
            changed = {**spec, field: bad}
            with self.subTest(field=field), self.assertRaises(AdmissionDenied):
                admit_signed_draft(self.workspace, self.core, self.permit(spec=changed),
                                   owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertEqual(self.core.snapshot()["state"], "EMPTY")

    def test_forged_owner_signature_and_modified_signed_spec_denied(self):
        fake = Ed25519PrivateKey.generate()
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, self.permit(private=fake),
                               owner_public_raw=self.owner_public_raw, now=self.now)
        modified = self.permit()
        modified["spec"]["source_sha"] = "0" * 40
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, modified,
                               owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertEqual(self.core.snapshot()["state"], "EMPTY")

    def test_stale_lease_wrong_git_revision_and_unsigned_denied(self):
        stale = self.permit(issued=self.now-900, expires=self.now-800)
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, stale,
                               owner_public_raw=self.owner_public_raw, now=self.now)
        spec = {**self.permit()["spec"],
                "source_sha": "1" * 40, "approval_commit": "1" * 40}
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, self.permit(spec=spec),
                               owner_public_raw=self.owner_public_raw, now=self.now)
        untrusted = self.permit()
        untrusted.pop("owner_signature")
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, untrusted,
                               owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertEqual(self.core.snapshot()["state"], "EMPTY")

    def test_changed_durable_ui_draft_after_owner_signature_denied(self):
        signed = self.permit()
        with self.workspace.connect() as db:
            db.execute(
                "UPDATE tasks SET objective=? WHERE id=?",
                ("Altered saved objective after independently signed permit.",
                 self.draft["id"]))
            db.commit()
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, signed,
                               owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertEqual(self.core.snapshot()["state"], "EMPTY")
        print("NF_CHANGED_SIGNED_WORKSPACE_DRAFT=DENIED")

    def test_legit_signer_cannot_force_foreign_windows_target(self):
        spec = {**self.permit()["spec"], "target": "C:/Windows/System32/bad.txt"}
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, self.core, self.permit(spec=spec),
                               owner_public_raw=self.owner_public_raw, now=self.now)
        self.assertEqual(self.core.snapshot()["state"], "EMPTY")
        print("NF_SIGNED_FOREIGN_TARGET_BY_CORE=DENIED")

    def test_malformed_joined_project_uuid_denied_before_owner_signature(self):
        """Corrupt-but-foreign-key-consistent SQLite IDs must not map into CORE.

        A signed browser cannot select project UUIDs; the trusted admission
        reader must still defend against externally tampered local DB rows.
        """
        bad_ids = ("abc", "A"*32, "x"*32, "f"*31,
                   "f"*33, "not-hex_uuid")
        for i, bad in enumerate(bad_ids):
            with self.subTest(project_uuid=bad):
                task_id = f"{i+100:032x}"
                with self.workspace.connect() as db:
                    db.execute(
                        "INSERT INTO projects(id,name,description,created_utc) "
                        "VALUES(?,?,?,?)",
                        (bad, "SQLite tamper fixture", "", "2026-10-19T10:00:00Z"))
                    db.execute(
                        "INSERT INTO tasks(id,project_id,objective,"
                        "model_preference,state,created_utc) "
                        "VALUES(?,?,?,?,?,?)",
                        (task_id, bad,
                         "Create one harmless CORE test proposal without applying files.",
                         "qwen2.5-coder:1.5b", "DRAFT_PENDING_OWNER_AUTH",
                         "2026-10-19T10:00:00Z"))
                    db.commit()
                with self.assertRaises(AdmissionDenied):
                    prepare_draft_request(self.workspace, task_id)
                self.assertEqual(self.core.snapshot()["state"], "EMPTY")
        print("NF_SIGNED_ADMISSION_CORRUPT_JOINED_PROJECT_UUID=DENIED_NO_CORE")

    def test_oversized_or_ineligible_draft_never_enqueued(self):
        long_draft = self.workspace.create_task({
            "project_id": self.project["id"],
            "objective": "test instruction " * 24,
            "model_preference": "auto",
        })
        with self.assertRaises(AdmissionDenied):
            prepare_draft_request(self.workspace, long_draft["id"])
        with self.assertRaises(AdmissionDenied):
            prepare_draft_request(self.workspace, "f" * 32)
        self.assertEqual(self.core.snapshot()["state"], "EMPTY")


if __name__ == "__main__":
    unittest.main()
