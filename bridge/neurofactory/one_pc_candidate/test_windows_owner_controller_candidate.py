"""Disposable Windows: real DPAPI protected signer -> signed owner CORE SQLite.

No system installation, owner keys shipped, active model, production queue,
HOST write or unreviewed SKILLS. The CI signer is created and destroyed.
"""
from __future__ import annotations

import base64
import subprocess
from pathlib import Path
import os
import secrets
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from signed_owner_admission import admit_signed_draft, AdmissionDenied
from test_signed_owner_admission import SignedRealCoreAdmission
from windows_owner_controller_candidate import (
    enroll, signed_enqueue_only, read_manifest, WindowsOwnerDenied,
    operator_sid, require_real_different_ui_account, PUBLIC_FILE, PRIVATE_FILE,
)


class OwnerControllerWindowsCI(unittest.TestCase):
    def setUp(self):
        if (os.name != "nt" or os.getenv("GITHUB_ACTIONS") != "true" or
                os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
                os.getenv("NF_OWNER_SIGNER_DISPOSABLE_CI") != "1"):
            self.skipTest("Only disposable Windows GitHub hosted runner")
        self.fi = SignedRealCoreAdmission(methodName=
            "test_real_owner_signature_admits_exact_draft_once")
        self.fi.setUp()
        self.root = Path(self.fi.tmp.name) / "owner-operator-protected"
        self.ci_user_name = "nfci" + secrets.token_hex(5)
        self.ci_user_password = secrets.token_urlsafe(21)
        self.ui_sid = None
        self.local_user_created = False
        self._create_ci_ui_user()
        self.signer_identity = operator_sid()
        self.assertNotEqual(self.ui_sid, self.signer_identity)
        self.manifest = enroll(
            self.root, ui_sid=self.ui_sid,
            confirm=lambda phrase: phrase,
            ci=True)
        self.pub = base64.b64decode(self.manifest["public_base64"], validate=True)
        self.now = int(time.time())

    def tearDown(self):
        try:
            if hasattr(self, "fi"):
                self.fi.tearDown()
        finally:
            if getattr(self, "local_user_created", False):
                import win32net
                win32net.NetUserDel(None, self.ci_user_name)

    def _create_ci_ui_user(self):
        import win32net
        import win32netcon
        import win32security
        flags = win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD
        info = {
            "name": self.ci_user_name,
            "password": self.ci_user_password,
            "priv": win32netcon.USER_PRIV_USER,
            "home_dir": "",
            "comment": "Disposable NF CI UI-only SID",
            "flags": flags,
            "script_path": "",
        }
        win32net.NetUserAdd(None, 1, info)
        self.local_user_created = True
        sid, _, _ = win32security.LookupAccountName(None, self.ci_user_name)
        self.ui_sid = win32security.ConvertSidToStringSid(sid)

    def sign(self, *, draft=None, spec=None, pin=None, confirm=None):
        return signed_enqueue_only(
            self.root,
            prepared_draft=self.fi.preview if draft is None else draft,
            spec=self.fi.permit()["spec"] if spec is None else spec,
            pinned_public=self.pub if pin is None else pin,
            confirm=(lambda notice: notice.splitlines()[-1])
            if confirm is None else confirm,
            now=self.now,
            ci=True)

    def test_operator_cli_refuses_headless_script_and_no_auto_enrollment(self):
        cli = Path(__file__).resolve().with_name("windows_owner_offline_cli.py")
        candidate = self.root.parent / "noninteractive-must-not-create-owner"
        result = subprocess.run(
            [sys.executable, "-B", str(cli), "enroll",
             "--owner-root", str(candidate),
             "--ui-windows-account", self.ci_user_name],
            stdin=subprocess.DEVNULL,
            capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(candidate.exists())
        self.assertNotIn(b"BEGIN PRIVATE", result.stdout + result.stderr)
        print("NF_WINDOWS_OFFLINE_OWNER_CLI_HEADLESS_DENIED_NO_KEY_CREATED=PASS")

    def test_nonexistent_or_same_sid_cannot_be_claimed_as_ui_account(self):
        with self.assertRaises(WindowsOwnerDenied):
            require_real_different_ui_account(self.signer_identity)
        with self.assertRaises(WindowsOwnerDenied):
            require_real_different_ui_account("S-1-5-21-1234-5678-9999-44444")
        self.assertEqual(require_real_different_ui_account(self.ui_sid), self.ui_sid)
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_WINDOWS_OWNER_UI_USER_SID_MUST_EXIST_AND_DIFFER=PASS")

    def test_real_dpapi_signing_and_real_core_queue_one_shot(self):
        permit = self.sign()
        self.assertEqual(permit["scope"],
                         "OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION")
        self.assertNotIn("private_key", str(permit))
        self.assertEqual(read_manifest(self.root, self.pub)[0], self.manifest)
        self.assertFalse(self.manifest["owner_presence_attested"])
        self.assertFalse(self.manifest["release_allowed"])
        self.assertNotEqual((self.root / PRIVATE_FILE).read_bytes()[:32], self.pub)
        result = admit_signed_draft(
            self.fi.workspace, self.fi.core, permit,
            owner_public_raw=self.pub, now=self.now)
        self.assertEqual(result["core_reported_state"], "QUEUED")
        self.assertFalse(result["queue_claim_allowed"])
        self.assertFalse(result["host_execution_allowed"])
        self.assertFalse(result["production_release"])
        self.assertEqual(self.fi.core.snapshot()["state"], "QUEUED")
        self.assertEqual(self.fi.workspace.list_tasks()[0]["state"],
                         "DRAFT_PENDING_OWNER_AUTH")
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.fi.workspace, self.fi.core, permit,
                               owner_public_raw=self.pub, now=self.now)
        print("NF_WINDOWS_DPAPI_OWNER_REAL_CORE_SIGNED_ENQUEUE_ONCE=PASS")

    def test_interactive_decline_and_wrong_pin_denied(self):
        with self.assertRaises(WindowsOwnerDenied):
            self.sign(confirm=lambda message: "NO")
        with self.assertRaises(WindowsOwnerDenied):
            self.sign(pin=b"x" * 32)
        with self.assertRaises(WindowsOwnerDenied):
            enroll(self.root, ui_sid=self.ui_sid,
                   confirm=lambda m: m, ci=True)
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_WINDOWS_OWNER_REJECTED_CONFIRMATION_AND_PIN=DENIED")

    def test_foreign_project_and_modified_source_denied(self):
        wrong_project = {**self.fi.permit()["spec"],
                         "project_id": "p-" + "f" * 32}
        wrong_commit = {**self.fi.permit()["spec"],
                        "approval_commit": "f" * 40}
        for spec in (wrong_project, wrong_commit):
            with self.subTest(spec=spec), self.assertRaises(WindowsOwnerDenied):
                self.sign(spec=spec)
        permit = self.sign()
        with self.fi.workspace.connect() as conn:
            conn.execute("UPDATE tasks SET objective=? WHERE id=?",
                         ("Different objective after owner signed immutable task.",
                          self.fi.draft["id"]))
            conn.commit()
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(
                self.fi.workspace, self.fi.core, permit,
                owner_public_raw=self.pub, now=self.now)
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_WINDOWS_OWNER_CORE_FOREIGN_PROJECT_STALE_DRAFT=DENIED")

    def test_tampered_private_ciphertext_fails_and_no_key_export(self):
        p = self.root / PRIVATE_FILE
        ciphertext = p.read_bytes()
        p.write_bytes(ciphertext[:-12] + bytes([ciphertext[-12] ^ 1]) +
                      ciphertext[-11:])
        with self.assertRaises(Exception):
            self.sign()
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_WINDOWS_DPAPI_PRIVATE_KEY_TAMPER=DENIED")

    def test_distinct_ui_windows_sid_cannot_read_protected_signer_key(self):
        import win32security
        import win32con
        identity = win32security.LogonUser(
            self.ci_user_name, os.environ["COMPUTERNAME"],
            self.ci_user_password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT,
        )
        private_path = self.root / PRIVATE_FILE
        public_path = self.root / PUBLIC_FILE
        # This block verifies the *kernel NTFS ACL*, not only a Python guard.
        try:
            win32security.ImpersonateLoggedOnUser(identity)
            with self.assertRaises((PermissionError, OSError)):
                private_path.read_bytes()
            with self.assertRaises((PermissionError, OSError)):
                public_path.read_bytes()
        finally:
            win32security.RevertToSelf()
            identity.Close()
        self.assertEqual(operator_sid(), self.signer_identity)
        print("NF_WINDOWS_REAL_DIFFERENT_UI_ACCOUNT_PRIVATE_KEY_READ=DENIED")


if __name__ == "__main__":
    unittest.main()
