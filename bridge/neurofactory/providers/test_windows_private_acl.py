"""Focused Windows ACL privilege gate cases only; all Qwen responses are MOCKS."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import evidence_receipt as receipt
from windows_private_acl import WindowsAclError, require_private_windows_acl


class PrivateDirectoryGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="nf-win-acl-negative-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.directory = self.root / "model_evidence"
        self.directory.mkdir(mode=0o700)

    @unittest.skipUnless(os.name == "nt", "Windows DACL only")
    def test_uncertain_dacl_fails_closed(self):
        with patch.object(receipt, "require_private_windows_acl",
                          side_effect=WindowsAclError("foreign ACE")):
            with self.assertRaises(receipt.EvidenceError):
                receipt.check_evidence_directory(self.directory)

    @unittest.skipUnless(os.name == "nt", "Windows DACL only")
    def test_real_acl_api_is_never_permissive_on_unreadable_path(self):
        missing = self.root / "unreadable-nonexistent-dir"
        with self.assertRaises(WindowsAclError):
            require_private_windows_acl(missing)

    @unittest.skipUnless(os.name == "nt", "Windows DACL only")
    def test_windows_dacl_checks_platform_directory_without_crashing(self):
        # A runner may have a private or inherited ACL. Both are acceptable
        # outcomes; the actual gate must explicitly decide rather than
        # silently default to "trusted" on API failure.
        try:
            require_private_windows_acl(self.directory)
        except WindowsAclError as exc:
            self.assertTrue(str(exc))
        else:
            self.assertTrue(self.directory.is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows DACL only")
    def test_acl_revocation_during_write_fails_closed(self):
        # Simulate a malicious DACL alteration after the first open.
        with patch.object(receipt, "require_private_windows_acl",
                          side_effect=[None, WindowsAclError("ACL changed")]) as verify:
            with self.assertRaises(receipt.EvidenceError):
                with receipt._pinned_directory(self.directory):
                    pass
            self.assertEqual(verify.call_count, 2)

    def test_no_untrusted_symlink_directory(self):
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.directory, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable for this test")
        with self.assertRaises(receipt.EvidenceError):
            receipt.check_evidence_directory(alias)

    def test_foreign_acl_blocked_before_ollama_call(self):
        import ollama_worker as worker
        import local_qwen
        task = worker.ProviderTask(
            task_id="NF-DEV-05-Q503", project_id="sandbox-one",
            input_sha256="a"*64, target_path="src/example.py",
            instruction="Generate a harmless one-function toy file.",
        )
        ledger = self.root / "ledger"
        ledger.mkdir(mode=0o700)
        with patch.object(worker, "check_resources",
                          return_value={"free_ram_bytes": 4 * worker.ONE_GIB}):
            with patch.object(worker, "check_evidence_directory",
                              side_effect=receipt.EvidenceError("untrusted DACL")):
                with patch.object(local_qwen, "_loopback_post") as inference:
                    result = worker.execute_one(
                        task, model="qwen2.5-coder:1.5b",
                        ledger_dir=ledger, evidence_dir=self.directory)
                    inference.assert_not_called()
        self.assertEqual(result["error_code"], "BLOCKED_EVIDENCE_DIRECTORY")
        self.assertFalse(result["attempt_consumed"])


if __name__ == "__main__":
    unittest.main()
