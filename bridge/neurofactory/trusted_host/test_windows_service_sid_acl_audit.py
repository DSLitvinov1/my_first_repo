"""Isolated Windows negative tests; no service installation or ACL mutation."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from windows_service_sid_acl_audit import inspect_windows_two_sid_boundary, IsolationDenied

class WindowsServiceBoundaryTests(unittest.TestCase):
    def test_missing_service_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IsolationDenied):
                inspect_windows_two_sid_boundary(
                    "NeurofactorySandboxReceiver",root,"S-1-5-21-123-456-789-1001")
    def test_no_user_supplied_service_name_substitution(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IsolationDenied):
                inspect_windows_two_sid_boundary(
                    "AttackerFakeReceiver",root,"S-1-5-21-123-456-789-1001")
    def test_sids_must_be_real_windows_account_identifiers(self):
        with tempfile.TemporaryDirectory() as root:
            for sid in ("Everyone","S-1-1-0","",None):
                with self.subTest(sid=sid):
                    with self.assertRaises(IsolationDenied):
                        inspect_windows_two_sid_boundary("NeurofactorySandboxReceiver",root,sid)
    def test_missing_and_reparse_roots_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IsolationDenied):
                inspect_windows_two_sid_boundary(
                    "NeurofactorySandboxReceiver",str(Path(root)/"missing"),
                    "S-1-5-21-123-456-789-1001")
    def test_unprovisioned_runner_must_never_gain_approval(self):
        with tempfile.TemporaryDirectory() as root:
            for _ in range(2):
                with self.assertRaises(IsolationDenied):
                    inspect_windows_two_sid_boundary("NeurofactorySandboxReceiver",
                        root,"S-1-5-21-123-456-789-1001")
    def test_utility_does_not_mutate_scm_ntfs_or_launch_services(self):
        s=Path(__file__).with_name("windows_service_sid_acl_audit.py").read_text()
        for forbidden in ("CreateService(","ChangeServiceConfig(","SetNamedSecurityInfo(",
                          "SetSecurityInfo(","subprocess.run(","CreateProcess(",
                          "win32serviceutil.InstallService("):
            self.assertNotIn(forbidden,s)
        self.assertIn('"release_approved":False',s)
        self.assertIn('"live_execution_allowed":False',s)

if __name__=="__main__":
    unittest.main()
