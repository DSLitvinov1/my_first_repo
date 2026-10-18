"""Isolated ACL policy tests; do not install services or modify access rights."""
import os
from pathlib import Path
import tempfile
import unittest

from windows_service_sid_acl_audit import (
    inspect_windows_two_sid_boundary, IsolationDenied, _verify_acl_entries,
)

RECEIVER = "S-1-5-21-111-222-333-1002"
WORKER = "S-1-5-21-111-222-333-1001"
STRANGER = "S-1-5-21-111-222-333-1003"
SYSTEM = "S-1-5-18"
ADMIN = "S-1-5-32-544"
WRITE = 0x00120116


class WindowsServiceBoundaryTests(unittest.TestCase):
    def test_missing_service_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IsolationDenied):
                inspect_windows_two_sid_boundary(
                    "NeurofactorySandboxReceiver", root, WORKER)

    def test_no_user_supplied_service_name_substitution(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IsolationDenied):
                inspect_windows_two_sid_boundary("AttackerFakeReceiver", root, WORKER)

    def test_sids_must_be_real_windows_account_identifiers(self):
        with tempfile.TemporaryDirectory() as root:
            for sid in ("Everyone", "S-1-1-0", "", None):
                with self.subTest(sid=sid):
                    with self.assertRaises(IsolationDenied):
                        inspect_windows_two_sid_boundary(
                            "NeurofactorySandboxReceiver", root, sid)

    def test_missing_and_reparse_roots_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(IsolationDenied):
                inspect_windows_two_sid_boundary(
                    "NeurofactorySandboxReceiver", str(Path(root) / "missing"), WORKER)

    def test_unprovisioned_runner_must_never_gain_approval(self):
        with tempfile.TemporaryDirectory() as root:
            for _ in range(2):
                with self.assertRaises(IsolationDenied):
                    inspect_windows_two_sid_boundary(
                        "NeurofactorySandboxReceiver", root, WORKER)

    def test_windows_scm_manager_access_uses_real_pywin32_constant(self):
        # Live Windows API shape, but no service install. A mocked refusal at
        # OpenSCManager proves that the proper Windows API is reached instead
        # of masking an AttributeError with a blanket IsolationDenied.
        if os.name != "nt":
            self.skipTest("Win32 API regression only on hosted Windows")
        import win32service
        with tempfile.TemporaryDirectory() as root:
            with patch.object(win32service, "OpenSCManager",
                              side_effect=RuntimeError("intentional read-only refusal")) as opener:
                with self.assertRaises(IsolationDenied):
                    inspect_windows_two_sid_boundary(
                        "NeurofactorySandboxReceiver", root,
                        "S-1-5-21-123-456-789-1001")
            opener.assert_called_once_with(
                None, None, win32service.SC_MANAGER_CONNECT)

    def test_utility_does_not_mutate_scm_ntfs_or_launch_services(self):
        s = Path(__file__).with_name("windows_service_sid_acl_audit.py").read_text()
        for forbidden in (
            "CreateService(", "ChangeServiceConfig(", "SetNamedSecurityInfo(",
            "SetSecurityInfo(", "subprocess.run(", "CreateProcess(",
            "win32serviceutil.InstallService(",
        ):
            self.assertNotIn(forbidden, s)
        self.assertRegex(s, r'"release_approved"\s*:\s*False')
        self.assertRegex(s, r'"live_execution_allowed"\s*:\s*False')


class PureAclPolicyTests(unittest.TestCase):
    def assert_denied(self, entries, owner=SYSTEM, protected=True, worker=WORKER):
        with self.assertRaises(IsolationDenied):
            _verify_acl_entries(entries, RECEIVER, worker, owner, protected)

    def test_minimal_protected_receiver_acl_is_policy_compatible(self):
        self.assertEqual(
            _verify_acl_entries([(RECEIVER, 0, WRITE)], RECEIVER, WORKER,
                                RECEIVER, True),
            (),
        )

    def test_privileged_os_accounts_explicitly_identified(self):
        entries = [(RECEIVER, 0, WRITE), (SYSTEM, 0, WRITE), (ADMIN, 0, WRITE)]
        self.assertEqual(
            _verify_acl_entries(entries, RECEIVER, WORKER, ADMIN, True),
            (SYSTEM, ADMIN) if SYSTEM < ADMIN else (ADMIN, SYSTEM),
        )

    def test_arbitrary_extra_writer_is_denied(self):
        self.assert_denied([(RECEIVER, 0, WRITE), (STRANGER, 0, WRITE)])

    def test_worker_group_and_world_writers_denied(self):
        for sid in (WORKER, "S-1-1-0", "S-1-5-11", "S-1-5-32-545"):
            with self.subTest(sid=sid):
                self.assert_denied([(RECEIVER, 0, WRITE), (sid, 0, WRITE)])

    def test_worker_owning_directory_is_denied_even_without_writer_ace(self):
        self.assert_denied([(RECEIVER, 0, WRITE)], owner=WORKER)

    def test_unknown_unprivileged_owner_is_denied(self):
        self.assert_denied([(RECEIVER, 0, WRITE)], owner=STRANGER)

    def test_inheritable_acl_not_protected_is_denied(self):
        self.assert_denied([(RECEIVER, 0, WRITE)], protected=False)

    def test_cannot_claim_receiver_write_access_from_read_only_ace(self):
        self.assert_denied([(RECEIVER, 0, 0x00120089)])

    def test_other_writes_through_delete_or_acl_rights_are_denied(self):
        for mask in (0x00010000, 0x00000040, 0x00040000, 0x00080000,
                     0x10000000, 0x40000000, 0x02000000):
            with self.subTest(mask=hex(mask)):
                self.assert_denied([(RECEIVER, 0, WRITE), (STRANGER, 0, mask)])

    def test_ambiguous_denial_and_object_aces_are_denied(self):
        for extra in ((RECEIVER, 1, WRITE), ("S-1-1-0", 1, WRITE),
                      (STRANGER, 5, WRITE), (STRANGER, 9, WRITE)):
            with self.subTest(extra=extra):
                self.assert_denied([(RECEIVER, 0, WRITE), extra])

    def test_malformed_acls_fail_closed(self):
        valid = [(RECEIVER, 0, WRITE)]
        for bad in ([], valid * 1025, [(RECEIVER, True, WRITE)],
                    [(RECEIVER, 0, True)], [(RECEIVER, 0, -1)],
                    [(RECEIVER, 0)], [("x",)]):
            with self.subTest(size=len(bad)):
                self.assert_denied(bad)

    def test_same_or_privileged_worker_sid_denied(self):
        for sid in (RECEIVER, SYSTEM, ADMIN):
            with self.subTest(sid=sid):
                self.assert_denied([(RECEIVER, 0, WRITE)], worker=sid)


if __name__ == "__main__":
    unittest.main()
