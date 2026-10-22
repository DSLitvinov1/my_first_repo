"""Windows-only targeted read-only signed-installer preflight checks.

This test NEVER runs or installs the unsigned Neurofactory installer.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from windows_package_preflight import inspect_windows_package,WindowsPackageDenied

PUB="AB"*20
class WindowsPublisherPreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-authenticode-preflight-")
        self.file=Path(self.tmp.name).resolve()/"Neurofactory-TEST-ONLY.exe"
        self.file.write_bytes(b"MZ"+(b"test signed file placeholder not executable"*80))
        self.digest=sha256(self.file.read_bytes()).hexdigest()

    def tearDown(self):self.tmp.cleanup()

    def observe(self, *, digest=None, thumb=None, file=None):
        return inspect_windows_package(
            installer=self.file if file is None else file,
            expected_sha256=self.digest if digest is None else digest,
            pinned_publisher_thumbprint=PUB if thumb is None else thumb,
        )

    def test_valid_pinned_authenticode_report_does_not_execute_setup(self):
        fake=Mock(returncode=0,stdout=json.dumps({"status":"Valid","thumbprint":PUB}),stderr="")
        with patch("subprocess.run",return_value=fake) as cmd:
            result=self.observe()
        self.assertEqual(cmd.call_count,1)
        args=cmd.call_args.args[0]
        self.assertEqual(args[:3],["powershell.exe","-NoProfile","-NonInteractive"])
        self.assertIn("-EncodedCommand",args)
        self.assertNotIn(str(self.file),args)
        self.assertEqual(cmd.call_args.kwargs["env"]["NF_ATTEST_READONLY_SETUP"],str(self.file))
        self.assertEqual(result["status"],"SIGNED_PACKAGE_AND_PIN_MATCH_NO_INSTALL")
        self.assertFalse(result["service_install_allowed"])
        self.assertFalse(result["production_release_allowed"])
        self.assertFalse(result["installer_was_executed"])

    def test_wrong_file_digest_rejected_before_powershell(self):
        with patch("subprocess.run",side_effect=AssertionError("should not execute")):
            with self.assertRaises(WindowsPackageDenied):
                self.observe(digest="f"*64)

    def test_unsigned_installer_rejected(self):
        fake=Mock(returncode=0,stdout=json.dumps({"status":"NotSigned","thumbprint":""}),stderr="")
        with patch("subprocess.run",return_value=fake):
            with self.assertRaises(WindowsPackageDenied):self.observe()

    def test_untrusted_but_signed_installer_rejected(self):
        fake=Mock(returncode=0,stdout=json.dumps({"status":"UnknownError","thumbprint":PUB}),stderr="")
        with patch("subprocess.run",return_value=fake):
            with self.assertRaises(WindowsPackageDenied):self.observe()

    def test_wrong_publisher_cert_rejected(self):
        fake=Mock(returncode=0,stdout=json.dumps({"status":"Valid","thumbprint":"CD"*20}),stderr="")
        with patch("subprocess.run",return_value=fake):
            with self.assertRaises(WindowsPackageDenied):self.observe()

    def test_nonexe_and_linked_file_rejected_without_subprocess(self):
        with patch("subprocess.run",side_effect=AssertionError("not allowed")):
            other=self.file.with_suffix(".cmd")
            other.write_bytes(self.file.read_bytes())
            with self.assertRaises(WindowsPackageDenied):
                self.observe(file=other)
            linked=self.file.parent/"shortcut.exe"
            try:
                linked.symlink_to(self.file)
            except (OSError,NotImplementedError):
                pass
            else:
                with self.assertRaises(WindowsPackageDenied):
                    self.observe(file=linked)

    def test_malformed_and_failed_authenticode_rejected(self):
        variants=[Mock(returncode=0,stdout="not-json",stderr=""),
                  Mock(returncode=1,stdout="",stderr="no signature"),
                  Mock(returncode=0,stdout=json.dumps({"status":"Valid","thumbprint":PUB,"extra":1}),stderr="")]
        for value in variants:
            with self.subTest(value=value.stdout), patch("subprocess.run",return_value=value):
                with self.assertRaises(WindowsPackageDenied):
                    self.observe()

    def test_installer_swap_between_hash_and_authenticode_refused(self):
        fake=Mock(returncode=0,stdout=json.dumps({"status":"Valid","thumbprint":PUB}),stderr="")
        def altered_during_check(*args, **kwargs):
            with self.file.open("ab") as stream:
                stream.write(b"MALICIOUS_MODIFICATION_AFTER_INITIAL_HASH")
            return fake
        with patch("subprocess.run",side_effect=altered_during_check) as run:
            with self.assertRaises(WindowsPackageDenied):
                self.observe()
        self.assertEqual(run.call_count,1)

    def test_broken_signature_process_no_auto_retry(self):
        with patch("subprocess.run",side_effect=TimeoutError("synthetic")) as tool:
            # TimeoutError is also an OSError on Windows; fail closed and
            # expose no uncontrolled retry.
            with self.assertRaises(WindowsPackageDenied):
                self.observe()
            self.assertEqual(tool.call_count,1)
        from subprocess import TimeoutExpired
        with patch("subprocess.run",side_effect=TimeoutExpired(cmd="pwsh",timeout=20)) as tool:
            with self.assertRaises(WindowsPackageDenied):
                self.observe()
            self.assertEqual(tool.call_count,1)

if __name__=="__main__":
    unittest.main()
