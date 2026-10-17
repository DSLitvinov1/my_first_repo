"""Local signer anchor logic only: no cross-UID security claim or live permit."""
import copy
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest

from offline_operator_anchor import (
    OperatorAnchorDenied, bootstrap, advance_fixture, verify_current
)

def digest(text):
    return hashlib.sha256(text.encode("utf8")).hexdigest()

class OperatorAnchorLogicTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix" or os.geteuid()==0 or os.environ.get("NF_OPERATOR_ANCHOR_FIXTURE_ONLY")!="1":
            self.skipTest("requires non-root explicit test-only Linux environment")
        self.temp=tempfile.TemporaryDirectory(prefix="nf-local-anchor-test-")
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)/"nf-signer-fixture"
        self.home.mkdir(mode=0o700)
        self.boot=bootstrap(self.home)
        self.pin=self.boot["public_key_sha256"]
        self.pub=self.boot["public_key_base64"]
    def make(self,n):
        return advance_fixture(self.home,digest(n))
    def check(self,p,*,pin=None,pub=None):
        return verify_current(self.home,p,
            self.pin if pin is None else pin,
            self.pub if pub is None else pub)
    def test_key_stays_private_and_bootstrap_never_returns_it(self):
        self.assertEqual(set(self.boot),{
            "status","public_key_base64","public_key_sha256","can_authorize_live_operations"})
        self.assertFalse(self.boot["can_authorize_live_operations"])
        self.assertEqual(stat.S_IMODE((self.home/"issuer-private.raw").stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE((self.home/"protected-anchor.json").stat().st_mode),0o600)
    def test_current_tip_verification_is_crypto_only(self):
        p=self.make("first")
        result=self.check(p)
        self.assertEqual(result["sequence"],1)
        self.assertFalse(result["operation_execution_allowed"])
        self.assertFalse(result["production_owner_authenticated"])
    def test_old_valid_receipt_rejected_after_new_advance(self):
        first=self.make("first")
        second=self.make("second")
        self.assertEqual(self.check(second)["sequence"],2)
        with self.assertRaises(OperatorAnchorDenied):
            self.check(first)
    def test_forged_receipt_fails_signature(self):
        p=self.make("first")
        p=copy.deepcopy(p)
        p["certificate"]["claim_sha256"]=digest("forged")
        with self.assertRaises(OperatorAnchorDenied):
            self.check(p)
    def test_wrong_independently_pinned_key_denied(self):
        p=self.make("first")
        with self.assertRaises(OperatorAnchorDenied):
            self.check(p,pin="f"*64)
    def test_invalid_public_key_bytes_denied(self):
        p=self.make("first")
        with self.assertRaises(OperatorAnchorDenied):
            self.check(p,pub="AA==")
    def test_duplicate_operation_does_not_move_tip(self):
        d=digest("same")
        first=advance_fixture(self.home,d)
        with self.assertRaises(OperatorAnchorDenied):
            advance_fixture(self.home,d)
        self.assertEqual(self.check(first)["sequence"],1)
    def test_bootstrap_cannot_reset_anchor(self):
        p=self.make("once")
        with self.assertRaises(OperatorAnchorDenied):
            bootstrap(self.home)
        self.assertEqual(self.check(p)["sequence"],1)
    def test_malformed_anchor_fails_closed_after_valid_signature(self):
        packet=self.make("one legitimate signed event")
        self.assertEqual(self.check(packet)["sequence"],1)
        (self.home/"protected-anchor.json").write_text("{}",encoding="ascii")
        with self.assertRaisesRegex(OperatorAnchorDenied,"damaged monotonic anchor"):
            self.check(packet)
    def test_duplicate_key_or_unexpected_fields_in_packet_denied(self):
        p=self.make("x")
        p=dict(p,operator_approved=True)
        with self.assertRaises(OperatorAnchorDenied):
            self.check(p)
    def test_packet_must_not_claim_execute_allowed(self):
        p=self.make("first")
        p["execution_allowed"]=True
        with self.assertRaises(OperatorAnchorDenied):
            self.check(p)
    def test_multiple_operations_monotonic_chain(self):
        for i in range(10):
            p=self.make(f"claim-{i}")
            self.assertEqual(self.check(p)["sequence"],i+1)
            self.assertFalse(p["execution_allowed"])
    def test_disposable_dir_must_be_private(self):
        home=self.home
        home.chmod(0o755)
        with self.assertRaises(OperatorAnchorDenied):
            self.make("x")
    def test_wrong_directory_basename_denied(self):
        other=Path(self.temp.name)/"another-dir"
        other.mkdir(mode=0o700)
        with self.assertRaises(OperatorAnchorDenied):
            bootstrap(other)

if __name__=="__main__":
    unittest.main()
