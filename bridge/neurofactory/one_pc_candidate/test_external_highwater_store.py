"""Only temporary isolated witness DB and synthetic ephemeral Ed25519 keys."""
import hashlib
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from independent_witness_receipt import verify_external_witness_receipt
from external_highwater_store import (
    provision_empty_database,reserve_external_epoch,
    inspect_external_highwater,HighwaterStoreDenied,
)
def digest(txt):
    return hashlib.sha256(txt.encode()).hexdigest()

class RealDurableWitnessCAS(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name).resolve()/"remote.sqlite3"
        self.signer=Ed25519PrivateKey.generate()
        self.now=int(time.time())
        self.source="a"*40
        self.package=digest("approved signed release synthetic")
        self.machine=digest("approved machine synthetic")
        provision_empty_database(self.path)
        self.assertEqual(inspect_external_highwater(self.path)["highest_committed_epoch"],0)
    def tearDown(self):
        self.tmp.cleanup()
    def claim(self,epoch=1,operation="one"):
        return {
            "schema":"nf.onepc.highwater.claim.v1",
            "source_sha40":self.source,
            "package_sha256":self.package,
            "machine_identity_sha256":self.machine,
            "review_evidence_sha256":digest("reviewer signed evidence fixture"),
            "operation_sha256":digest(operation),
            "external_epoch":epoch,
            "nonce":secrets.token_hex(32),
        }
    def reserve(self,claim,**overrides):
        args=dict(database=self.path,claim=claim,
                  private_witness_signer=self.signer,
                  operator_pinned_witness_id="witness-independent-node-1",
                  operator_pinned_machine_identity_sha256=self.machine,
                  operator_pinned_package_sha256=self.package,
                  operator_pinned_source_sha40=self.source,
                  now_unix=self.now)
        args.update(overrides)
        return reserve_external_epoch(**args)
    def test_real_sqlite_committed_first_signed_then_verified(self):
        claim=self.claim()
        receipt=self.reserve(claim)
        verified=verify_external_witness_receipt(
            claim=claim,receipt=receipt,
            pinned_witness_public=self.signer.public_key(),
            independently_pinned_witness_id="witness-independent-node-1",
            independently_observed_minimum_epoch=1,now_unix=self.now)
        self.assertEqual(verified["highest_committed_epoch"],1)
        self.assertFalse(verified["production_install_authorized"])
        self.assertEqual(inspect_external_highwater(self.path)["reserved_operations"],1)
        self.assertEqual(self.reserve_next(2)["evidence"]["highest_committed_epoch"],2)
        self.assertEqual(inspect_external_highwater(self.path)["highest_committed_epoch"],2)
    def reserve_next(self,epoch):
        return self.reserve(self.claim(epoch=epoch,operation="op-"+str(epoch)))
    def test_duplicate_delivery_after_lost_reply_never_repeats(self):
        one=self.claim()
        self.reserve(one)
        with self.assertRaises(HighwaterStoreDenied):
            self.reserve(one)
        self.assertEqual(inspect_external_highwater(self.path)["highest_committed_epoch"],1)
    def test_operation_cannot_be_reused_with_new_nonce(self):
        self.reserve(self.claim())
        with self.assertRaises(HighwaterStoreDenied):
            self.reserve(self.claim(2))
        self.assertEqual(inspect_external_highwater(self.path)["highest_committed_epoch"],1)
    def test_skipped_and_rolled_back_epochs_refused(self):
        with self.assertRaises(HighwaterStoreDenied):
            self.reserve(self.claim(2))
        self.reserve(self.claim(1))
        with self.assertRaises(HighwaterStoreDenied):
            self.reserve(self.claim(1,operation="another"))
    def test_foreign_machine_package_or_source_refused_before_mutation(self):
        for change in (
            {"operator_pinned_machine_identity_sha256":digest("different")},
            {"operator_pinned_package_sha256":digest("different")},
            {"operator_pinned_source_sha40":"b"*40},
        ):
            with self.assertRaises(HighwaterStoreDenied):
                self.reserve(self.claim(),**change)
            self.assertEqual(inspect_external_highwater(self.path)["highest_committed_epoch"],0)
    def test_fake_or_mismatched_crypto_key_refused(self):
        with self.assertRaises(HighwaterStoreDenied):
            self.reserve(self.claim(),private_witness_signer=bytes(32))
        self.assertEqual(inspect_external_highwater(self.path)["highest_committed_epoch"],0)
    def test_operator_cannot_replace_preexisting_state(self):
        with self.assertRaises(HighwaterStoreDenied):
            provision_empty_database(self.path)
    def test_corrupt_counter_blocks_future_tasks(self):
        conn=sqlite3.connect(self.path)
        conn.execute("UPDATE counter SET highest_epoch=7 WHERE singleton=1")
        conn.commit();conn.close()
        with self.assertRaises(HighwaterStoreDenied):
            inspect_external_highwater(self.path)
        with self.assertRaises(HighwaterStoreDenied):
            self.reserve(self.claim(1))
    def test_private_witness_disk_state_never_claims_hardware_attestation(self):
        report=inspect_external_highwater(self.path)
        self.assertFalse(report["remote_physical_independence_attested"])
        self.assertFalse(report["production_effects_authorized"])

if __name__=="__main__":
    unittest.main()
