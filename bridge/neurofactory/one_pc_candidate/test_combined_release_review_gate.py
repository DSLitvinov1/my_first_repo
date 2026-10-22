"""One new read-only combined-gate path with disposable in-memory keys only."""
import base64
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import secrets
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secure_release_preflight import _DOMAIN as RD, _canonical
from independent_witness_receipt import _DOMAIN as WD
from combined_release_review_gate import inspect_combined_release_candidate, CombinedReleaseDenied
from windows_package_preflight import WindowsPackageDenied

def digest(s):
    return sha256(s.encode("ascii")).hexdigest()

class CombinedReleaseAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time())
        self.priv={x:Ed25519PrivateKey.generate() for x in RD}
        self.pins={x:s.public_key() for x,s in self.priv.items()}
        self.witness=Ed25519PrivateKey.generate()
        self.claim={
            "schema":"neurofactory.onepc.release_claim.v1",
            "repository":"DSLitvinov1/my_first_repo",
            "candidate_sha":"cc9cf22ee246ff376b84490c0f118612ac82ac51",
            "installer_sha256":digest("actual-signed-exe-only-a-fixture"),
            "components_manifest_sha256":digest("manifest-fixture"),
            "review_evidence_sha256":digest("synthetic-fixture-not-human-approval"),
            "owner_id":"independent-owner-demo",
            "reviewer_id":"independent-reviewer-demo",
            "witness_id":"independent-witness-demo",
            "machine_identity_sha256":digest("physical-machine-hash-fixture"),
            "external_epoch":17,
            "nonce":secrets.token_hex(16),
            "issued_unix":self.now-3,
            "expires_unix":self.now+60,
            "review_verdict":"APPROVE",
            "scope":"REVIEWED_INSTALL_ONLY_NO_AUTORUN",
            "service_name":"NeurofactoryCoreHost",
        }
        self.expected={x:self.claim[x] for x in (
            "candidate_sha","installer_sha256","components_manifest_sha256",
            "review_evidence_sha256","owner_id","reviewer_id","witness_id",
            "machine_identity_sha256")}
        self.expected["minimum_external_epoch"]=17
        self.signatures={
            x:{
                "role":x,"claim":deepcopy(self.claim),
                "signature_base64":base64.b64encode(
                    self.priv[x].sign(RD[x]+_canonical(self.claim))).decode(),
            }
            for x in RD
        }
        self.wclaim={
            "schema":"nf.onepc.highwater.claim.v1",
            "source_sha40":self.claim["candidate_sha"],
            "package_sha256":self.claim["installer_sha256"],
            "machine_identity_sha256":self.claim["machine_identity_sha256"],
            "review_evidence_sha256":self.claim["review_evidence_sha256"],
            "operation_sha256":digest("one-test-only-operation"),
            "external_epoch":17,
            "nonce":secrets.token_hex(32),
        }
        self.ack={
            "schema":"nf.onepc.external_witness.highwater.v1",
            "claim_sha256":sha256(_canonical(self.wclaim)).hexdigest(),
            "source_sha40":self.claim["candidate_sha"],
            "machine_identity_sha256":self.claim["machine_identity_sha256"],
            "witness_id":"independent-witness-demo",
            "highest_committed_epoch":17,
            "previous_accepted_epoch":16,
            "recorded_unix":self.now-1,
            "expires_unix":self.now+30,
            "decision":"RECORDED_EXTERNALLY_NO_AUTO_RETRY",
            "separate_device_claimed":True,
        }
        self.receipt={
            "evidence":self.ack,
            "signature_base64":base64.b64encode(
                self.witness.sign(WD+_canonical(self.ack))).decode(),
        }
    def inspect(self,**changes):
        opts=dict(
            installer=Path("/synthetic-signed-installer.exe").resolve(),
            signatures=self.signatures,pinned_release_keys=self.pins,
            independently_pinned_release=self.expected,
            now_unix=self.now,
            observed_manifest_sha256=self.claim["components_manifest_sha256"],
            witness_claim=self.wclaim,witness_receipt=self.receipt,
            independently_pinned_witness_key=self.witness.public_key(),
            independently_pinned_witness_id="independent-witness-demo",
            fresh_external_minimum_epoch=17,
            independently_pinned_publisher_thumbprint="A"*40,
        )
        opts.update(changes)
        with patch("combined_release_review_gate.inspect_windows_package",
                   return_value={"production_release_allowed":False}):
            return inspect_combined_release_candidate(**opts)
    def test_all_synthetic_crypto_even_with_mocked_valid_publisher_still_denies_release(self):
        report=self.inspect()
        self.assertTrue(report["three_distinct_claim_signatures_checked"])
        self.assertTrue(report["separate_highwater_signature_checked"])
        self.assertFalse(report["production_installer_authorized"])
        self.assertFalse(report["service_activation_authorized"])
        self.assertFalse(report["current_review_approved_by_independent_human_attested"])
        self.assertFalse(report["remote_highwater_queried_during_this_operation"])
    def test_witness_different_package_or_physical_identity_denied(self):
        with self.assertRaises(CombinedReleaseDenied):
            self.inspect(witness_claim={**self.wclaim,
                       "package_sha256":digest("different-installer")})
        with self.assertRaises(CombinedReleaseDenied):
            self.inspect(witness_claim={**self.wclaim,
                       "machine_identity_sha256":digest("different-machine")})
    def test_forged_reviewer_signature_denied(self):
        signatures=deepcopy(self.signatures)
        signatures["reviewer"]["signature_base64"]=base64.b64encode(b"\0"*64).decode()
        with self.assertRaises(CombinedReleaseDenied):
            self.inspect(signatures=signatures)
    def test_external_counter_lower_than_remote_minimum_denied(self):
        with self.assertRaises(CombinedReleaseDenied):
            self.inspect(fresh_external_minimum_epoch=18)
    def test_absent_or_bad_windows_code_signing_denied(self):
        with patch("combined_release_review_gate.inspect_windows_package",
                   side_effect=WindowsPackageDenied("UNSIGNED")):
            with self.assertRaises(CombinedReleaseDenied):
                inspect_combined_release_candidate(
                    installer=Path("/synthetic-signed-installer.exe").resolve(),
                    signatures=self.signatures,pinned_release_keys=self.pins,
                    independently_pinned_release=self.expected,
                    now_unix=self.now,
                    observed_manifest_sha256=self.claim["components_manifest_sha256"],
                    witness_claim=self.wclaim,witness_receipt=self.receipt,
                    independently_pinned_witness_key=self.witness.public_key(),
                    independently_pinned_witness_id="independent-witness-demo",
                    fresh_external_minimum_epoch=17,
                    independently_pinned_publisher_thumbprint="A"*40)
if __name__=="__main__":
    unittest.main()
