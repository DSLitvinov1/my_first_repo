"""Targeted release-preflight checks. All signers are DISPOSABLE IN-MEMORY TEST ONLY."""
from __future__ import annotations

import base64
from copy import deepcopy
from hashlib import sha256
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secure_release_preflight import (
    _DOMAIN, _canonical, check_signed_release_preflight, SecureReleaseDenied,
)

def digest(label):
    return sha256(label.encode("utf-8")).hexdigest()

class IndependentReleaseGateTest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.private = {role:Ed25519PrivateKey.generate() for role in _DOMAIN}
        self.pinned = {role:secret.public_key() for role,secret in self.private.items()}
        self.claim = {
            "schema": "neurofactory.onepc.release_claim.v1",
            "repository": "DSLitvinov1/my_first_repo",
            "candidate_sha": "a9bb3724c2a0636803987496e26b51af3276f55c",
            "installer_sha256": digest("CI-built unsigned Windows draft installer"),
            "components_manifest_sha256": digest("CI-built manifest"),
            "review_evidence_sha256": digest("unavailable reviewer evidence TEST ONLY"),
            "owner_id": "owner_test", "reviewer_id": "reviewer_test",
            "witness_id": "witness_test",
            "machine_identity_sha256": digest("CI-disposable-machine-ONLY"),
            "external_epoch": 12,
            "nonce": "e" * 32,
            "issued_unix": self.now-5, "expires_unix": self.now+600,
            "review_verdict": "APPROVE",
            "scope": "REVIEWED_INSTALL_ONLY_NO_AUTORUN",
            "service_name": "NeurofactoryCoreHost",
        }
        self.expected = {
            "candidate_sha": self.claim["candidate_sha"],
            "installer_sha256": self.claim["installer_sha256"],
            "components_manifest_sha256": self.claim["components_manifest_sha256"],
            "review_evidence_sha256": self.claim["review_evidence_sha256"],
            "owner_id": self.claim["owner_id"],
            "reviewer_id": self.claim["reviewer_id"],
            "witness_id": self.claim["witness_id"],
            "machine_identity_sha256": self.claim["machine_identity_sha256"],
            "minimum_external_epoch": self.claim["external_epoch"],
        }

    def signed(self, claim=None, secrets=None):
        claim=self.claim if claim is None else claim
        secrets=self.private if secrets is None else secrets
        return {
            role: {
                "role": role,
                "claim": deepcopy(claim),
                "signature_base64": base64.b64encode(
                    secrets[role].sign(_DOMAIN[role]+_canonical(claim))
                ).decode("ascii"),
            }
            for role in _DOMAIN
        }

    def inspect(self, envelopes=None, *, observed_installer=None,
                observed_manifest=None, pins=None, expected=None, now=None):
        return check_signed_release_preflight(
            signatures=self.signed() if envelopes is None else envelopes,
            pinned_keys=self.pinned if pins is None else pins,
            operator_expected=self.expected if expected is None else expected,
            now_unix=self.now if now is None else now,
            observed_installer_sha256=(
                self.claim["installer_sha256"] if observed_installer is None else observed_installer),
            observed_manifest_sha256=(
                self.claim["components_manifest_sha256"] if observed_manifest is None else observed_manifest),
        )

    def test_independent_three_signatures_still_cannot_install(self):
        result=self.inspect()
        self.assertTrue(result["owner_signature_checked"])
        self.assertTrue(result["independent_reviewer_signature_checked"])
        self.assertTrue(result["independent_witness_signature_checked"])
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["service_install_allowed"])
        self.assertFalse(result["automatic_code_effects_allowed"])
        self.assertFalse(result["physical_machine_identity_independently_attested"])
        self.assertEqual(result["status"], "THREE_SIGNATURES_MATCH_NOT_INSTALL_AUTHORIZATION")

    def test_reviewer_missing_or_wrong_key_denied(self):
        signatures=self.signed()
        signatures.pop("reviewer")
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(signatures)
        wrong=self.signed()
        wrong["reviewer"]["signature_base64"]=base64.b64encode(
            Ed25519PrivateKey.generate().sign(_DOMAIN["reviewer"]+_canonical(self.claim))
        ).decode("ascii")
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(wrong)

    def test_owner_witness_or_reviewer_replacement_denied(self):
        for role in _DOMAIN:
            with self.subTest(role=role):
                packet=self.signed()
                packet[role]["signature_base64"]=self.signed()["owner"]["signature_base64"] \
                    if role != "owner" else self.signed()["reviewer"]["signature_base64"]
                with self.assertRaises(SecureReleaseDenied):
                    self.inspect(packet)

    def test_replayed_approval_for_another_sha_or_machine_denied(self):
        for key in ("candidate_sha", "machine_identity_sha256", "review_evidence_sha256"):
            with self.subTest(key=key):
                expected=dict(self.expected)
                expected[key]="d" * (40 if key=="candidate_sha" else 64)
                with self.assertRaises(SecureReleaseDenied):
                    self.inspect(expected=expected)

    def test_modified_installer_or_manifest_on_disk_denied(self):
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(observed_installer="f"*64)
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(observed_manifest="f"*64)

    def test_external_rollback_counter_requires_operator_minimum(self):
        expect=dict(self.expected,minimum_external_epoch=13)
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(expected=expect)

    def test_expired_approval_and_long_lived_claim_denied(self):
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(now=self.now+601)
        future=dict(self.claim,expires_unix=self.now+4000)
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(self.signed(future))

    def test_reject_or_unknown_verdict_cannot_provision(self):
        for verdict in ("REJECT","INCONCLUSIVE","WAIT_CORE_SHA", True):
            with self.subTest(verdict=verdict), self.assertRaises(SecureReleaseDenied):
                self.inspect(self.signed(dict(self.claim,review_verdict=verdict)))

    def test_duplicate_keys_or_same_named_principals_denied(self):
        duplicate=dict(self.pinned, witness=self.pinned["owner"])
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(pins=duplicate)
        same=dict(self.claim,reviewer_id=self.claim["owner_id"])
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(self.signed(same))

    def test_client_supplied_privilege_flags_and_wrong_scope_denied(self):
        extra=dict(self.claim,production_release_authorized=True)
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(self.signed(extra))
        scope=dict(self.claim,scope="AUTO_EXECUTE_QWEN_AND_WRITE_FILES")
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(self.signed(scope))
        bad_service=dict(self.claim,service_name="NeurofactoryCoreAdmissionCI")
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(self.signed(bad_service))

    def test_signature_from_wrong_domain_denied(self):
        packet=self.signed()
        packet["witness"]["signature_base64"]=base64.b64encode(
            self.private["witness"].sign(_DOMAIN["reviewer"]+_canonical(self.claim))
        ).decode()
        with self.assertRaises(SecureReleaseDenied):
            self.inspect(packet)

if __name__=="__main__":
    unittest.main()
