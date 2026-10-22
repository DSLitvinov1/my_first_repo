"""No remote key creation: synthetic ephemeral Ed25519 keys only inside CI unit tests."""
import base64
import json
from copy import deepcopy
from hashlib import sha256
import secrets
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from independent_witness_receipt import (
    _DOMAIN, _canonical, IndependentWitnessDenied,
    verify_external_witness_receipt,parse_bounded_witness_reply,
)

def digest(s):
    return sha256(s.encode("ascii")).hexdigest()

class IndependentExternalWitnessReceiptTests(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time())
        self.key=Ed25519PrivateKey.generate()
        self.claim={
            "schema":"nf.onepc.highwater.claim.v1",
            "source_sha40":"cc9cf22ee246ff376b84490c0f118612ac82ac51",
            "package_sha256":digest("pinned-install"),
            "machine_identity_sha256":digest("offline-machine-candidate"),
            "review_evidence_sha256":digest("synthetic-review-does-not-grant-approval"),
            "operation_sha256":digest("one-specific-operation"),
            "external_epoch":9,
            "nonce":secrets.token_hex(32),
        }
        self.evidence={
            "schema":"nf.onepc.external_witness.highwater.v1",
            "claim_sha256":digest(_canonical(self.claim).decode("ascii")),
            "source_sha40":self.claim["source_sha40"],
            "machine_identity_sha256":self.claim["machine_identity_sha256"],
            "witness_id":"separate-witness-test",
            "highest_committed_epoch":9,
            "previous_accepted_epoch":8,
            "recorded_unix":self.now-5,
            "expires_unix":self.now+50,
            "decision":"RECORDED_EXTERNALLY_NO_AUTO_RETRY",
            "separate_device_claimed":True,
        }
    def packet(self, evidence=None, key=None):
        evidence=self.evidence if evidence is None else evidence
        key=self.key if key is None else key
        return {"evidence":deepcopy(evidence),
                "signature_base64":base64.b64encode(
                    key.sign(_DOMAIN+_canonical(evidence))).decode("ascii")}
    def verify(self, packet=None, **kwargs):
        params=dict(claim=self.claim,receipt=self.packet() if packet is None else packet,
                    pinned_witness_public=self.key.public_key(),
                    independently_pinned_witness_id="separate-witness-test",
                    independently_observed_minimum_epoch=9,now_unix=self.now)
        params.update(kwargs)
        return verify_external_witness_receipt(**params)
    def denied(self,**evidence_changes):
        with self.assertRaises(IndependentWitnessDenied):
            self.verify(self.packet({**self.evidence,**evidence_changes}))
    def test_signed_witness_evidence_is_not_release_authorization(self):
        r=self.verify()
        self.assertTrue(r["signature_verified"])
        self.assertFalse(r["physical_machine_release_authorized"])
        self.assertFalse(r["production_install_authorized"])
        self.assertFalse(r["device_separation_independently_attested"])
        self.assertFalse(r["receipt_replay_resistant_without_remote_query"])
    def test_stale_highwater_denied(self):
        self.denied(highest_committed_epoch=8)
    def test_same_epoch_as_prior_denied(self):
        self.denied(previous_accepted_epoch=9)
    def test_rollback_of_independent_expected_epoch_denied(self):
        with self.assertRaises(IndependentWitnessDenied):
            self.verify(independently_observed_minimum_epoch=10)
    def test_signature_from_wrong_witness_denied(self):
        with self.assertRaises(IndependentWitnessDenied):
            self.verify(self.packet(key=Ed25519PrivateKey.generate()))
    def test_wrong_machine_or_source_denied(self):
        self.denied(machine_identity_sha256=digest("another-pc"))
        self.denied(source_sha40="a"*40)
    def test_cross_package_operation_or_nonce_denied(self):
        for field in ("package_sha256","operation_sha256","nonce"):
            with self.subTest(field=field), self.assertRaises(IndependentWitnessDenied):
                self.verify(claim={**self.claim,field:digest("different")})
    def test_wrong_witness_id_denied(self):
        self.denied(witness_id="other-independent-witness")
        with self.assertRaises(IndependentWitnessDenied):
            self.verify(independently_pinned_witness_id="another-remote-server")
    def test_expired_or_overlong_evidence_denied(self):
        self.denied(expires_unix=self.now)
        self.denied(expires_unix=self.now+3600)
    def test_witness_claims_same_machine_denied(self):
        self.denied(separate_device_claimed=False)
    def test_unknown_or_permissive_receipt_state_denied(self):
        self.denied(decision="AUTHORIZE_MODEL_FILE_EFFECTS")
    def test_integer_confusion_denied(self):
        for field in ("highest_committed_epoch","previous_accepted_epoch",
                      "recorded_unix","expires_unix"):
            with self.subTest(field=field):
                self.denied(**{field:True})
    def test_duplicate_or_extra_field_denied(self):
        self.denied(privileged_override=True)
    def test_wire_parser_rejects_duplicate_evidence_and_oversized(self):
        packet=self.packet()
        raw=json.dumps(packet,separators=(",",":")).encode("ascii")
        parsed=parse_bounded_witness_reply(raw)
        self.assertTrue(self.verify(parsed)["signature_verified"])
        doubled=b'{"evidence":{},"evidence":{},"signature_base64":"'+b"A"*88+b'"}'
        with self.assertRaises(IndependentWitnessDenied):
            parse_bounded_witness_reply(doubled)
        with self.assertRaises(IndependentWitnessDenied):
            parse_bounded_witness_reply(b"x"*3501)
        with self.assertRaises(IndependentWitnessDenied):
            parse_bounded_witness_reply(b'{"evidence":NaN,"signature_base64":'+b'"'+b"A"*88+b'"}')

    def test_signature_envelope_extra_role_denied(self):
        packet=self.packet()
        packet["allow_install"]=True
        with self.assertRaises(IndependentWitnessDenied):
            self.verify(packet)

if __name__ == "__main__":
    unittest.main()
