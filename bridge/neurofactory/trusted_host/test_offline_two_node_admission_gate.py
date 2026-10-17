"""Synthetic two-node credentials: 10 focused negative scope controls.

No device identified here is real. No user computer or live keys touched.
"""
import base64
import copy
import hashlib
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from offline_two_node_admission_gate import (
    TwoNodeAdmissionDenied,check_two_node_bundle,_canonical)

def b64(x):
    return base64.b64encode(x).decode("ascii")

def public(k):
    return k.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def sha(x):
    return hashlib.sha256(x).hexdigest()

class SignedTwoNodeReadinessTests(unittest.TestCase):
    def setUp(self):
        self.now=1800000000
        self.operator=Ed25519PrivateKey.generate()
        self.owner=Ed25519PrivateKey.generate()
        self.payload={
            "schema":"nf.two_physical_operator_attestation.test.v1",
            "repo_id":"723328237",
            "operator_id":"fixture-independent-operator",
            "observed_unix":self.now-20,
            "expires_unix":self.now+300,
            "test_scope_sha256":sha(b"only disposable synthetic host tests"),
            "host":{
                "role":"HOST","node_id":"nf-node-host-example-01",
                "hardware_fingerprint_sha256":sha(b"fixture-host-hardware"),
                "operator_attestation_sha256":sha(b"fixture-host-operator-observation"),
                "tls_certificate_sha256":sha(b"fixture-host-cert"),
                "source_sha40":"a"*40},
            "witness":{
                "role":"WITNESS","node_id":"nf-node-witness-example-02",
                "hardware_fingerprint_sha256":sha(b"fixture-witness-hardware"),
                "operator_attestation_sha256":sha(b"fixture-witness-operator-observation"),
                "tls_certificate_sha256":sha(b"fixture-witness-cert"),
                "source_sha40":"b"*40},
        }
        self.approval={
            "schema":"nf.two_physical_owner_consent.test.v1",
            "owner_id":"151650108","repo_id":"723328237",
            "host_node_id":self.payload["host"]["node_id"],
            "witness_node_id":self.payload["witness"]["node_id"],
            "operator_payload_sha256":sha(_canonical(self.payload)),
            "approved_test_scope_sha256":self.payload["test_scope_sha256"],
            "approve_reboot_host":True,
            "approve_restore_host_db":True,
            "approve_reboot_witness":False,
            "expires_unix":self.now+240,
            "nonce_sha256":sha(b"one-time synthetic nonce"),
        }
    def bundle(self,payload=None,approval=None,operator_key=None,owner_key=None):
        payload=copy.deepcopy(self.payload if payload is None else payload)
        approval=copy.deepcopy(self.approval if approval is None else approval)
        ok=operator_key or self.operator
        uk=owner_key or self.owner
        return {
            "operator_payload":payload,
            "operator_signature_base64":b64(ok.sign(
                b"NF-TWO-NODE-OPERATOR-TEST\0"+_canonical(payload))),
            "owner_approval":approval,
            "owner_signature_base64":b64(uk.sign(
                b"NF-TWO-NODE-OWNER-TEST\0"+_canonical(approval)))}
    def verify(self,bundle=None,**kwargs):
        request={"operator_public_b64":b64(public(self.operator)),
                 "owner_public_b64":b64(public(self.owner)),
                 "expected_operator_public_sha256":sha(public(self.operator)),
                 "expected_owner_public_sha256":sha(public(self.owner)),
                 "now_unix":self.now,"consumed_nonce_sha256s":()}
        request.update(kwargs)
        return check_two_node_bundle(self.bundle() if bundle is None else bundle,**request)
    def test_dual_signature_fixture_does_not_grant_real_reboot_or_deployment(self):
        status=self.verify()
        self.assertEqual(status["status"],"SIGNED_TWO_NODE_MANIFEST_FORMAT_VALID_TEST_ONLY")
        self.assertFalse(status["physical_distinctness_independently_observed"])
        self.assertFalse(status["installation_permitted"])
        self.assertFalse(status["reboot_permitted"])
        self.assertFalse(status["production_authority"])
    def test_same_hardware_fingerprint_rejected_even_if_separately_named(self):
        x=copy.deepcopy(self.payload)
        x["witness"]["hardware_fingerprint_sha256"]=x["host"]["hardware_fingerprint_sha256"]
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(payload=x))
    def test_same_device_identity_rejected(self):
        x=copy.deepcopy(self.payload)
        x["witness"]["node_id"]=x["host"]["node_id"]
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(payload=x))
    def test_same_tls_certificate_rejected(self):
        x=copy.deepcopy(self.payload)
        x["witness"]["tls_certificate_sha256"]=x["host"]["tls_certificate_sha256"]
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(payload=x))
    def test_forged_operator_signature_rejected(self):
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(operator_key=Ed25519PrivateKey.generate()))
    def test_forged_owner_signature_rejected(self):
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(owner_key=Ed25519PrivateKey.generate()))
    def test_permission_to_reboot_witness_rejected(self):
        x=dict(self.approval,approve_reboot_witness=True)
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(approval=x))
    def test_changed_project_scope_rejected(self):
        x=dict(self.approval,approved_test_scope_sha256=sha(b"foreign project"))
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(self.bundle(approval=x))
    def test_expired_both_signers_not_usable(self):
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(now_unix=self.now+360)
    def test_consumed_owner_nonce_cannot_authorize_again(self):
        with self.assertRaises(TwoNodeAdmissionDenied):
            self.verify(consumed_nonce_sha256s=(self.approval["nonce_sha256"],))

if __name__=="__main__":
    unittest.main()
