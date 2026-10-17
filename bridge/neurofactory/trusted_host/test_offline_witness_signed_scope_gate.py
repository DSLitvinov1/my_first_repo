"""Non-production issuer+owner witness-side security checks. Fake keys only."""
import base64
import copy
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from signed_effect_permit import _validated_payload
from offline_external_effect_witness import canon
from offline_witness_signed_scope_gate import (
    SignedWitnessScopeDenied,scope_verified_claim)

def sha(data):
    return hashlib.sha256(data).hexdigest()
def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def b64(raw):
    return base64.b64encode(raw).decode()

class WitnessRejectsUnattestedScopes(unittest.TestCase):
    def setUp(self):
        self.now=1800000200
        self.issuer=Ed25519PrivateKey.generate()
        self.owner=Ed25519PrivateKey.generate()
        self.policy={
            "schema":"nf.witness.pinned_scope.test.v1",
            "owner_id":"151650108","github_owner_numeric_id":"151650108","repo_id":"723328237",
            "repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox","worker_id":"worker-sandbox-01",
            "issuer_public_base64":b64(pub(self.issuer)),
            "owner_public_base64":b64(pub(self.owner)),
            "issuer_sha256":sha(pub(self.issuer)),
            "owner_sha256":sha(pub(self.owner)),
        }
        self.body={
            "schema":"neurofactory.trusted_host.signed_effect_permit.v1",
            "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
            "issuer_id":"operator-test","key_id":"test-key",
            "owner_id":"151650108","repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox","task_id":"NF-DEV-05-Q973",
            "worker_id":"worker-sandbox-01","source_sha40":"a"*40,
            "source_file_sha256":"b"*64,"input_task_sha256":"c"*64,
            "policy_sha256":"d"*64,
            "target":"bridge/neurofactory/development/core_owned/new-safe-file.py",
            "proposed_content_sha256":"e"*64,
            "fencing_token_sha256":"f"*64,
            "lease_epoch":7,"issued_unix":1800000190,
            "expires_unix":1800000250,"idempotency_key":"1"*64,
            "operation_id":"signed-effect-one"}
    def bundle(self,body=None,claim_changes=None,grant_changes=None,
               issuer=None,owner=None):
        body=copy.deepcopy(self.body if body is None else body)
        canonical=_validated_payload(body)
        packet={"payload":body,"signature_base64":b64(
            (self.issuer if issuer is None else issuer).sign(canonical))}
        fields=("owner_id","repository","project_id","task_id","worker_id",
                "source_sha40","target","operation_id","lease_epoch")
        statement={k:body[k] for k in fields}
        statement.update({"permit_sha256":sha(canonical),
                          "expires_unix":1800000240})
        if grant_changes:statement.update(grant_changes)
        grant={"statement":statement,"signature_base64":b64(
            (self.owner if owner is None else owner).sign(canon(statement)))}
        claim={"schema":"nf.remote_witness.claim.v1",
               "owner_id":"151650108","repo_id":"723328237",
               "task_id":body["task_id"],"operation_id":body["operation_id"],
               "target":body["target"],"lease_epoch":body["lease_epoch"],
               "permit_sha256":sha(canonical),
               "content_sha256":body["proposed_content_sha256"],
               "nonce":sha(b"unique-network-nonce")}
        if claim_changes:claim.update(claim_changes)
        return {"claim":claim,"signed_packet":packet,
                "signed_owner_grant":grant}
    def check(self,envelope=None,policy=None,now=None):
        return scope_verified_claim(
            self.bundle() if envelope is None else envelope,
            self.policy if policy is None else policy,
            now_unix=self.now if now is None else now)
    def reject(self,**kwargs):
        with self.assertRaises(SignedWitnessScopeDenied):
            self.check(**kwargs)
    def test_both_independent_signatures_match_exact_claim_without_authority(self):
        result=self.check()
        self.assertTrue(result["claim_sha256"])
        self.assertFalse(result["current_central_lease_checked_here"])
        self.assertFalse(result["production_execution_allowed"])
    def test_no_owner_signature_denied(self):
        env=self.bundle();env["signed_owner_grant"]=None
        self.reject(envelope=env)
    def test_fake_issuer_key_denied(self):
        self.reject(envelope=self.bundle(issuer=Ed25519PrivateKey.generate()))
    def test_fake_owner_key_denied(self):
        self.reject(envelope=self.bundle(owner=Ed25519PrivateKey.generate()))
    def test_owner_grant_wrong_commit_denied(self):
        self.reject(envelope=self.bundle(grant_changes={"source_sha40":"f"*40}))
    def test_owner_grant_wrong_worker_denied(self):
        self.reject(envelope=self.bundle(grant_changes={"worker_id":"worker-foreign"}))
    def test_claim_wrong_target_denied(self):
        self.reject(envelope=self.bundle(claim_changes={
            "target":"bridge/neurofactory/development/core_owned/other.py"}))
    def test_claim_wrong_permit_digest_denied(self):
        self.reject(envelope=self.bundle(claim_changes={"permit_sha256":"0"*64}))
    def test_claim_wrong_content_denied(self):
        self.reject(envelope=self.bundle(claim_changes={"content_sha256":"0"*64}))
    def test_claim_other_fencing_epoch_denied(self):
        self.reject(envelope=self.bundle(claim_changes={"lease_epoch":8}))
    def test_expired_issuer_permit_denied(self):
        self.reject(now=1800000251)
    def test_expired_owner_grant_denied(self):
        self.reject(now=1800000241)
    def test_wrong_operator_pinned_public_key_denied(self):
        bad=dict(self.policy,issuer_public_base64=b64(pub(Ed25519PrivateKey.generate())))
        self.reject(policy=bad)
    def test_wrong_pinned_project_denied(self):
        bad=dict(self.policy,project_id="foreign-project")
        self.reject(policy=bad)
    def test_claim_foreign_repository_id_denied(self):
        self.reject(envelope=self.bundle(claim_changes={"repo_id":"11111"}))

if __name__=="__main__":
    unittest.main()
