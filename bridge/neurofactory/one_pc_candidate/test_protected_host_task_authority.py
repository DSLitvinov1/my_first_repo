"""Real Ed25519 signature verification with disposable 3 independent signers only.

No private keys imported from users/hosts, no OS permission, no task effects.
"""
import base64
from copy import deepcopy
from hashlib import sha256
import secrets
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protected_host_task_authority import (
    _DOMAIN,_canon,ProtectedHostTaskDenied,verify_one_host_operation,
)
from independent_witness_receipt import _DOMAIN as WITNESS_DOMAIN

def h(value):
    return sha256(value.encode("ascii")).hexdigest()

class SignedTaskBoundToActualExternalClaim(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time())
        self.owner=Ed25519PrivateKey.generate()
        self.reviewer=Ed25519PrivateKey.generate()
        self.witness=Ed25519PrivateKey.generate()
        self.claim={
            "schema":"nf.host.one_effect_scope.v1",
            "repository":"DSLitvinov1/my_first_repo",
            "task_id":"nf-one-task-1",
            "project_id":"owner-project-1",
            "source_sha40":"f"*40,
            "package_sha256":h("real installed candidate - synthetic"),
            "machine_identity_sha256":h("Windows measured machine - synthetic"),
            "review_evidence_sha256":h("human signed independent review - synthetic"),
            "operation_sha256":h("fixed one operation"),
            "payload_sha256":h("fixed file bytes"),
            "worker_sid":"S-1-5-21-12345-67890-12345-1101",
            "service_sid":"S-1-5-80-1-2-3-4-5",
            "operation_type":"OWNER_REVIEWED_FIXED_SAFE_FILE_V1",
            "external_epoch":5,
            "nonce":secrets.token_hex(32),
            "issued_unix":self.now-4,
            "expires_unix":self.now+45,
        }
        self.expected={k:self.claim[k] for k in (
            "source_sha40","package_sha256","machine_identity_sha256",
            "review_evidence_sha256","operation_sha256","payload_sha256",
            "worker_sid","service_sid","task_id","project_id"
        )}
        self.expected["minimum_external_epoch"]=5
        self.remote={
            "schema":"nf.onepc.highwater.claim.v1",
            "source_sha40":self.claim["source_sha40"],
            "package_sha256":self.claim["package_sha256"],
            "machine_identity_sha256":self.claim["machine_identity_sha256"],
            "review_evidence_sha256":self.claim["review_evidence_sha256"],
            "operation_sha256":self.claim["operation_sha256"],
            "external_epoch":5,
            "nonce":self.claim["nonce"],
        }
        self.evidence={
            "schema":"nf.onepc.external_witness.highwater.v1",
            "claim_sha256":sha256(_canon(self.remote)).hexdigest(),
            "source_sha40":self.claim["source_sha40"],
            "machine_identity_sha256":self.claim["machine_identity_sha256"],
            "witness_id":"external-independent-review-test",
            "highest_committed_epoch":5,
            "previous_accepted_epoch":4,
            "recorded_unix":self.now-3,
            "expires_unix":self.now+40,
            "decision":"RECORDED_EXTERNALLY_NO_AUTO_RETRY",
            "separate_device_claimed":True,
        }
    def role(self,who,claim=None,key=None):
        c=self.claim if claim is None else claim
        s={"owner":self.owner,"reviewer":self.reviewer}[who] if key is None else key
        return {
            "role":who,"claim":deepcopy(c),
            "signature_base64":base64.b64encode(
                s.sign(_DOMAIN[who]+_canon(c))).decode("ascii")
        }
    def ack(self,evidence=None,signer=None):
        e=self.evidence if evidence is None else evidence
        key=self.witness if signer is None else signer
        return {"evidence":deepcopy(e),
                "signature_base64":base64.b64encode(
                    key.sign(WITNESS_DOMAIN+_canon(e))).decode("ascii")}
    def invoke(self,**changes):
        args={
            "claim":self.claim,
            "owner_signature":self.role("owner"),
            "reviewer_signature":self.role("reviewer"),
            "witness_claim":self.remote,
            "witness_receipt":self.ack(),
            "independently_pinned_owner_key":self.owner.public_key(),
            "independently_pinned_reviewer_key":self.reviewer.public_key(),
            "independently_pinned_witness_key":self.witness.public_key(),
            "independently_pinned_witness_id":"external-independent-review-test",
            "operator_expected":self.expected,
            "independently_observed_remote_epoch":5,
            "now_unix":self.now,
        }
        args.update(changes)
        return verify_one_host_operation(**args)
    def denied(self,**changes):
        with self.assertRaises(ProtectedHostTaskDenied):
            self.invoke(**changes)
    def test_all_real_signatures_match_never_grants_execution(self):
        v=self.invoke()
        self.assertTrue(v["owner_valid_signature"])
        self.assertTrue(v["independent_reviewer_valid_signature"])
        self.assertTrue(v["separate_remote_witness_signature_valid"])
        self.assertFalse(v["production_task_effect_allowed"])
        self.assertFalse(v["actual_core_queue_lease_verified"])
        self.assertFalse(v["real_windows_worker_sid_checked_by_os"])
    def test_forged_owner_not_authenticated(self):
        self.denied(owner_signature=self.role(
            "owner",key=Ed25519PrivateKey.generate()))
    def test_forged_reviewer_not_authenticated(self):
        self.denied(reviewer_signature=self.role(
            "reviewer",key=Ed25519PrivateKey.generate()))
    def test_forged_witness_not_authenticated(self):
        self.denied(witness_receipt=self.ack(signer=Ed25519PrivateKey.generate()))
    def test_shared_owner_reviewer_keys_denied(self):
        self.denied(independently_pinned_reviewer_key=self.owner.public_key())
    def test_modified_payload_denied_even_with_correct_signatures_of_old_claim(self):
        self.denied(claim={**self.claim,"payload_sha256":h("unapproved replacement")})
    def test_other_machine_scope_denied(self):
        self.denied(claim={**self.claim,
                           "machine_identity_sha256":h("foreign machine")})
    def test_other_task_or_project_denied(self):
        self.denied(claim={**self.claim,"task_id":"nf-another-task"})
        self.denied(claim={**self.claim,"project_id":"another-project"})
    def test_other_worker_or_service_principal_denied(self):
        self.denied(claim={**self.claim,
                           "worker_sid":"S-1-5-21-12345-67890-12345-1102"})
        self.denied(claim={**self.claim,
                           "service_sid":self.claim["worker_sid"]})
    def test_wrong_remote_operation_or_nonce_denied(self):
        self.denied(witness_claim={**self.remote,
                                   "operation_sha256":h("different action")})
        self.denied(witness_claim={**self.remote,"nonce":secrets.token_hex(32)})
    def test_expired_and_replayed_epoch_denied(self):
        self.denied(now_unix=self.claim["expires_unix"])
        self.denied(independently_observed_remote_epoch=6)
        self.denied(operator_expected={**self.expected,"minimum_external_epoch":6})
    def test_unknown_operation_type_denied(self):
        self.denied(claim={**self.claim,
                           "operation_type":"EXECUTE_ANY_SHELL_COMMAND"})
    def test_unsigned_remote_reply_or_mutated_signed_remote_claim_denied(self):
        self.denied(witness_receipt=self.ack({
            **self.evidence,"highest_committed_epoch":4}))
        self.denied(witness_receipt=self.ack({
            **self.evidence,"decision":"AUTHORIZE_SHELL"}))
    def test_non_monotonic_machine_flags_and_boolean_epochs_denied(self):
        self.denied(claim={**self.claim,"external_epoch":True})
        self.denied(claim={**self.claim,"expires_unix":self.now+3600})

if __name__=="__main__":
    unittest.main()
