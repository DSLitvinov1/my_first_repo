"""Targeted offline checks of coordinator data contract; never invoke model/bridge."""
import copy
import unittest

from mvp_task_exchange import (
    ExchangeError, start, authorize, prepare_request,
    record_provider_result, attest_source, checkpoint, restore, project
)

A = "a"*40
B = "b"*40
C = "c"*40
H = "a"*64
Q = "b"*64

def proposal():
    return {
        "task_id": "NF-DEV-05-Q001", "project_id": "nf-sandbox",
        "target": "bridge/neurofactory/development/core_owned/sample.py",
        "objective": "Create one deterministic and harmless sandbox example file for review.",
        "source_sha": A, "source_sha256": H,
        "model": "qwen3:4b", "reserved_units": 2500
    }

def approval():
    return {"task_id": "NF-DEV-05-Q001", "source_sha": A,
            "owner": "CORE", "approval_commit": B,
            "scope": proposal()["target"]}

def response(mode="local"):
    return {"task_id": "NF-DEV-05-Q001", "source_sha": A, "model": "qwen3:4b",
            "text": "Verified file content candidate", "local_only": True,
            "published": False, "mode": mode}

def source_proof():
    return {"task_id": "NF-DEV-05-Q001", "source_before": A,
            "source_after": B, "file_sha256": Q, "review_commit": C}

def authorized_state():
    # Fake verifier permitted ONLY in local tests, never valid production provenance.
    return authorize(start(proposal()), approval(), trusted_approval_check=lambda x,p: True)

def request_state():
    return prepare_request(authorized_state())

def returned_state(mode="local"):
    return record_provider_result(request_state(), response(mode))

class ExchangeTests(unittest.TestCase):
    def test_candidate_starts_blocked_with_zero_paid_budget(self):
        a = start(proposal())
        self.assertEqual(a["status"], "PENDING_APPROVAL")
        self.assertEqual(a["cost_limit_usd"], 0)
        self.assertFalse(a["live_execution_allowed"])
        self.assertFalse(a["publication_allowed"])
        self.assertFalse(a["retry_allowed"])
        self.assertEqual(a["handoff"], "PAUSED_BY_USER")

    def test_id_target_and_traversal_rejected(self):
        for key,value in (("task_id","new-job"),("target","/etc/passwd"),
                          ("target","bridge/neurofactory/development/core_owned/../x.py"),
                          ("source_sha","main")):
            p = proposal()
            p[key]=value
            with self.subTest(key=key,value=value), self.assertRaises(ExchangeError):
                start(p)

    def test_no_untrusted_approval(self):
        with self.assertRaises(ExchangeError):
            authorize(start(proposal()), approval())
        with self.assertRaises(ExchangeError):
            authorize(start(proposal()), approval(), trusted_approval_check=lambda x,p: "APPROVE")
        with self.assertRaises(ExchangeError):
            authorize(start(proposal()), approval(), trusted_approval_check=lambda x,p: False)

    def test_approval_source_and_owner_must_match(self):
        for key,value in (("source_sha",B),("scope","something-else"),
                          ("owner","REVIEW"),("approval_commit","main")):
            r=approval()
            r[key]=value
            with self.subTest(key=key),self.assertRaises(ExchangeError):
                authorize(start(proposal()),r,trusted_approval_check=lambda x,p:True)

    def test_approval_input_not_mutated(self):
        a=start(proposal())
        before=copy.deepcopy(a)
        authorize(a,approval(),trusted_approval_check=lambda x,p:True)
        self.assertEqual(a,before)

    def test_no_request_without_external_owner(self):
        with self.assertRaises(ExchangeError):
            prepare_request(start(proposal()))

    def test_pure_request_never_authorizes_transport(self):
        a=request_state()
        self.assertEqual(a["status"],"READY_FOR_CORE")
        self.assertEqual(a["request"]["task_id"],"NF-DEV-05-Q001")
        self.assertTrue(a["request"]["local_only"])
        self.assertFalse(a["live_execution_allowed"])
        self.assertFalse(a["publication_allowed"])

    def test_request_or_approval_duplicate_rejected(self):
        with self.assertRaises(ExchangeError):
            prepare_request(request_state())
        with self.assertRaises(ExchangeError):
            authorize(authorized_state(),approval(),trusted_approval_check=lambda x,p:True)

    def test_provider_requires_task_and_source_binding(self):
        for key,value in (("task_id","NF-DEV-05-Q002"),("source_sha", B),
                          ("model","gpt-api"),("local_only",False),
                          ("published",True),("mode","cloud")):
            res=response()
            res[key]=value
            with self.subTest(key=key),self.assertRaises(ExchangeError):
                record_provider_result(request_state(),res)

    def test_provider_reply_metadata_only_and_untrusted(self):
        state=returned_state()
        self.assertEqual(state["status"],"RESPONSE_UNVERIFIED")
        self.assertNotIn("text",state["result"])
        self.assertFalse(state["result"]["verified"])
        self.assertNotIn("Verified file content candidate",str(state))

    def test_provider_return_once_only(self):
        with self.assertRaises(ExchangeError):
            record_provider_result(returned_state(),response())

    def test_mock_result_cannot_get_git_attestation(self):
        with self.assertRaises(ExchangeError):
            attest_source(returned_state("mock"),source_proof(),
                          trusted_source_check=lambda p,s:True)

    def test_result_cannot_self_authorize_git(self):
        with self.assertRaises(ExchangeError):
            attest_source(returned_state(),source_proof())
        with self.assertRaises(ExchangeError):
            attest_source(returned_state(),source_proof(),
                          trusted_source_check=lambda p,s:{"verdict":"APPROVE"})

    def test_source_version_and_provenance_match(self):
        proof=source_proof()
        proof["source_before"]=B
        with self.assertRaises(ExchangeError):
            attest_source(returned_state(),proof,
                          trusted_source_check=lambda p,s:True)

    def test_attested_state_still_cannot_publish(self):
        a=attest_source(returned_state(),source_proof(),
                        trusted_source_check=lambda p,s:True)
        self.assertEqual(a["status"],"SOURCE_VERIFIED")
        visible=project(a)
        self.assertFalse(visible["external_execution_allowed"])
        self.assertFalse(visible["publication_allowed"])
        self.assertFalse(visible["automatic_retry_allowed"])
        self.assertEqual(visible["handoff"],"PAUSED_BY_USER")

    def test_checksum_rejects_plain_mutation(self):
        a=checkpoint(returned_state())
        a["body"]["result"]["model"]="other"
        with self.assertRaises(ExchangeError):
            restore(a,trusted_checkpoint_check=lambda record:True)

    def test_forged_checksum_alone_not_trusted(self):
        a=checkpoint(returned_state())
        with self.assertRaises(ExchangeError):
            restore(a)
        with self.assertRaises(ExchangeError):
            restore(a,trusted_checkpoint_check=lambda record:"REVIEW_OK")

    def test_checkpoint_roundtrip_only_with_host_attestation(self):
        a=returned_state()
        b=restore(checkpoint(a),trusted_checkpoint_check=lambda record:True)
        self.assertEqual(a,b)
        self.assertIsNot(a,b)

    def test_event_chain_rejects_stage_reorder(self):
        a=checkpoint(request_state())
        a["body"]["events"][1]["kind"]="REQUEST_PREPARED"
        # Recalculate outer digest would still fail the inner event chain.
        with self.assertRaises(ExchangeError):
            restore(a,trusted_checkpoint_check=lambda record:True)

    def test_projection_never_claims_authenticated_origin(self):
        a=project(returned_state())
        self.assertFalse(a["source_verified_by_host"])
        self.assertEqual(a["review_provenance"],"NOT_ATTESTED_BY_PROJECTION")
        self.assertNotIn("text",a)

if __name__=="__main__":
    unittest.main()
