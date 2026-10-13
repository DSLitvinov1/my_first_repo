"""Coordinator release gate: negative REVIEW always blocks exact and changed HANDOFF.

Mocks the GitHub read-only API; no model calls, source execution or uploads.
"""
import base64
import copy
import hashlib
import json
import unittest

from review_release_gate import (
    API, HANDOFF_BRANCH, HANDOFF_FILE, REVIEW_BRANCH, REVIEW_FILE,
    KNOWN_REJECTED_SHA, KNOWN_REJECTED_SOURCE_SHA256,
    ReleaseEvidenceError, analyze, audit
)

REVIEW_SHA = "6b71680d3ce7e6f83565fed3e915b8ffc793ae6b"
MODULE = b"# reviewed example source in offline security regression\n"

def report():
    return {
        "schema":1,"project":"НЕЙРОЗАВОД","issue":3,"role":"REVIEW",
        "decision":"REJECT","allow_merging":False,"allow_publication":False,
        "allow_core_handoff_integration":False,
        "reviewed":{
            "source_branch":HANDOFF_BRANCH,
            "reviewed_file":HANDOFF_FILE,
            "exact_commit":KNOWN_REJECTED_SHA,
            "source_sha256":KNOWN_REJECTED_SOURCE_SHA256
        },
        "blocking_findings":[
            {"id":"REVIEW-HANDOFF-001","status":"CONFIRMED_REPRODUCED"},
            {"id":"REVIEW-HANDOFF-002","status":"CONFIRMED_API_CAN_BE_FED_FORGED_REVIEW"}
        ]
    }


class ReleaseGateTests(unittest.TestCase):
    def test_negative_owner_verdict_blocks_exact_source(self):
        result=analyze(report(),KNOWN_REJECTED_SHA,REVIEW_SHA,
                       KNOWN_REJECTED_SOURCE_SHA256)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["status"],"REJECTED_CURRENT_SOURCE")
        self.assertIn("directory_swap_race_confirmed",result["reasons"])
        self.assertIn("qwen_provenance_not_authenticated",result["reasons"])

    def test_changed_handoff_still_blocked_and_needs_new_review(self):
        result=analyze(report(),"a"*40,REVIEW_SHA,"d"*64)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["status"],"HANDOFF_REVIEW_STALE")
        self.assertIn("new_independent_review_required",result["reasons"])

    def test_changed_review_document_does_not_authorize(self):
        new=report()
        new["reviewed"]["exact_commit"]="b"*40
        result=analyze(new,KNOWN_REJECTED_SHA,REVIEW_SHA,KNOWN_REJECTED_SOURCE_SHA256)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["status"],"REVIEW_RECORD_CHANGED")

    def test_forged_positive_verdict_not_accepted(self):
        fake=report()
        fake["decision"]="APPROVE"
        with self.assertRaises(ReleaseEvidenceError):
            analyze(fake,KNOWN_REJECTED_SHA,REVIEW_SHA,KNOWN_REJECTED_SOURCE_SHA256)

    def test_release_flag_true_despite_reject_denied(self):
        fake=report()
        fake["allow_publication"]=True
        with self.assertRaises(ReleaseEvidenceError):
            analyze(fake,KNOWN_REJECTED_SHA,REVIEW_SHA,KNOWN_REJECTED_SOURCE_SHA256)

    def test_deleted_adverse_security_finding_refused(self):
        fake=report()
        fake["blocking_findings"]=fake["blocking_findings"][:1]
        with self.assertRaises(ReleaseEvidenceError):
            analyze(fake,KNOWN_REJECTED_SHA,REVIEW_SHA,KNOWN_REJECTED_SOURCE_SHA256)

    def test_wrong_project_or_role_rejected(self):
        for field,value in (("project","other"),("issue",2),("role","HANDOFF")):
            fake=report()
            fake[field]=value
            with self.subTest(field=field):
                with self.assertRaises(ReleaseEvidenceError):
                    analyze(fake,KNOWN_REJECTED_SHA,REVIEW_SHA,KNOWN_REJECTED_SOURCE_SHA256)

    def test_unprotected_even_if_caller_claims_true_not_release(self):
        result=analyze(report(),KNOWN_REJECTED_SHA,REVIEW_SHA,KNOWN_REJECTED_SOURCE_SHA256,
                       protected=True)
        self.assertTrue(result["blocked"])
        self.assertNotIn("production_branch_protection_unconfirmed",result["reasons"])

    def test_live_api_reads_immutable_exact_commit_not_moving_branch(self):
        calls=[]
        source=MODULE
        body=json.dumps(report()).encode("utf-8")
        def fake_get(endpoint):
            calls.append(endpoint)
            if endpoint.endswith("/branches/"+HANDOFF_BRANCH):
                return {"commit":{"sha":KNOWN_REJECTED_SHA}}
            if endpoint.endswith("/branches/"+REVIEW_BRANCH):
                return {"commit":{"sha":REVIEW_SHA}}
            if endpoint==API+"contents/"+HANDOFF_FILE+"?ref="+KNOWN_REJECTED_SHA:
                return {"path":HANDOFF_FILE,"type":"file","encoding":"base64",
                        "content":base64.b64encode(source).decode()}
            if endpoint==API+"contents/"+REVIEW_FILE+"?ref="+REVIEW_SHA:
                return {"path":REVIEW_FILE,"type":"file","encoding":"base64",
                        "content":base64.b64encode(body).decode()}
            raise AssertionError("Unexpected API: "+endpoint)
        result=audit(fake_get)
        self.assertTrue(result["release"]["blocked"])
        self.assertEqual(result["release"]["status"],"HANDOFF_REVIEW_STALE")
        self.assertEqual(len(calls),4)
        self.assertTrue(all("neurofactory" in c for c in calls))

    def test_wrong_content_path_refused(self):
        def fake_get(endpoint):
            if endpoint.endswith("/branches/"+HANDOFF_BRANCH):
                return {"commit":{"sha":KNOWN_REJECTED_SHA}}
            if endpoint.endswith("/branches/"+REVIEW_BRANCH):
                return {"commit":{"sha":REVIEW_SHA}}
            return {"path":"bridge/unrelated/file.py","type":"file","encoding":"base64",
                    "content":base64.b64encode(MODULE).decode()}
        with self.assertRaises(ReleaseEvidenceError):
            audit(fake_get)

    def test_untrusted_missing_review_record_refused(self):
        def fake_get(endpoint):
            if endpoint.endswith("/branches/"+HANDOFF_BRANCH):
                return {"commit":{"sha":KNOWN_REJECTED_SHA}}
            if endpoint.endswith("/branches/"+REVIEW_BRANCH):
                return {"commit":{"sha":REVIEW_SHA}}
            if "/contents/"+HANDOFF_FILE in endpoint:
                return {"path":HANDOFF_FILE,"type":"file","encoding":"base64",
                        "content":base64.b64encode(MODULE).decode()}
            return {"path":REVIEW_FILE,"type":"file","encoding":"base64","content":"badjson!"}
        with self.assertRaises(ReleaseEvidenceError):
            audit(fake_get)

    def test_no_claim_that_qwen_tag_authenticates_model(self):
        result=analyze(report(),KNOWN_REJECTED_SHA,REVIEW_SHA,
                       KNOWN_REJECTED_SOURCE_SHA256)
        self.assertEqual(result["github_model_attestation"],"not_established")
        self.assertTrue(result["independent_review_report_is_not_cryptographic_signature"])

if __name__=="__main__":
    unittest.main(verbosity=2)
