"""Coordinator-only regression: fail closed while final Stage5 release lacks proofs.

This test never invokes models, publisher, other lane code, or Windows runners.
"""
import copy
import json
from pathlib import Path
import unittest

MANIFEST = Path(__file__).with_name("stage5-final-acceptance-gate-20261014.json")
REQUIRED_BLOCKERS = {
    "separate_review_owner_approves_exact_handoff",
    "core_owned_runtime_integration",
    "new_multi_task_production_queue_execution",
    "actual_approved_single_github_publication",
    "replay_same_task_no_second_publication",
    "cross_runner_live_recovery_of_new_published_task",
}

def assess(doc):
    if not isinstance(doc, dict) or doc.get("owner") != "COORDINATOR":
        raise ValueError("Wrong report owner")
    if doc.get("project") != "НЕЙРОЗАВОД" or doc.get("issue") != 3:
        raise ValueError("Wrong project/issue")
    requirements = doc.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("No release requirements")
    ids = [r.get("id") for r in requirements]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicated requirement")
    blockers = [r["id"] for r in requirements if r.get("state") != "verified" and
                not str(r.get("state", "")).startswith("verified_")]
    if doc.get("release_authorization") is True and blockers:
        raise ValueError("Release granted before all mandatory evidence")
    if doc.get("release_decision") == "ACCEPTED" and (blockers or
            doc.get("release_authorization") is not True):
        raise ValueError("False acceptance certificate")
    if doc.get("release_authorization") is False and doc.get("release_decision") != "NOT_ACCEPTED":
        raise ValueError("Inconsistent failed release")
    safety = doc.get("safety", {})
    if (safety.get("chatgpt_delivery_paused") is not True or
            safety.get("external_model_api_paid") is not False or
            safety.get("branch_merges_performed") is not False):
        raise ValueError("Unsafe coordinator safety claim")
    prs = doc.get("blocking_pull_requests", [])
    if not isinstance(prs, list) or any(x.get("merge_allowed") is not False for x in prs):
        raise ValueError("Pending mixed ownership PR incorrectly released")
    return {"status": "NOT_ACCEPTED" if blockers else "REQUIRES_INDEPENDENT_LIVE_RECHECK",
            "blocking_count": len(blockers), "blocked_ids": blockers}


class RealScopeReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_current_manifest_refuses_release(self):
        result = assess(self.doc)
        self.assertEqual(result["status"], "NOT_ACCEPTED")
        self.assertTrue(REQUIRED_BLOCKERS.issubset(result["blocked_ids"]))

    def test_qwen_approval_does_not_impersonate_review_owner(self):
        proof = next(p for p in self.doc["verified_evidence"] if p["kind"] == "live_two_models")
        self.assertEqual(proof["model_verdict"], "APPROVE")
        self.assertEqual(proof["separate_review_owner"], "PENDING")
        self.assertEqual(proof["publication_count"], 0)
        self.assertFalse(self.doc["release_authorization"])

    def test_original_artifact_hashes_are_pinned(self):
        proof = next(p for p in self.doc["verified_evidence"] if p["kind"] == "live_two_models")
        self.assertEqual(proof["candidate_sha256"],
                         "3f8bcaa10c21eadc6d90250434f88b10f5d1598f2d01476f75931f6546fc5c32")
        self.assertEqual(proof["artifacts"], [11850873678])

    def test_cannot_claim_acceptance_by_flipping_flag(self):
        bad = copy.deepcopy(self.doc)
        bad["release_authorization"] = True
        bad["release_decision"] = "ACCEPTED"
        with self.assertRaises(ValueError):
            assess(bad)

    def test_cannot_hide_blockers_with_duplicate_entry(self):
        bad = copy.deepcopy(self.doc)
        bad["requirements"].append(copy.deepcopy(bad["requirements"][0]))
        with self.assertRaises(ValueError):
            assess(bad)

    def test_missing_issue_or_wrong_owner_denied(self):
        for changed in ({"issue": 5}, {"owner": "HANDOFF"}, {"project": "other"}):
            bad = copy.deepcopy(self.doc)
            bad.update(changed)
            with self.assertRaises(ValueError):
                assess(bad)

    def test_mixed_pr_stays_unmerged(self):
        self.assertEqual(self.doc["blocking_pull_requests"][0]["number"], 2)
        self.assertFalse(self.doc["blocking_pull_requests"][0]["merged"])
        self.assertFalse(self.doc["blocking_pull_requests"][0]["merge_allowed"])

    def test_no_paid_model_or_chat_delivery_enabled(self):
        for changed in ({"chatgpt_delivery_paused": False},
                        {"external_model_api_paid": True},
                        {"branch_merges_performed": True}):
            bad = copy.deepcopy(self.doc)
            bad["safety"].update(changed)
            with self.assertRaises(ValueError):
                assess(bad)

    def test_candidate_semantic_checks_not_production_execution(self):
        proof = next(p for p in self.doc["verified_evidence"] if
                     p["kind"] == "candidate_isolated_semantic_test")
        self.assertEqual(proof["passed"], 5)
        self.assertIn("not production", proof["tests_executed_in"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
