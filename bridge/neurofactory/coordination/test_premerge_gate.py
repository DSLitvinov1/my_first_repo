"""Coordinator pre-merge safety gate regressions; all network data simulated."""
import copy
import unittest

from premerge_gate import (
    BASE_BRANCH, EXPECTED_OWNER_CHECK, REVIEW_GATE, REPO, MergeGateError,
    evaluate, verify_pr, independent_github_review, required_checks, URL
)
from check_lanes import load_policy

POLICY = load_policy()
SHA = "a" * 40
BRANCH = "neurofactory-core-queue-owned-20261013"
FILES = [{"filename": "bridge/neurofactory/development/stage5_development_queue.py", "status": "modified"}]


def candidate():
    return {
        "number": 10, "state": "open", "draft": False, "mergeable": True,
        "mergeable_state": "clean", "updated_at": "2026-10-14T12:00:00Z",
        "user": {"login": "writer"},
        "base": {"ref": BASE_BRANCH, "repo": {"full_name": REPO}},
        "head": {"ref": BRANCH, "sha": SHA, "repo": {"full_name": REPO}}
    }


def approvals():
    return [{"user": {"login": "independent_reviewer"}, "state": "APPROVED",
             "commit_id": SHA, "submitted_at": "2026-10-14T12:05:00Z"}]


def checks():
    return [
        {"name": EXPECTED_OWNER_CHECK, "head_sha": SHA,
         "status": "completed", "conclusion": "success"},
        {"name": REVIEW_GATE, "head_sha": SHA,
         "status": "completed", "conclusion": "success"}
    ]


class PreMergeGateTests(unittest.TestCase):
    def assert_block(self, pr=None, files=None, reviews=None, runs=None, reason=None):
        value = evaluate(pr if pr is not None else candidate(),
                         files if files is not None else FILES,
                         reviews if reviews is not None else approvals(),
                         runs if runs is not None else checks(), POLICY)
        self.assertFalse(value["integration_consideration_allowed"])
        if reason:
            self.assertIn(reason, value["blocking_reasons"])
        self.assertFalse(value["automerge"])
        return value

    def test_valid_complete_independent_evidence_is_only_considerable(self):
        decision = evaluate(candidate(), FILES, approvals(), checks(), POLICY)
        self.assertTrue(decision["integration_consideration_allowed"])
        self.assertFalse(decision["automerge"])
        self.assertTrue(decision["read_only"])

    def test_draft_never_considered(self):
        p=candidate();p["draft"]=True
        self.assert_block(pr=p,reason="draft_or_not_open")

    def test_renamed_foreign_file_denied_even_if_destination_owned(self):
        files=[{"filename":FILES[0]["filename"],"status":"renamed",
                "previous_filename":"bridge/neurofactory/development/stage5_git_receipts.py"}]
        self.assert_block(files=files,reason="mixed_or_unowned_changes")

    def test_unassigned_other_project_denied(self):
        self.assert_block(files=[{"filename":"other_project/server.py","status":"added"}],
                          reason="mixed_or_unowned_changes")

    def test_mixed_review_core_denied(self):
        self.assert_block(files=FILES+[{"filename":"bridge/neurofactory/development/review_owned/check.py",
                                       "status":"added"}],reason="mixed_or_unowned_changes")

    def test_unapproved_external_fork_denied(self):
        p=candidate();p["head"]["repo"]["full_name"]="attacker/fork"
        self.assert_block(pr=p,reason="wrong_base_or_external_fork")

    def test_wrong_production_base_denied(self):
        p=candidate();p["base"]["ref"]="main"
        self.assert_block(pr=p,reason="wrong_base_or_external_fork")

    def test_unconfirmed_clean_mergeability_denied(self):
        p=candidate();p["mergeable_state"]="unstable"
        self.assert_block(pr=p,reason="mergeability_not_confirmed")

    def test_self_approval_not_independent(self):
        x=approvals();x[0]["user"]["login"]="writer"
        self.assert_block(reviews=x,reason="no_fresh_independent_git_review")

    def test_old_sha_approval_not_independent(self):
        x=approvals();x[0]["commit_id"]="b"*40
        self.assert_block(reviews=x,reason="no_fresh_independent_git_review")

    def test_dismissed_approval_not_independent(self):
        x=approvals()+[{"user":{"login":"independent_reviewer"},"state":"DISMISSED",
                        "commit_id":SHA}]
        self.assert_block(reviews=x,reason="no_fresh_independent_git_review")

    def test_reviewed_sha_mismatch_denied(self):
        c=checks();c[1]["head_sha"]="c"*40
        self.assert_block(runs=c,reason="missing_current_owner_or_qwen3_check")

    def test_unsuccessful_independent_model_check_denied(self):
        c=checks();c[1]["conclusion"]="failure"
        self.assert_block(runs=c,reason="missing_current_owner_or_qwen3_check")

    def test_unfinished_check_denied(self):
        c=checks();c[0]["status"]="queued";c[0]["conclusion"]=None
        self.assert_block(runs=c,reason="missing_current_owner_or_qwen3_check")

    def test_unapproved_branch_denied(self):
        p=candidate();p["head"]["ref"]="neurofactory-stage5-review-isolated-20261013"
        self.assert_block(pr=p,reason="mixed_or_unowned_changes")

    def test_bad_sha_refused_not_downgraded(self):
        p=candidate();p["head"]["sha"]="invalid"
        with self.assertRaises(MergeGateError):
            evaluate(p,FILES,approvals(),checks(),POLICY)

    def test_live_pr_changed_during_audit_denied(self):
        p=candidate()
        def fetch(url):
            if url==URL+"pulls/10":
                fetch.count+=1
                d=copy.deepcopy(p)
                if fetch.count>1:d["head"]["sha"]="b"*40
                return d
            if "/files?" in url:return FILES
            if "/reviews?" in url:return approvals()
            if "/check-runs?" in url:return {"total_count":2,"check_runs":checks()}
            raise AssertionError(url)
        fetch.count=0
        with self.assertRaisesRegex(MergeGateError,"changed during audit"):
            verify_pr(10,fetch,POLICY)

    def test_missing_check_run_pagination_denied(self):
        p=candidate()
        def fetch(url):
            if url==URL+"pulls/10":return p
            if "/files?" in url:return FILES
            if "/reviews?" in url:return approvals()
            if "/check-runs?" in url:return {"total_count":100,"check_runs":checks()}
            raise AssertionError(url)
        with self.assertRaises(MergeGateError):
            verify_pr(10,fetch,POLICY)

    def test_real_historical_pr2_is_blocked(self):
        p=candidate();p["number"]=2;p["draft"]=True
        p["head"]["ref"]="neurofactory-stage5-review-isolated-20261013"
        paths=FILES+[{"filename":"bridge/neurofactory/development/stage5_independent_security_review_v2.py",
                      "status":"added"}]
        result=self.assert_block(pr=p,files=paths,reviews=[],runs=[])
        self.assertIn("mixed_or_unowned_changes",result["blocking_reasons"])

if __name__=="__main__":
    unittest.main(verbosity=2)
