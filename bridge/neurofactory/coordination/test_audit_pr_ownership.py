"""No network required; guarantee different chats cannot mix code or tests."""
import pathlib
import sys
import unittest

HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from audit_pr_ownership import classify_pr, scan, REPO, URL_ROOT
from check_lanes import load_policy

POLICY = load_policy()

class ParallelChatPRTests(unittest.TestCase):
    def test_three_active_chats_have_distinct_branches(self):
        names=["core","handoff","coordinator"]
        branches=[row["branch"] for row in POLICY["chat_lanes"]
                  if row["id"] in names]
        self.assertEqual(len(branches), 3)
        self.assertEqual(len(set(branches)), 3)

    def test_core_only(self):
        check=classify_pr(10,"neurofactory-core-queue-owned-20261013",[
            "bridge/neurofactory/development/stage5_development_queue.py",
            "bridge/neurofactory/development/test_stage5_development_queue.py",
            ".github/workflows/neurofactory-core-owned-queue-check.yml",
        ],POLICY,False)
        self.assertTrue(check["approved"])

    def test_handoff_only(self):
        check=classify_pr(11,"neurofactory-model-handoff-owned-20261013",[
            "bridge/neurofactory/development/stage5_live_pair_lab.py",
            "bridge/neurofactory/development/model_handoff_owned/test_q002.py",
            ".github/workflows/neurofactory-handoff-owned-isolated.yml",
        ],POLICY,False)
        self.assertTrue(check["approved"])

    def test_coordinator_only(self):
        check=classify_pr(12,"neurofactory-chat-coordination-20261013",[
            "bridge/neurofactory/coordination/audit_pr_ownership.py",
            "bridge/neurofactory/coordination/test_audit_pr_ownership.py",
            ".github/workflows/neurofactory-coordination-audit.yml",
        ],POLICY,False)
        self.assertTrue(check["approved"])

    def test_review_files_cannot_be_sneaked_into_core(self):
        check=classify_pr(2,"neurofactory-core-queue-owned-20261013",[
            "bridge/neurofactory/development/stage5_development_queue.py",
            "bridge/neurofactory/development/stage5_concurrency_independent_qwen3.py",
        ],POLICY,True)
        self.assertFalse(check["approved"])
        self.assertCountEqual(check["owners"],["core","review"])

    def test_actual_historical_pr2_detected_and_blocked(self):
        files=[
            ".github/workflows/neurofactory-stage5-restore-concurrency-qwen3.yml",
            ".github/workflows/neurofactory-stage5-scoped-review-v2.yml",
            "bridge/neurofactory/development/stage5_concurrency_independent_qwen3.py",
            "bridge/neurofactory/development/stage5_development_queue.py",
            "bridge/neurofactory/development/stage5_independent_security_review_v2.py",
            "bridge/neurofactory/development/test_stage5_development_queue.py",
        ]
        report=classify_pr(2,"neurofactory-stage5-review-isolated-20261013",
                           files,POLICY,True)
        self.assertFalse(report["approved"])
        self.assertCountEqual(report["owners"],["core","review"])
        self.assertTrue(report["draft"])

    def test_wrong_branch_even_with_single_owner(self):
        check=classify_pr(13,"neurofactory-stage5-pair-recovery-20261013",[
            "bridge/neurofactory/development/stage5_live_pair_lab.py"],POLICY,False)
        self.assertFalse(check["approved"])

    def test_non_neurofactory_and_paid_chat_paths_rejected(self):
        for path in ("other/secret.py",
                     "bridge/neurofactory/development/chat_agent/auto_send.py",
                     ".github/workflows/other_project.yml"):
            with self.subTest(path=path):
                self.assertFalse(classify_pr(14,
                    "neurofactory-chat-coordination-20261013",
                    [path],POLICY,False)["approved"])

    def test_empty_files_fail_closed(self):
        self.assertFalse(classify_pr(15,"neurofactory-core-queue-owned-20261013",
                                     [],POLICY,False)["approved"])

    def test_mock_api_scan_detects_pr2_without_writing(self):
        def mock_getter(endpoint):
            self.assertTrue(endpoint.startswith(URL_ROOT))
            if "/files?" in endpoint:
                return [{"filename":"bridge/neurofactory/development/stage5_development_queue.py"},
                        {"filename":"bridge/neurofactory/development/stage5_independent_security_review_v2.py"}]
            return [{"number":2,"head":{"ref":"neurofactory-stage5-review-isolated-20261013"},
                     "draft":True}]
        audit=scan(mock_getter)
        self.assertEqual(audit["unsafe_ready_prs"],[])
        self.assertEqual(audit["drafts_requiring_split"],[2])
        self.assertEqual(audit["active_chats"],3)

    def test_unsafe_non_draft_pr_detected(self):
        def mock_getter(endpoint):
            if "/files?" in endpoint:
                return [{"filename":"bridge/neurofactory/development/stage5_development_queue.py"},
                        {"filename":"bridge/neurofactory/development/stage5_git_receipts.py"}]
            return [{"number":4,"head":{"ref":"neurofactory-core-queue-owned-20261013"},
                     "draft":False}]
        self.assertEqual(scan(mock_getter)["unsafe_ready_prs"],[4])

if __name__ == "__main__":
    unittest.main(verbosity=2)
