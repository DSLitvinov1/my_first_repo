"""Regression gates against chat/lane cross-contamination and unsafe actions."""
import copy
import unittest
from check_lanes import (
    load_policy, check_overlaps, check_change_set, owners_for, OwnershipError
)

POLICY = load_policy()


class ChatLaneOwnershipTests(unittest.TestCase):
    def test_all_scope_examples_have_one_owner(self):
        self.assertGreaterEqual(check_overlaps(POLICY), 20)

    def test_current_chat_only_owns_coordination_and_ledger(self):
        self.assertEqual(owners_for("bridge/neurofactory/coordination/OWNERSHIP_RU.md", POLICY), ["coordinator"])
        self.assertEqual(owners_for("bridge/neurofactory/development/stage5-cost-ledger.json", POLICY), ["coordinator"])
        self.assertEqual(owners_for("bridge/neurofactory/development/stage5_remote_journal.py", POLICY), ["core"])

    def test_model_handoff_cannot_edit_recovery_or_expense_ledger(self):
        for path in (
            "bridge/neurofactory/development/stage5_remote_journal.py",
            "bridge/neurofactory/development/stage5_usage_ledger.py",
            "bridge/neurofactory/development/stage5_development_queue.py"
        ):
            with self.assertRaises(OwnershipError):
                check_change_set("handoff", [path], POLICY)

    def test_independent_reviewer_cannot_modify_executor(self):
        with self.assertRaises(OwnershipError):
            check_change_set("review", [
                "bridge/neurofactory/development/stage5_live_pair_lab.py"
            ], POLICY)

    def test_provider_chat_only_owns_free_adapters(self):
        self.assertTrue(check_change_set("providers", [
            "bridge/neurofactory/providers/free_qwen_adapter.py"
        ], POLICY)["ok"])
        with self.assertRaises(OwnershipError):
            check_change_set("providers", [
                "bridge/neurofactory/development/stage4_queue.py"
            ], POLICY)

    def test_other_projects_denied(self):
        for path in ("bridge/beautymed/file.py", "server/main.py",
                     ".github/workflows/unrelated.yml", "../secret.py",
                     "/etc/passwd", "bridge/neurofactory/../../other.py"):
            with self.assertRaises(OwnershipError):
                owners_for(path, POLICY)

    def test_chat_sending_code_blocked(self):
        with self.assertRaises(OwnershipError):
            owners_for("bridge/neurofactory/development/chat_agent/sender.py", POLICY)

    def test_mixed_changes_denied_as_one_batch(self):
        with self.assertRaises(OwnershipError):
            check_change_set("core", [
                "bridge/neurofactory/development/stage4_queue.py",
                "bridge/neurofactory/development/stage5_live_pair_lab.py"
            ], POLICY)

    def test_every_lanes_branch_unique(self):
        branches = [lane["branch"] for lane in POLICY["chat_lanes"]]
        self.assertEqual(len(branches), len(set(branches)))
        self.assertNotIn(POLICY["reference_branch"], branches)

    def test_paid_and_chat_guards_cannot_be_relaxed(self):
        altered = copy.deepcopy(POLICY)
        altered["gates"]["chatgpt_delivery"] = "enabled"
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "lanes.json"
            p.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaises(OwnershipError):
                load_policy(p)

    def test_unclaimed_development_file_denied(self):
        with self.assertRaises(OwnershipError):
            check_change_set("core", [
                "bridge/neurofactory/development/arbitrary_production.py"
            ], POLICY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
