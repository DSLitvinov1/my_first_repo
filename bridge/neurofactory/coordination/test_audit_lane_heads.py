"""Offline regression tests for exact five-lane GitHub compare audit."""
import copy
import unittest

from audit_lane_heads import (
    API, BOOTSTRAP, LANES, LaneAuditError,
    github_get, inspect_branch, scan
)
from check_lanes import load_policy

POLICY = load_policy()
FILES = {
    "core": ["bridge/neurofactory/development/core_owned/task.py"],
    "handoff": ["bridge/neurofactory/development/model_handoff_owned/result.json"],
    "review": ["bridge/neurofactory/development/review_owned/report.json"],
    "providers": ["bridge/neurofactory/providers/free_model.py"],
    "coordinator": ["bridge/neurofactory/coordination/progress.json"],
}
BRANCHES = {x["id"]: x["branch"] for x in POLICY["chat_lanes"]}


def response(lane, filenames=None, status="ahead", behind=0, ahead=1):
    items = [{"filename": x, "status": "added"}
             for x in (FILES[lane] if filenames is None else filenames)]
    return {"status": status, "ahead_by": ahead, "behind_by": behind,
            "total_commits": ahead, "files": items}


def fake_get(override=None):
    override = override or {}
    def fetch(url):
        if not url.startswith(API + "compare/" + BOOTSTRAP + "..."):
            raise AssertionError("Unexpected endpoint: " + url)
        branch = url.split("...")[-1]
        lane = next((key for key, b in BRANCHES.items() if b == branch), None)
        if lane is None:
            raise AssertionError("Unexpected branch: " + branch)
        return override.get(lane, response(lane))
    return fetch


class ChatBranchHeadAuditTests(unittest.TestCase):
    def test_all_five_lanes_have_unique_safe_deltas(self):
        result = scan(POLICY, fake_get())
        self.assertEqual(len(result["lanes"]), 5)
        self.assertEqual(result["cross_chat_file_conflicts"], [])
        self.assertEqual(sum(x["file_count"] for x in result["lanes"]), 5)
        self.assertEqual(result["paid_model_calls"], 0)
        self.assertEqual(result["mutation_operations"], 0)

    def test_distinct_branch_can_be_unchanged(self):
        result = scan(POLICY, fake_get({
            "core": response("core", [], status="identical", ahead=0)
        }))
        self.assertEqual(result["lanes"][0]["file_count"], 0)

    def test_wrong_lane_file_rejected(self):
        malicious = response("core", FILES["handoff"])
        with self.assertRaisesRegex(LaneAuditError, "Wrong lane"):
            scan(POLICY, fake_get({"core": malicious}))

    def test_paid_and_chat_sender_paths_rejected(self):
        for filename in ("bridge/neurofactory/development/chat_agent/sender.py",
                         ".github/workflows/other-app.yml",
                         "bridge/neurofactory/../../other-app/file.py"):
            with self.subTest(filename=filename):
                with self.assertRaises(LaneAuditError):
                    inspect_branch("coordinator", POLICY, fake_get({
                        "coordinator": response("coordinator", [filename])
                    }))

    def test_diverged_history_must_stop(self):
        for status, behind in (("diverged", 3), ("behind", 1), ("ahead", 1)):
            with self.subTest(status=status):
                with self.assertRaises(LaneAuditError):
                    scan(POLICY, fake_get({
                        "core": response("core", status=status, behind=behind)
                    }))

    def test_missing_or_truncated_files_must_stop(self):
        incomplete = response("handoff")
        incomplete.pop("files")
        with self.assertRaises(LaneAuditError):
            inspect_branch("handoff", POLICY, fake_get({"handoff": incomplete}))
        partial = response("handoff", [])
        with self.assertRaises(LaneAuditError):
            inspect_branch("handoff", POLICY, fake_get({"handoff": partial}))

    def test_unexpected_rename_of_other_chat_denied(self):
        old = response("core", ["bridge/neurofactory/development/core_owned/next.py"])
        old["files"][0].update({
            "status": "renamed",
            "previous_filename": "bridge/neurofactory/development/review_owned/old.py"
        })
        with self.assertRaises(LaneAuditError):
            scan(POLICY, fake_get({"core": old}))

    def test_rename_within_same_owned_area_allowed(self):
        renamed = response("core", ["bridge/neurofactory/development/core_owned/next.py"])
        renamed["files"][0].update({
            "status": "renamed",
            "previous_filename": "bridge/neurofactory/development/core_owned/old.py"
        })
        result = scan(POLICY, fake_get({"core": renamed}))
        self.assertEqual(result["lanes"][0]["file_count"], 2)

    def test_duplicate_compare_filenames_denied(self):
        dup = response("review", FILES["review"] * 2)
        with self.assertRaises(LaneAuditError):
            inspect_branch("review", POLICY, fake_get({"review": dup}))

    def test_stale_branch_cannot_claim_another_owner(self):
        p = copy.deepcopy(POLICY)
        p["chat_lanes"][0]["branch"] = BRANCHES["handoff"]
        with self.assertRaises((LaneAuditError, AssertionError)):
            scan(p, fake_get())

    def test_free_and_chat_safety_controls_not_weakened(self):
        for section, option in (("gates", "paid_api"), ("gates", "chatgpt_delivery")):
            p = copy.deepcopy(POLICY)
            p[section][option] = "enabled"
            with self.assertRaises(LaneAuditError):
                scan(p, fake_get())

    def test_reject_unknown_owner_and_url(self):
        with self.assertRaises(LaneAuditError):
            inspect_branch("unknown", POLICY, fake_get())
        with self.assertRaises(LaneAuditError):
            github_get("https://api.github.com/repos/other/project/actions/runs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
