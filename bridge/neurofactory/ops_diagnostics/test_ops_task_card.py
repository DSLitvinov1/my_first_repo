"""Narrow offline tests for the third, untrusted coordinator task-card layer."""
import copy
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from diagnose import SnapshotError
from ops_task_card import adapt_task_card
from ui_readonly_bundle import join_readonly_views, main
from test_ui_readonly_bundle import board
from test_status_adapter import sample
from status_adapter import snapshot_to_status


def good():
    return {
        "schema": 1,
        "kind": "task_status_card",
        "task_id": "NF-DEV-05-Q091",
        "display_phase": "waiting_review",
        "source_sha": "f" * 40,
        "source_trust": "not_attested",
        "actions_allowed": False,
    }


class TaskCardLayerTests(unittest.TestCase):
    def reject(self, change):
        card = good()
        change(card)
        with self.assertRaises(SnapshotError):
            adapt_task_card(card)

    def test_missing_card_is_unknown_and_untrusted(self):
        output = join_readonly_views(board(), snapshot_to_status(sample()))
        card = output["coordinator_task_card"]
        self.assertEqual(card["display_phase"], "UNKNOWN")
        self.assertIsNone(card["task_id"])
        self.assertFalse(card["actions_allowed"])

    def test_valid_task_card_preserves_reported_phase_only(self):
        card = adapt_task_card(good())
        self.assertEqual(card["task_id"], "NF-DEV-05-Q091")
        self.assertEqual(card["reported_phase"], "waiting_review")
        self.assertEqual(card["display_phase"], "UNKNOWN")
        self.assertFalse(card["source_verified"])
        self.assertEqual(card["task_input_sha"], "f"*40)

    def test_different_task_input_and_ops_sha_are_not_comparable(self):
        payload = join_readonly_views(board(), snapshot_to_status(sample()), good())
        self.assertEqual(payload["coordinator_task_card"]["input_sha_vs_ops_sha"], "NOT_COMPARABLE")
        self.assertEqual(payload["coordinator_task_card"]["display_phase"], "UNKNOWN")
        self.assertTrue(payload["consistency"]["board_project_match"])
        self.assertFalse(payload["trust"]["release_authorized"])
        self.assertFalse(any(payload["actions_allowed"].values()))

    def test_explicit_unknown_coordinator_card(self):
        x = good()
        x["task_id"] = None
        x["display_phase"] = "unknown"
        x["source_sha"] = None
        self.assertIsNone(adapt_task_card(x)["task_input_sha"])

    def test_forged_approval_refused(self):
        self.reject(lambda d: d.update(source_trust="independently_approved"))

    def test_forged_permission_refused(self):
        self.reject(lambda d: d.update(actions_allowed=True))

    def test_forged_task_phase_refused(self):
        self.reject(lambda d: d.update(display_phase="approved"))

    def test_conflict_missing_identity_sha_refused(self):
        self.reject(lambda d: d.update(task_id=None))

    def test_bad_git_sha_refused(self):
        self.reject(lambda d: d.update(source_sha="unverified"))

    def test_bad_task_id_refused(self):
        self.reject(lambda d: d.update(task_id="NF-DEV-05-Q091/../../secrets"))

    def test_arbitrary_extra_secret_refused(self):
        self.reject(lambda d: d.update(api_key="PRIVATE_KEY"))

    def test_wrong_schema_refused(self):
        self.reject(lambda d: d.update(schema=True))

    def test_unknown_with_claimed_source_sha_refused(self):
        x = good()
        x["task_id"] = None
        x["display_phase"] = "unknown"
        with self.assertRaises(SnapshotError):
            adapt_task_card(x)

    def test_coordinator_candidate_phase_still_unknown_to_live_ui(self):
        x = good()
        x["display_phase"] = "candidate"
        self.assertEqual(adapt_task_card(x)["display_phase"], "UNKNOWN")

    def test_cli_reads_only_supplied_three_offline_files(self):
        with TemporaryDirectory() as tmp:
            board_p = Path(tmp)/"board.json"
            project_p = Path(tmp)/"project.json"
            card_p = Path(tmp)/"task.json"
            board_p.write_text(json.dumps(board()), encoding="utf-8")
            project_p.write_text(json.dumps(sample()), encoding="utf-8")
            card_p.write_text(json.dumps(good()), encoding="utf-8")
            existing = set(Path(tmp).iterdir())
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--board", str(board_p), "--project", str(project_p),
                                       "--task-card", str(card_p)]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["coordinator_task_card"]["reported_phase"], "waiting_review")
            self.assertEqual(result["coordinator_task_card"]["display_phase"], "UNKNOWN")
            self.assertEqual(set(Path(tmp).iterdir()), existing)

    def test_cli_rejects_duplicate_json_fields(self):
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/"task.json"
            p.write_text('{"schema":1,"schema":2}',encoding="utf-8")
            errors=StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(["--task-card",str(p)]),2)
            self.assertIn("OPS_UI_REFUSED",errors.getvalue())


if __name__ == "__main__":
    unittest.main()
