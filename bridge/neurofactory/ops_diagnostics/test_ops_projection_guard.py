"""Targeted negative tests for direct, untrusted OPS UI projection arguments."""
import copy
import unittest
from diagnose import SnapshotError
from status_adapter import snapshot_to_status
from test_status_adapter import sample
from test_ui_readonly_bundle import board
from ui_readonly_bundle import join_readonly_views


class ProjectionBoundaryTests(unittest.TestCase):
    def view(self):
        return snapshot_to_status(sample())

    def reject(self, change):
        document = self.view()
        change(document)
        with self.assertRaises(SnapshotError):
            join_readonly_views(board(), document)

    def test_valid_prior_output_remains_usable(self):
        output = join_readonly_views(board(), self.view())
        self.assertFalse(output["trust"]["live_source_verified"])
        self.assertFalse(output["actions_allowed"]["publish"])

    def test_forged_latest_success_rejected(self):
        self.reject(lambda d: d["run_highlights"].update(
            last_reported_success={
                "id": 999999, "source_verified": True, "secret": "INJECTED"}))

    def test_secret_in_last_failure_rejected(self):
        self.reject(lambda d: d["run_highlights"].update(
            last_reported_failure={"token": "PRIVATE_TOKEN"}))

    def test_run_claims_platform_attestation_rejected(self):
        self.reject(lambda d: d["runs"][0].update(source_verified=True))

    def test_fake_run_link_rejected(self):
        self.reject(lambda d: d["runs"][0].update(
            url="https://example.invalid/collect?token=secret"))

    def test_run_sha_mismatch_rejected(self):
        self.reject(lambda d: d["runs"][0].update(
            matches_project_head=False))

    def test_unknown_worker_secret_rejected(self):
        self.reject(lambda d: d["workers"][0].update(
            api_key="do-not-copy"))

    def test_worker_verified_flag_rejected(self):
        self.reject(lambda d: d["workers"][0].update(source_verified=True))

    def test_worker_false_live_state_rejected(self):
        self.reject(lambda d: d["workers"][0].update(display_state="RUNNING"))

    def test_bridge_false_live_state_rejected(self):
        self.reject(lambda d: d["bridge"].update(display_state="RUNNING"))

    def test_partial_checkpoint_approved_rejected(self):
        self.reject(lambda d: d["queue"][0]["checkpoint"].update(
            externally_verified=True))

    def test_wrong_checkpoint_count_rejected(self):
        self.reject(lambda d: d.update(checkpoint_counts={"VERIFIED": 1}))

    def test_task_stall_forged_rejected(self):
        self.reject(lambda d: d["queue"][0].update(possibly_stalled=False))

    def test_task_status_forged_rejected(self):
        self.reject(lambda d: d["queue"][0].update(display_state="CHECKED"))

    def test_extra_problem_secret_rejected(self):
        self.reject(lambda d: d["problems"][0].update(api_token="sensitive"))

    def test_problem_injected_text_rejected(self):
        self.reject(lambda d: d["problems"][0].update(code="<script>"))

    def test_problem_repeated_forged_rejected(self):
        def mutate(d):
            d["problems"].append({
                "code": "RUNNER_LOST", "task_id": "NF-OPS-EXAMPLE-1",
                "run_ids": [101, 101], "distinct_reported_runs": 2,
                "recurrent_in_snapshot": True,
                "severity": "WARNING", "source_verified": False})
        self.reject(mutate)

    def test_project_extra_secret_rejected(self):
        self.reject(lambda d: d["project"].update(secret="foo"))

    def test_project_path_traversal_rejected(self):
        self.reject(lambda d: d["project"].update(
            branch="main/../../unexpected"))

    def test_unverified_source_forged_rejected(self):
        self.reject(lambda d: d["source"].update(verified=True))

    def test_release_permission_rejected(self):
        self.reject(lambda d: d["actions_allowed"].update(recover=True))

    def test_top_level_foreign_field_rejected(self):
        self.reject(lambda d: d.update(host_secret="key-value"))

    def test_valid_run_highlights_with_two_sources(self):
        d = sample()
        d["runs"].extend([
            {"id": 210, "state": "COMPLETED", "conclusion": "SUCCESS",
             "head_sha": "a"*40},
            {"id": 220, "state": "COMPLETED", "conclusion": "FAILURE",
             "head_sha": "a"*40},
            {"id": 250, "state": "COMPLETED", "conclusion": "SUCCESS",
             "head_sha": "e"*40}
        ])
        projected = snapshot_to_status(d)
        output = join_readonly_views(board(), projected)
        detail = output["project_detail"]
        self.assertEqual(detail["last_reported_success"]["id"], 210)
        self.assertEqual(detail["last_reported_failure"]["id"], 220)
        self.assertFalse(output["trust"]["release_authorized"])


if __name__ == "__main__":
    unittest.main()
