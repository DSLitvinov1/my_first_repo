"""Untrusted snapshot adversarial checks for operator-only Neurofactory diagnostics."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

from diagnose import SnapshotError, diagnose, _parse_unique, main

SHA = "a" * 40
OTHER_SHA = "b" * 40
ART = "c" * 64
TASK = "NF-DEV-05-Q091"

def example():
    return {
        "schema": 1, "scope": "neurofactory-ops-candidate",
        "target": {"task_id": TASK, "branch": "neurofactory-ops-sandbox",
                   "head_sha": SHA},
        "branch": {"name": "neurofactory-ops-sandbox",
                   "head_sha": SHA, "protected": True},
        "runs": [
            {"id": 111, "role": "unit_tests", "status": "completed",
             "conclusion": "success", "head_sha": SHA},
            {"id": 112, "role": "model_writer", "status": "completed",
             "conclusion": "success", "head_sha": SHA},
            {"id": 113, "role": "model_reviewer", "status": "completed",
             "conclusion": "success", "head_sha": SHA},
            {"id": 114, "role": "independent_review", "status": "completed",
             "conclusion": "success", "head_sha": SHA},
        ],
        "review": {"verdict": "APPROVE", "head_sha": SHA,
                   "artifact_sha256": ART},
        "checkpoint": {"state": "sealed", "task_id": TASK,
                       "head_sha": SHA, "durable_readback": True},
        "publisher_receipt": {"state": "externally_verified",
                              "commit_sha": OTHER_SHA, "task_id": TASK},
        "ownership": {"lane": "ops_candidate", "same_owner_paths": True}
    }

class ReadonlyDiagnoseTests(unittest.TestCase):
    def check_blocker(self, mutate, code):
        d = example()
        mutate(d)
        self.assertIn(code, diagnose(d)["blockers"])

    def test_positive_claims_never_authorize_release(self):
        result = diagnose(example())
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["writes_performed"], 0)
        self.assertEqual(result["model_calls_performed"], 0)
        self.assertEqual(result["diagnosis"], "BLOCKED")
        self.assertIn("REVIEW_PROVENANCE_UNVERIFIED", result["blockers"])

    def test_review_reject(self):
        self.check_blocker(lambda d: d["review"].update(verdict="REJECT"),
                           "INDEPENDENT_REVIEW_REJECTED")

    def test_missing_review(self):
        self.check_blocker(lambda d: d.update(review=None),
                           "INDEPENDENT_REVIEW_MISSING")

    def test_wrong_review_sha(self):
        self.check_blocker(lambda d: d["review"].update(head_sha=OTHER_SHA),
                           "REVIEW_NOT_FOR_CURRENT_HEAD")

    def test_stale_branch(self):
        self.check_blocker(lambda d: d["branch"].update(head_sha=OTHER_SHA),
                           "STALE_BRANCH_HEAD")

    def test_incorrect_branch(self):
        self.check_blocker(lambda d: d["branch"].update(name="main"),
                           "WRONG_BRANCH")

    def test_unprotected_branch(self):
        self.check_blocker(lambda d: d["branch"].update(protected=False),
                           "BRANCH_PROTECTION_MISSING")

    def test_run_wrong_commit(self):
        self.check_blocker(lambda d: d["runs"][0].update(head_sha=OTHER_SHA),
                           "OUTDATED_RUN")

    def test_run_failure(self):
        self.check_blocker(lambda d: d["runs"][0].update(conclusion="failure"),
                           "RUN_FAILED")

    def test_run_timeout(self):
        self.check_blocker(lambda d: d["runs"][0].update(conclusion="timed_out"),
                           "RUN_FAILED")

    def test_run_in_progress(self):
        self.check_blocker(lambda d: d["runs"][0].update(status="in_progress",
                                                         conclusion=None),
                           "RUN_NOT_FINISHED")

    def test_required_test_missing(self):
        self.check_blocker(lambda d: d.update(
            runs=[r for r in d["runs"] if r["role"] != "unit_tests"]),
            "UNIT_TESTS_MISSING")

    def test_two_models_required(self):
        self.check_blocker(lambda d: d.update(
            runs=[r for r in d["runs"] if r["role"] != "model_writer"]),
            "TWO_MODEL_EVIDENCE_MISSING")

    def test_partial_checkpoint(self):
        self.check_blocker(lambda d: d["checkpoint"].update(state="partial"),
                           "CHECKPOINT_PARTIAL")

    def test_wrong_checkpoint_task(self):
        self.check_blocker(lambda d: d["checkpoint"].update(task_id="NF-DEV-05-Q092"),
                           "CHECKPOINT_WRONG_TASK")

    def test_checkpoint_readback_does_not_count_as_independent_proof(self):
        self.assertIn("CROSS_RUN_DURABILITY_UNVERIFIED", diagnose(example())["blockers"])

    def test_missing_checkpoint(self):
        self.check_blocker(lambda d: d.update(checkpoint=None),
                           "CHECKPOINT_MISSING")

    def test_unknown_publisher_outcome_stops_replay(self):
        self.check_blocker(lambda d: d.update(
            publisher_receipt={"state":"uncertain"}), "UNCERTAIN_PUBLISH_STOP")

    def test_no_publisher_run_does_not_imply_success(self):
        self.check_blocker(lambda d: d.update(
            publisher_receipt={"state":"not_attempted"}), "PUBLISHER_NOT_ATTEMPTED")

    def test_missing_publisher_receipt(self):
        self.check_blocker(lambda d: d.update(
            publisher_receipt=None), "PUBLISHER_RECEIPT_MISSING")

    def test_wrong_receipt_task(self):
        self.check_blocker(lambda d: d["publisher_receipt"].update(task_id="NF-DEV-05-Q099"),
                           "RECEIPT_WRONG_TASK")

    def test_foreign_path_warning(self):
        self.check_blocker(lambda d: d["ownership"].update(same_owner_paths=False),
                           "POSSIBLE_FOREIGN_FILE_CHANGE")

    def test_missing_ownership(self):
        self.check_blocker(lambda d: d.update(ownership=None),
                           "OWNERSHIP_EVIDENCE_MISSING")

    def test_duplicate_run_ids_rejected(self):
        d = example()
        d["runs"][1]["id"] = 111
        with self.assertRaises(SnapshotError):
            diagnose(d)

    def test_invalid_run_claim_rejected(self):
        d = example()
        d["runs"][0].update(status="queued", conclusion="success")
        with self.assertRaises(SnapshotError):
            diagnose(d)

    def test_unsafe_json_duplicate_keys_rejected(self):
        with self.assertRaises(SnapshotError):
            _parse_unique('{"schema":1,"schema":2}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(SnapshotError):
            _parse_unique('{"bad":NaN}')

    def test_input_oversized_run_list_rejected(self):
        d=example()
        d["runs"]=d["runs"]*50
        with self.assertRaises(SnapshotError):
            diagnose(d)

    def test_schema_must_be_exact(self):
        d=example()
        d["extra"]={"secret":"never echo"}
        with self.assertRaises(SnapshotError):
            diagnose(d)

    def test_unknown_scope_rejected(self):
        d=example()
        d["scope"]="different-project"
        with self.assertRaises(SnapshotError):
            diagnose(d)

    def test_output_does_not_echo_secrets(self):
        d=example()
        d["review"]["private_token"]="SENSITIVE_CUSTOMER_TOKEN"
        text=json.dumps(diagnose(d))
        self.assertNotIn("SENSITIVE_CUSTOMER_TOKEN",text)

    def test_cli_is_readonly_and_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"snapshot.json"
            p.write_text(json.dumps(example()),encoding="utf-8")
            output=StringIO()
            with redirect_stdout(output):
                code=main([str(p)])
            self.assertEqual(code,0)
            self.assertEqual(json.loads(output.getvalue()),diagnose(example()))
            self.assertEqual(list(Path(td).iterdir()),[p])

    def test_cli_invalid_snapshot_exits_nonzero_without_writes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"snapshot.json"
            p.write_text('{"schema":1,"schema":2}',encoding="utf-8")
            err=StringIO()
            with redirect_stderr(err):
                code=main([str(p)])
            self.assertEqual(code,2)
            self.assertIn("DIAGNOSIS_REFUSED",err.getvalue())
            self.assertEqual(len(list(Path(td).iterdir())),1)

if __name__ == "__main__":
    unittest.main()
