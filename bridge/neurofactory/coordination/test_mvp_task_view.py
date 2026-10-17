import copy
import unittest
from mvp_task_view import ViewError, task_card

def candidate():
    return {"schema": 1, "task_id": "NF-DEV-05-Q001", "project_id": "nf-sandbox",
            "source_sha": "a"*40, "stage": "READY_FOR_CORE", "result_digest": None,
            "review_provenance": "NOT_ATTESTED_BY_PROJECTION", "source_verified_by_host": False,
            "external_execution_allowed": False, "publication_allowed": False,
            "automatic_retry_allowed": False, "handoff": "PAUSED_BY_USER"}

class TaskViewTests(unittest.TestCase):
    def test_missing_is_unknown(self):
        self.assertEqual(task_card(None)["display_phase"], "unknown")
    def test_valid_no_effects(self):
        p = candidate()
        old = copy.deepcopy(p)
        result = task_card(p)
        self.assertEqual(p, old)
        self.assertFalse(result["actions_allowed"])
        self.assertEqual(result["display_phase"], "waiting_dependency")
    def test_unverified_result_remains_waiting(self):
        p = candidate()
        p.update(stage="RESPONSE_UNVERIFIED", result_digest="b"*64)
        self.assertEqual(task_card(p)["display_phase"], "waiting_review")
    def test_source_verified_still_never_approved(self):
        p = candidate()
        p.update(stage="SOURCE_VERIFIED", result_digest="b"*64)
        self.assertFalse(task_card(p)["actions_allowed"])
    def test_spoofed_release_fails(self):
        p = candidate()
        p["publication_allowed"] = True
        with self.assertRaises(ViewError): task_card(p)
    def test_fake_trusted_origin_fails(self):
        p = candidate()
        p["review_provenance"] = "APPROVED"
        with self.assertRaises(ViewError): task_card(p)
    def test_unexpected_payload_field_fails(self):
        p = candidate()
        p["execute"] = True
        with self.assertRaises(ViewError): task_card(p)
    def test_digest_stage_collision_fails(self):
        p = candidate()
        p["result_digest"] = "b"*64
        with self.assertRaises(ViewError): task_card(p)
    def test_bad_sha_fails(self):
        p = candidate()
        p["source_sha"] = "main"
        with self.assertRaises(ViewError): task_card(p)
    def test_boolean_schema_fails(self):
        p = candidate()
        p["schema"] = True
        with self.assertRaises(ViewError): task_card(p)

if __name__ == "__main__": unittest.main()
