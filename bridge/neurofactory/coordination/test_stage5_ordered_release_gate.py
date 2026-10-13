"""Coordinator-only ordered preflight; NEVER authorizes a merge or a publication."""
import copy
import json
import re
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("stage5-ordered-release-gate-20261014.json")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ORDER = ["separate_REVIEW_owner_approves_exact_handoff",
         "CORE_owns_and_tests_minimal_integration_contract",
         "COORDINATOR_rechecks_exact_five_heads_and_branch_protection",
         "COORDINATOR_authorizes_two_or_more_unique_never_finished_tasks",
         "independent_approval_of_new_task_before_trusted_publisher",
         "publish_once_then_fetch_receipt_and_persist_checkpoint",
         "retry_delivery_must_be_noop_and_runner_failover_safe"]

def inspect(doc):
    if doc.get("project") != "НЕЙРОЗАВОД" or doc.get("issue_number") != 3:
        raise ValueError("Foreign release docket")
    if doc.get("role") != "COORDINATOR" or doc.get("kind") != "ordered_stage5_integration_readiness_only":
        raise ValueError("Untrusted release coordinator")
    if doc.get("release_authorized") is not False or doc.get("production_writes_allowed") is not False:
        raise ValueError("Premature release is forbidden")
    if doc.get("launch_order") != ORDER:
        raise ValueError("Review, integration, publisher sequence modified")
    handoff, review, core = doc["handoff"], doc["review_owner"], doc["core"]
    if handoff["branch"] != "neurofactory-model-handoff-owned-20261013":
        raise ValueError("Wrong handoff owner")
    if not SHA.fullmatch(handoff["head"]) or not DIGEST.fullmatch(handoff["source_sha256"]):
        raise ValueError("Handoff source not pinned")
    if not DIGEST.fullmatch(handoff["candidate_sha256"]) or type(handoff["artifact_id"]) is not int:
        raise ValueError("Candidate evidence not pinned")
    if handoff["candidate_code_published"] is not False:
        raise ValueError("False claim of already published candidate")
    if review["branch"] != "neurofactory-review-owned-20261013" or core["branch"] != "neurofactory-core-queue-owned-20261013":
        raise ValueError("Wrong owner for review or integration")
    if review["decision"] not in ("PENDING", "APPROVE", "REJECT"):
        raise ValueError("Malformed independent decision")
    review_approved = (review["decision"] == "APPROVE"
                       and review["reviewed_handoff_commit"] == handoff["head"]
                       and review["reviewed_module_sha256"] == handoff["source_sha256"]
                       and review["reviewed_artifact_id"] == handoff["artifact_id"]
                       and isinstance(review["evidence_run"], int)
                       and isinstance(review["signoff_ref"], str) and bool(review["signoff_ref"]))
    core_ready = (review_approved and core["integration_contract"] == "APPROVED"
                  and bool(core["approved_minimal_paths"])
                  and bool(core["own_tests"]))
    approved_new_ids = doc["future_new_tasks"]["identifiers_reserved"]
    ids_valid = (isinstance(approved_new_ids, list) and 2 <= len(approved_new_ids) <= 8
                 and len(set(approved_new_ids)) == len(approved_new_ids)
                 and all(re.fullmatch(r"NF-DEV-05-Q[0-9]{3}", x) for x in approved_new_ids)
                 and "NF-DEV-05-Q090" not in approved_new_ids)
    new_task_ready = core_ready and ids_valid and doc["future_new_tasks"]["identifiers_approved"] is True
    if doc["future_new_tasks"]["repeat_completed_Q090"] is not False:
        raise ValueError("Previously completed task would be repeated")
    protection = doc["protection"]
    if protection["branch"] != "neurofactory-public-lab-20261012":
        raise ValueError("Wrong integration destination")
    protected = protection["rules_enforced"] is True and protection["observed_protected"] is True
    conflict = doc["existing_conflict"]
    if conflict["pull_request"] != 2 or conflict["allow_merge"] is not False:
        raise ValueError("Historical mixed PR must stay blocked")
    conditions = doc["conditions"]
    if conditions != {"paid_models_allowed":False,"chatgpt_sending_enabled":False,
                      "restart_shared_windows_allowed":False,"other_projects_writes":False}:
        raise ValueError("Unsafe deployment permissions")
    stage = ("AWAITING_REVIEW_OWNER" if not review_approved else
             "AWAITING_CORE_COMPATIBILITY" if not core_ready else
             "AWAITING_BRANCH_PROTECTION" if not protected else
             "AWAITING_UNIQUE_TASK_APPROVAL" if not new_task_ready else
             "ELIGIBLE_FOR_SEPARATE_LIVE_TEST_AUTHORIZATION")
    # This is a readiness assessment ONLY. It is never a signed approval.
    return {"status":stage,"review_owner_approved":review_approved,
            "core_integration_contract_ready":core_ready,
            "unique_tasks_approved":new_task_ready,"rules_enforced":protected,
            "publication_authorized":False,"merge_authorized":False}

class OrderedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(PATH.read_text(encoding="utf-8"))

    def test_current_state_refuses_publication_and_merge(self):
        result = inspect(self.doc)
        self.assertEqual(result["status"], "AWAITING_REVIEW_OWNER")
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["merge_authorized"])

    def test_model_approval_cannot_imitate_review_owner(self):
        altered = copy.deepcopy(self.doc)
        altered["review_owner"]["decision"] = "APPROVE"
        self.assertEqual(inspect(altered)["status"], "AWAITING_REVIEW_OWNER")

    def test_old_handoff_commit_or_wrong_digest_is_not_approved(self):
        for field, value in [("reviewed_handoff_commit","0"*40),
                             ("reviewed_module_sha256","a"*64),
                             ("reviewed_artifact_id",987)]:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.doc)
                altered["review_owner"].update({"decision":"APPROVE",
                    "reviewed_handoff_commit":altered["handoff"]["head"],
                    "reviewed_module_sha256":altered["handoff"]["source_sha256"],
                    "reviewed_artifact_id":altered["handoff"]["artifact_id"],
                    "evidence_run":123,"signoff_ref":"review-owned-proof"})
                altered["review_owner"][field] = value
                self.assertFalse(inspect(altered)["review_owner_approved"])

    def test_core_cannot_proceed_before_review(self):
        altered = copy.deepcopy(self.doc)
        altered["core"]["integration_contract"] = "APPROVED"
        altered["core"]["approved_minimal_paths"] = ["core_owned/connector.py"]
        altered["core"]["own_tests"] = [123]
        self.assertFalse(inspect(altered)["core_integration_contract_ready"])

    def test_no_identifiers_are_reserved_yet(self):
        self.assertEqual(self.doc["future_new_tasks"]["identifiers_reserved"],[])
        self.assertFalse(inspect(self.doc)["unique_tasks_approved"])

    def test_no_repetition_of_completed_q090(self):
        altered = copy.deepcopy(self.doc)
        altered["future_new_tasks"]["repeat_completed_Q090"] = True
        with self.assertRaises(ValueError): inspect(altered)

    def test_historical_mixed_pr_still_blocked(self):
        altered = copy.deepcopy(self.doc)
        altered["existing_conflict"]["allow_merge"] = True
        with self.assertRaises(ValueError): inspect(altered)

    def test_no_paid_model_or_chat_sender(self):
        for key in self.doc["conditions"]:
            with self.subTest(key=key):
                altered = copy.deepcopy(self.doc)
                altered["conditions"][key] = True
                with self.assertRaises(ValueError): inspect(altered)

    def test_fake_production_release_denied(self):
        altered = copy.deepcopy(self.doc)
        altered["release_authorized"] = True
        with self.assertRaises(ValueError): inspect(altered)

    def test_launch_order_is_not_skippable(self):
        altered = copy.deepcopy(self.doc)
        altered["launch_order"].reverse()
        with self.assertRaises(ValueError): inspect(altered)

    def test_no_hardcoded_zero_billing_claim(self):
        self.assertNotIn("charges_rub", self.doc)

if __name__ == "__main__":
    unittest.main(verbosity=2)
