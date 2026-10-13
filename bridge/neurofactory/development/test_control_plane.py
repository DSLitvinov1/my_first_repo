"""Unit tests for real development roadmap, not synthetic customer applications."""
import copy
import hashlib
import json
import pathlib
import unittest
import control_plane as core

PLAN=json.loads((pathlib.Path(__file__).resolve().parent/"roadmap.json").read_text("utf-8"))

class RoadmapTests(unittest.TestCase):
    def setUp(self):
        # Isolate stage-one transition tests from the live advancing production roadmap.
        self.p=copy.deepcopy(PLAN)
        for item in self.p["milestones"]:
            item["state"]="active" if item["id"]=="NF-DEV-01" else "pending"
            item.pop("evidence",None)
    def evidence(self):
        return {"repo":"DSLitvinov1/my_first_repo",
                "branch":"neurofactory-public-lab-20261012",
                "commit_sha":"a"*40,"tests_passed":True,"independent_review":True,
                "reviewer":"qwen3:4b","review_verdict":"REVIEW_OK",
                "verification_mode":"authorized_connector_checked",
                "cloud_test_run":38317981561,"windows_bridge_run":38318013640,
                "independent_review_run":38318188623}
    def test_31_explicit_chat_pause_disables_delivery_but_keeps_next_work(self):
        p=copy.deepcopy(self.p)
        p["chat_delivery_paused"]=True
        p["stage3_independent_of_chat"]=True
        p["milestones"][0]["state"]="verified"
        p["milestones"][1]["state"]="deferred"
        p["milestones"][2]["state"]="active"
        core.validate(p)
        entry=core.outbox(p)
        self.assertEqual(entry["task_id"],"NF-DEV-03")
        self.assertEqual(entry["state"],"paused_by_user")
        self.assertEqual(entry["delivery"],"no_chat_send")
        self.assertFalse(entry["auto_send_enabled"])
    def test_32_deferred_chat_without_explicit_pause_rejected(self):
        p=copy.deepcopy(self.p)
        p["milestones"][0]["state"]="verified"
        p["milestones"][1]["state"]="deferred"
        p["chat_delivery_paused"]=False
        with self.assertRaises(core.PlanError):core.validate(p)
    def test_25_live_roadmap_remains_valid_after_advancement(self):
        self.assertEqual(core.validate(copy.deepcopy(PLAN))["mode"],"self_development")
    def test_26_outbox_tracks_live_active_task(self):
        live=copy.deepcopy(PLAN)
        current=core.select(live)
        if current is not None:
            self.assertEqual(core.outbox(live)["task_id"],current["id"])
    def test_27_live_chat_delivery_required(self):
        core.complete(self.p,"NF-DEV-01",self.evidence())
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-02",self.evidence())
    def test_28_clicked_send_is_not_delivery(self):
        core.complete(self.p,"NF-DEV-01",self.evidence())
        bad=self.evidence()
        bad.update(live_chat_delivery_verified=True,observer="send_button_clicked",
                   delivery_sequence="a"*24,conversation_url="https://chatgpt.com/c/example")
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-02",bad)
    def test_29_real_delivery_unlocks_stage_three(self):
        core.complete(self.p,"NF-DEV-01",self.evidence())
        received=self.evidence()
        received.update(live_chat_delivery_verified=True,observer="visible_chat_turn",
                        delivery_sequence=core.outbox(self.p)["sequence"],
                        conversation_url="https://chatgpt.com/c/12345678-abcd-1234-abcd-123456789012")
        core.complete(self.p,"NF-DEV-02",received)
        self.assertEqual(core.select(self.p)["id"],"NF-DEV-03")
    def test_30_wrong_fingerprint_cannot_approve_stage_two(self):
        core.complete(self.p,"NF-DEV-01",self.evidence())
        bad=self.evidence()
        bad.update(live_chat_delivery_verified=True,observer="visible_chat_turn",
                   delivery_sequence="a"*24,
                   conversation_url="https://chatgpt.com/c/12345678-abcd-1234-abcd-123456789012")
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-02",bad)
    def test_01_validated_real_roadmap(self):
        self.assertIs(core.validate(self.p),self.p)
    def test_02_first_real_development_milestone(self):
        self.assertEqual(core.select(self.p)["id"],"NF-DEV-01")
    def test_03_scheduled_prompt_stable(self):
        a=core.outbox(self.p);b=core.outbox(copy.deepcopy(self.p))
        self.assertEqual(a["sequence"],b["sequence"])
    def test_04_disabled_unknown_chat(self):
        self.assertIsNone(core.outbox(self.p)["destination_conversation"])
        self.assertFalse(core.outbox(self.p)["auto_send_enabled"])
    def test_05_no_duplicate_when_verified(self):
        core.complete(self.p,"NF-DEV-01",self.evidence())
        self.assertEqual(core.select(self.p)["id"],"NF-DEV-02")
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",self.evidence())
    def test_06_block_missing_review(self):
        bad=self.evidence();bad["independent_review"]=False
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_07_block_missing_test(self):
        bad=self.evidence();bad["tests_passed"]=False
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_08_block_other_repo(self):
        bad=self.evidence();bad["repo"]="DSLitvinov1/other-project"
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_09_block_other_branch(self):
        bad=self.evidence();bad["branch"]="main"
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_10_bad_commit_denied(self):
        bad=self.evidence();bad["commit_sha"]="bad"
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_11_scope_drift_denied(self):
        self.p["allow_changes_prefixes"].append("other_project/")
        with self.assertRaises(core.PlanError):core.validate(self.p)
    def test_12_paid_mode_denied(self):
        self.p["free_only"]=False
        with self.assertRaises(core.PlanError):core.validate(self.p)
    def test_13_parallel_milestones_denied(self):
        self.p["milestones"][1]["state"]="active"
        with self.assertRaises(core.PlanError):core.validate(self.p)
    def test_14_false_dependency_denied(self):
        self.p["milestones"][0]["state"]="pending"
        self.p["milestones"][1]["state"]="active"
        with self.assertRaises(core.PlanError):core.validate(self.p)
    def test_15_dependency_order_denied(self):
        self.p["milestones"][0]["depends_on"]=["NF-DEV-05"]
        with self.assertRaises(core.PlanError):core.validate(self.p)
    def test_16_missing_prompt_denied(self):
        self.p["milestones"][0]["prompt"]=""
        with self.assertRaises(core.PlanError):core.validate(self.p)
    def test_17_no_new_training_application(self):
        prompt=core.outbox(self.p)["prompt"]
        self.assertIn("без учебных приложений",prompt)
        self.assertIn("нейрозавод",prompt)
    def test_18_outbox_digest_correct(self):
        entry=core.outbox(self.p)
        raw=json.dumps({"id":entry["task_id"],"prompt":entry["prompt"]},
                       ensure_ascii=False,sort_keys=True)
        self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(),entry["sha256"])
    def test_19_next_prompt_changes_after_completion(self):
        old=core.outbox(self.p)["sequence"]
        core.complete(self.p,"NF-DEV-01",self.evidence())
        self.assertNotEqual(old,core.outbox(self.p)["sequence"])
    def test_20_resolve_all_marks_no_more_work(self):
        for step in self.p["milestones"]:
            step["state"]="verified"
        entry=core.outbox(self.p)
        self.assertEqual(entry["delivery"],"no_chat_send")
        self.assertEqual(entry["prompt"],"")
    def test_22_missing_review_run_rejected(self):
        bad=self.evidence();del bad["independent_review_run"]
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_23_unchecked_external_status_rejected(self):
        bad=self.evidence();bad["verification_mode"]="self_report"
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_24_second_agent_verdict_rejected(self):
        bad=self.evidence();bad["review_verdict"]="REVIEW_BAD"
        with self.assertRaises(core.PlanError):
            core.complete(self.p,"NF-DEV-01",bad)
    def test_21_never_allow_account_credentials(self):
        self.p["milestones"][0]["prompt"]+=" токен=НЕ_ДОПУСКАЕТСЯ"
        with self.assertRaises(core.PlanError):core.validate(self.p)

if __name__=="__main__":
    unittest.main(verbosity=2)
