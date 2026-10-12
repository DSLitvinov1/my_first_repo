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
        self.p=copy.deepcopy(PLAN)
    def evidence(self):
        return {"repo":"DSLitvinov1/my_first_repo",
                "branch":"neurofactory-public-lab-20261012",
                "commit_sha":"a"*40,"tests_passed":True,"independent_review":True}
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
    def test_21_never_allow_account_credentials(self):
        self.p["milestones"][0]["prompt"]+=" токен секрет"
        with self.assertRaises(core.PlanError):core.validate(self.p)

if __name__=="__main__":
    unittest.main(verbosity=2)
