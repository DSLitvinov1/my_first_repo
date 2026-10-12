"""Acceptance gates for real application-factory self-improvement; no educational apps."""
import copy,inspect,json,pathlib,unittest
import real_self_improve as real
import stage3_guard as gate
ROOT=pathlib.Path(__file__).resolve().parent

SAFE_CANDIDATE='''
def approved_change_path(path):
    if not isinstance(path, str) or len(path) < 4 or len(path) > 240:
        return False
    if not path.isascii() or '\\\\' in path or not all(
        part != '' and part != '.' and part != '..' and
        all(c.isalnum() or c in '_-.' for c in part)
        for part in path.split('/')
    ):
        return False
    if path.startswith('bridge/neurofactory/'):
        return True
    return path.startswith('.github/workflows/neurofactory-') and path.endswith('.yml') and len(path) > 38
'''.strip()+'\n'
class RealSelfImprovementTests(unittest.TestCase):
    def setUp(self):
        self.plan=gate.read()
        # Fixture stays at stage two even after the real roadmap advances.
        for item in self.plan['milestones']:
            if item['id']=='NF-DEV-01':item['state']='verified'
            elif item['id']=='NF-DEV-02':item['state']='active'
            else:item['state']='pending'
    def test_01_real_candidate_contract(self):
        self.assertIsNotNone(real.validate_source(SAFE_CANDIDATE))
    def test_02_independent_real_repo_path_policy(self):
        self.assertEqual(real.acceptance(SAFE_CANDIDATE),len(real.GOOD)+len(real.BAD)+len(real.NONSTR))
    def test_03_ban_import(self):
        with self.assertRaises(ValueError):real.validate_source("import os\n"+SAFE_CANDIDATE)
    def test_04_ban_io(self):
        code=SAFE_CANDIDATE.replace("return True","open('secrets');return True")
        with self.assertRaises(ValueError):real.validate_source(code)
    def test_05_ban_process_launch(self):
        code=SAFE_CANDIDATE.replace("return True","__import__('os').system('whoami');return True")
        with self.assertRaises(ValueError):real.validate_source(code)
    def test_06_ban_second_function(self):
        with self.assertRaises(ValueError):real.validate_source(SAFE_CANDIDATE+"\ndef other(): pass\n")
    def test_07_ban_class(self):
        with self.assertRaises(ValueError):real.validate_source(SAFE_CANDIDATE+"\nclass Backdoor: pass\n")
    def test_08_ban_dynamic_attr(self):
        code=SAFE_CANDIDATE.replace("return True","return path.__class__")
        with self.assertRaises(ValueError):real.validate_source(code)
    def test_09_ban_missing_contract(self):
        with self.assertRaises(ValueError):real.validate_source(SAFE_CANDIDATE.replace("approved_change_path","arbitrary"))
    def test_10_wrong_project_bad(self):
        code="def approved_change_path(path):\n    return True\n"
        with self.assertRaises(ValueError):real.acceptance(code)
    def test_11_current_stage_two_blocks_self_change(self):
        self.assertFalse(gate.approved_stage3(self.plan))
    def test_12_clicked_button_does_not_unlock(self):
        p=copy.deepcopy(self.plan);p["milestones"][1]["state"]="verified";p["milestones"][2]["state"]="active"
        p["milestones"][1]["evidence"]={"observer":"send_button_clicked"}
        self.assertFalse(gate.approved_stage3(p))
    def test_13_actual_chat_receipt_unlocks_only_stage3(self):
        p=copy.deepcopy(self.plan);p["milestones"][1]["state"]="verified";p["milestones"][2]["state"]="active"
        p["milestones"][1]["evidence"]={
            "observer":"visible_chat_turn","live_chat_delivery_verified":True,
            "conversation_url":"https://chatgpt.com/c/12345678-abcd-1234-abcd-123456789012",
            "delivery_sequence":__import__("control_plane").outbox(self.plan)["sequence"],"independent_review":True,"tests_passed":True}
        self.assertTrue(gate.approved_stage3(p))
    def test_14_no_other_path_to_stage_three(self):
        p=copy.deepcopy(self.plan);p["milestones"][2]["state"]="active"
        with self.assertRaises(Exception):gate.approved_stage3(p)
if __name__=="__main__":
    unittest.main(verbosity=2)
