"""Regression for forged expected receipt identity overlooked by first Qwen reviewer."""
import hashlib,importlib.util,json,pathlib,unittest
import stage4_live_worker as limits
HERE=pathlib.Path(__file__).resolve().parent
SOURCE=HERE/"stage4_receipt_rules.py"
REPO="DSLitvinov1/my_first_repo"
TARGET="bridge/neurofactory/development/stage4_receipt_rules.py"
class ReceiptAttackRegression(unittest.TestCase):
    def setUp(self):
        self.source=SOURCE.read_text("utf-8")
        spec=importlib.util.spec_from_file_location("nf4_verified_candidate",SOURCE)
        mod=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.fn=mod.receipt_matches
        self.sha="a"*40
    def test_regular_valid_receipt(self):
        record={"repo":REPO,"path":TARGET,"sha":self.sha}
        self.assertTrue(self.fn(record,REPO,TARGET,self.sha))
    def test_forged_repo_matching_untrusted_expectation(self):
        record={"repo":"attacker/other","path":TARGET,"sha":self.sha}
        self.assertFalse(self.fn(record,"attacker/other",TARGET,self.sha))
    def test_forged_path_matching_untrusted_expectation(self):
        record={"repo":REPO,"path":"bridge/other_project/file.py","sha":self.sha}
        self.assertFalse(self.fn(record,REPO,"bridge/other_project/file.py",self.sha))
    def test_forged_repo_and_path_together(self):
        record={"repo":"attacker/other","path":"../secret","sha":self.sha}
        self.assertFalse(self.fn(record,"attacker/other","../secret",self.sha))
    def test_case_changed_sha_denied(self):
        record={"repo":REPO,"path":TARGET,"sha":"A"*40}
        self.assertFalse(self.fn(record,REPO,TARGET,"A"*40))
    def test_nonstring_inputs_denied(self):
        record={"repo":REPO,"path":TARGET,"sha":self.sha}
        for bad in (None,{},[],3,True):
            self.assertFalse(self.fn(record,bad,TARGET,self.sha))
            self.assertFalse(self.fn(record,REPO,bad,self.sha))
            self.assertFalse(self.fn(record,REPO,TARGET,bad))
    def test_extra_metadata_denied(self):
        record={"repo":REPO,"path":TARGET,"sha":self.sha,"untrusted":True}
        self.assertFalse(self.fn(record,REPO,TARGET,self.sha))
    def test_structural_guard_and_existing_15_cases(self):
        digest,passed=limits.check(self.source)
        self.assertEqual(passed,15)
        self.assertEqual(digest,hashlib.sha256(self.source.encode()).hexdigest())
    def test_no_network_or_write_functions(self):
        self.assertNotIn("import ",self.source)
        self.assertNotIn("open(",self.source)
        self.assertNotIn("eval(",self.source)
if __name__=="__main__":unittest.main()
