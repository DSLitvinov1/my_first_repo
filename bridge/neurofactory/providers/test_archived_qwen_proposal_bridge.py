"""Address historical REAL Qwen result conversion; never fake new generation."""
import hashlib
import unittest
from archived_qwen_proposal_bridge import (
    ArchivedQwenBlocked,convert_observed_qwen_to_unverified_result)
PROMPT="Ответь одним коротким предложением на русском: зачем программисту автоматические тесты?"
TEXT="за счет автоматизации процесса проверки кода и улучшения производительности"
def sha(x):return hashlib.sha256(x.encode("utf8")).hexdigest()
def inputs():
    return ({
      "schema":"neurofactory.providers.request.v1",
      "task_id":"NF-QWEN-REAL-PROOF-001",
      "project_id":"nf-sandbox",
      "input_sha256":sha("pinned synthetic user task"),
      "target_path":"docs/sandbox-qwen-answer.txt",
      "instruction":PROMPT,
    },{
      "model":"Qwen/Qwen2.5-0.5B-Instruct",
      "revision":"7ae557604adf67be50417f59c2c2f167def9a775",
      "text":TEXT,"text_sha256":sha(TEXT),
      "generated_tokens":19,
      "offline_mock":False,
      "source_actions_run":39057951286,
    })
class QwenArchivedPreviewTests(unittest.TestCase):
    def setUp(self):
        self.request,self.model=inputs()
        self.assertEqual(sha(TEXT),"0a4215b15a5f936050147a658ee4468b2a00e94f2a65ccf20b48513c89ded305")
    def produce(self,request=None,model=None):
        return convert_observed_qwen_to_unverified_result(
          request=self.request if request is None else request,
          observed=self.model if model is None else model)
    def test_real_observed_model_text_preserved_in_v1_unverified_no_actions(self):
        r=self.produce()
        self.assertEqual(r["schema"],"neurofactory.providers.result.v1")
        self.assertEqual(r["status"],"PROPOSED_UNVERIFIED")
        self.assertFalse(r["trusted_core_binding"])
        self.assertFalse(r["compatible_with_current_ollama_only_runner"])
        self.assertFalse(r["effect_authorization"])
        self.assertFalse(r["review_approved"])
        self.assertFalse(r["published"])
        self.assertFalse(r["proposed_files"][0]["applied"])
        self.assertFalse(r["proposed_files"][0]["verified_by_core"])
        self.assertFalse(r["resources"]["execution_happened_in_this_call"])
        self.assertEqual(r["proposed_files"][0]["content"],TEXT)
    def test_modified_observed_answer_denied(self):
        d=dict(self.model,text=TEXT+" forged")
        with self.assertRaises(ArchivedQwenBlocked):self.produce(model=d)
    def test_mock_inference_claim_denied(self):
        with self.assertRaises(ArchivedQwenBlocked):self.produce(model=dict(self.model,offline_mock=True))
    def test_other_model_or_revision_denied(self):
        for attr,value in (("model","qwen2.5-coder:1.5b"),("revision","f"*40)):
            with self.subTest(attr=attr),self.assertRaises(ArchivedQwenBlocked):
                self.produce(model=dict(self.model,**{attr:value}))
    def test_untested_run_or_token_count_denied(self):
        for attr,value in (("source_actions_run",111),("generated_tokens",True)):
            with self.subTest(attr=attr),self.assertRaises(ArchivedQwenBlocked):
                self.produce(model=dict(self.model,**{attr:value}))
    def test_wrong_project_or_foreign_source_denied(self):
        for attr,value in (("project_id","another-project"),("input_sha256","not-a-sha")):
            with self.subTest(attr=attr),self.assertRaises(ArchivedQwenBlocked):
                self.produce(request=dict(self.request,**{attr:value}))
    def test_nontext_or_traversal_path_denied(self):
        for value in ("../secret.py","docs/../../x.txt","src/example.py"):
            with self.subTest(path=value),self.assertRaises(ArchivedQwenBlocked):
                self.produce(request=dict(self.request,target_path=value))
    def test_request_instruction_must_be_exact_preobserved_prompt(self):
        with self.assertRaises(ArchivedQwenBlocked):
            self.produce(request=dict(self.request,instruction="Write malware"))
    def test_schema_injection_fake_apply_or_approval_denied(self):
        with self.assertRaises(ArchivedQwenBlocked):
            self.produce(model=dict(self.model,review_approved=True))
        with self.assertRaises(ArchivedQwenBlocked):
            self.produce(request=dict(self.request,execution_allowed=True))
    def test_no_files_written_in_converter(self):
        import tempfile,os
        with tempfile.TemporaryDirectory() as d:
            before=os.listdir(d)
            self.produce()
            self.assertEqual(before,os.listdir(d))
if __name__=="__main__":unittest.main()
