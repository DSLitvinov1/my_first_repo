"""Isolated tests: no Ollama, GitHub, filesystem, network or queue access."""
import hashlib
import unittest
from mvp_provider_wire import WireError, make_request, summarize_reply

def proposal():
    return {"task_id":"NF-DEV-05-Q001", "project_id":"nf-sandbox",
            "target":"bridge/neurofactory/development/core_owned/sample.py",
            "objective":"Write one harmless deterministic function in a sandbox Python file.",
            "source_sha":"a"*40, "source_sha256":"a"*64,
            "model":"qwen3:4b","reserved_units":2048}

def mapped():
    return make_request(proposal(),provider_path="src/sample.py",
                        trusted_input_digest="b"*64,
                        trusted_mapping_verifier=lambda b,r:True)

def reply():
    content="def safe():\n    return 1\n"
    return {"schema":"neurofactory.providers.result.v1",
            "status":"PROPOSED_UNVERIFIED",
            "task_id":"NF-DEV-05-Q001","project_id":"nf-sandbox",
            "input_sha256":"b"*64,"model":"qwen3:4b",
            "provider":"ollama-loopback","offline_mock":False,
            "api_cost_usd":0,"review_approved":False,"published":False,
            "proposed_files":[{"relative_path":"src/sample.py","content":content,
                               "content_sha256":hashlib.sha256(content.encode()).hexdigest(),
                               "applied":False,"verified_by_core":False}],
            "response_sha256":"c"*64,"prompt_sha256":"d"*64,
            "error_code":None,"attempt_consumed":True,
            "observed_local_reply":True,"resources":{"free_ram_bytes":10**10}}

class ProviderWireTests(unittest.TestCase):
    def test_compatible_request_exact_schema(self):
        p=mapped()
        self.assertEqual(set(p["request"]),{"schema","task_id","project_id","input_sha256",
                                              "target_path","instruction"})
        self.assertFalse(p["permissions"]["execution"])
        self.assertFalse(p["permissions"]["paid_api"])
        self.assertEqual(p["binding"]["source_sha"],"a"*40)
        self.assertEqual(p["request"]["input_sha256"],"b"*64)

    def test_no_unauthenticated_mapping(self):
        with self.assertRaises(WireError):
            make_request(proposal(),provider_path="src/sample.py",
                         trusted_input_digest="b"*64)
        with self.assertRaises(WireError):
            make_request(proposal(),provider_path="src/sample.py",
                         trusted_input_digest="b"*64,
                         trusted_mapping_verifier=lambda b,r:"APPROVED")

    def test_traversal_and_outside_path_rejected(self):
        for target in ("../src/sample.py","src/../sample.py","src/.hidden.py",
                       "/src/sample.py","docs/file.exe"):
            with self.subTest(target=target),self.assertRaises(WireError):
                make_request(proposal(),provider_path=target,trusted_input_digest="b"*64,
                             trusted_mapping_verifier=lambda b,r:True)

    def test_foreign_input_snapshot_rejected(self):
        with self.assertRaises(WireError):
            make_request(proposal(),provider_path="src/sample.py",trusted_input_digest="main",
                         trusted_mapping_verifier=lambda b,r:True)

    def test_honest_proposal_only_unverified(self):
        receipt=summarize_reply(mapped(),reply())
        self.assertEqual(receipt["status"],"RESPONSE_UNVERIFIED")
        self.assertEqual(receipt["source_sha"],"a"*40)
        self.assertNotIn("content",receipt)
        self.assertFalse(receipt["source_verified"])
        self.assertFalse(receipt["publication_allowed"])

    def test_mismatch_task_and_input_and_model(self):
        for key,val in (("task_id","NF-DEV-05-Q002"),("input_sha256","f"*64),
                        ("model","gpt-cloud"),("project_id","wrong")):
            result=reply()
            result[key]=val
            with self.subTest(key=key),self.assertRaises(WireError):
                summarize_reply(mapped(),result)

    def test_spoofed_approvals_cost_or_publication_rejected(self):
        for key,val in (("review_approved",True),("published",True),
                        ("offline_mock",True),("api_cost_usd",2),("api_cost_usd",False)):
            result=reply()
            result[key]=val
            with self.subTest(key=key),self.assertRaises(WireError):
                summarize_reply(mapped(),result)

    def test_forged_path_and_digest_rejected(self):
        for key,val in (("relative_path","src/other.py"),
                        ("content_sha256","f"*64),("applied",True),
                        ("verified_by_core",True)):
            result=reply()
            result["proposed_files"][0][key]=val
            with self.subTest(key=key),self.assertRaises(WireError):
                summarize_reply(mapped(),result)

    def test_unknown_result_blocked_without_retry(self):
        result=reply()
        result.update(status="BLOCKED",error_code="UNKNOWN_INFERENCE",
                      proposed_files=[],response_sha256=None)
        x=summarize_reply(mapped(),result)
        self.assertEqual(x["status"],"BLOCKED")
        self.assertFalse(x["automatic_retry_allowed"])
        self.assertFalse(x["publication_allowed"])
        self.assertFalse(x["source_verified"])

    def test_unknown_with_hidden_proposed_file_rejected(self):
        result=reply()
        result.update(status="BLOCKED",error_code="UNKNOWN_INFERENCE")
        with self.assertRaises(WireError):
            summarize_reply(mapped(),result)

    def test_invalid_model_output_blocks_safely(self):
        result=reply()
        result.update(status="INVALID_MODEL_OUTPUT",error_code="UNVERIFIED_RESPONSE_FORMAT",
                      proposed_files=[])
        self.assertEqual(summarize_reply(mapped(),result)["status"],"BLOCKED")

    def test_provider_does_not_get_rights_from_extra_fields(self):
        result=reply()
        result["release_allowed"]=True
        with self.assertRaises(WireError):
            summarize_reply(mapped(),result)

if __name__=="__main__":
    unittest.main()
