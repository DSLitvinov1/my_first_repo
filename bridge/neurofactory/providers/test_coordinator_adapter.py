"""Targeted tests of the new coordinator schema translation (offline only)."""
import copy
from hashlib import sha256
import json
import unittest

import coordinator_adapter as a


class CoordinatorBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.proposal = {
            "task_id": "NF-DEV-05-Q123",
            "project_id": "study-project",
            "target": "bridge/neurofactory/development/core_owned/sandbox_demo.py",
            "objective": "Create a harmless function returning the sum of two integers.",
            "source_sha": "a" * 40,
            "source_sha256": "b" * 64,
            "model": "qwen2.5-coder:1.5b",
            "reserved_units": 5000
        }
        self.request = {
            "task_id": self.proposal["task_id"],
            "source_sha": self.proposal["source_sha"],
            "model": self.proposal["model"],
            "budget_units": self.proposal["reserved_units"],
            "local_only": True,
            "purpose": "CORE_SANDBOX_PROPOSAL"
        }

    def payload(self, proposal=None, prepared=None):
        return json.dumps({
            "schema": "neurofactory.providers.coordinator_pair.v1",
            "proposal": self.proposal if proposal is None else proposal,
            "prepared_request": self.request if prepared is None else prepared
        }).encode()

    def test_translation_preserves_identity_and_scope(self):
        result = a.parse_coordinator_pair(self.payload())
        self.assertEqual(result.task.task_id, "NF-DEV-05-Q123")
        self.assertEqual(result.task.target_path, self.proposal["target"])
        self.assertEqual(result.source_sha, "a"*40)
        self.assertEqual(result.model, self.proposal["model"])
        self.assertEqual(result.max_reserved_units, 5000)

    def test_coordinator_request_tampered_task_rejected(self):
        prepared = dict(self.request, task_id="NF-DEV-05-Q124")
        with self.assertRaises(ValueError): a.parse_coordinator_pair(self.payload(prepared=prepared))

    def test_coordinator_source_mismatch_rejected(self):
        prepared = dict(self.request, source_sha="c"*40)
        with self.assertRaises(ValueError): a.parse_coordinator_pair(self.payload(prepared=prepared))

    def test_untrusted_foreign_path_rejected(self):
        proposal = dict(self.proposal, target="src/other.py")
        with self.assertRaises(ValueError): a.parse_coordinator_pair(self.payload(proposal=proposal))

    def test_bad_model_or_budget_rejected(self):
        for change in ({"model":"cloud-inference"},{"reserved_units":50},{"reserved_units":True}):
            with self.subTest(change=change):
                proposal = dict(self.proposal, **change)
                with self.assertRaises(ValueError): a.parse_coordinator_pair(self.payload(proposal=proposal))

    def test_duplicate_json_field_rejected(self):
        raw=self.payload().replace(b'"model":',b'"model": "forged", "model":',1)
        with self.assertRaises(ValueError):a.parse_coordinator_pair(raw)

    def test_successful_candidate_only_unverified_text(self):
        candidate=a.parse_coordinator_pair(self.payload())
        content="def add(a, b):\n    return a+b\n"
        source={
            "status":"PROPOSED_UNVERIFIED","task_id":candidate.task.task_id,
            "project_id":candidate.task.project_id,
            "input_sha256":candidate.task.input_sha256,
            "model":candidate.model,"provider":"ollama-loopback",
            "offline_mock":False,"published":False,"review_approved":False,
            "proposed_files":[{
                "relative_path":candidate.task.target_path,
                "content":content,
                "content_sha256":sha256(content.encode()).hexdigest(),
                "applied":False,"verified_by_core":False}]
        }
        result=a.coordinator_result(candidate,source)
        self.assertEqual(result["source_sha"],"a"*40)
        self.assertEqual(result["text"],content)
        self.assertFalse(result["published"])
        self.assertEqual(result["mode"],"local")

        forged=copy.deepcopy(source)
        forged["proposed_files"][0]["content"]="malicious modification"
        with self.assertRaises(ValueError):a.coordinator_result(candidate,forged)

        mocked=copy.deepcopy(source)
        mocked["offline_mock"]=True
        with self.assertRaises(ValueError):a.coordinator_result(candidate,mocked)

    def test_truncated_or_invalid_schema_rejected(self):
        for raw in (b"",b'{}',b'{"schema":',b"x"*16385):
            with self.subTest(length=len(raw)):
                with self.assertRaises(ValueError):a.parse_coordinator_pair(raw)


if __name__=="__main__":
    unittest.main()
