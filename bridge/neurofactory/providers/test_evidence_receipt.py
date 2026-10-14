"""Targeted evidence tests: fake Ollama replies are explicitly TEST FIXTURES.

No case below is a real Qwen inference or independent provenance signoff.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import evidence_receipt as e
import ollama_worker as worker
import local_qwen


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="nf-provider-evidence-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.ledger = self.root / "ledger"
        self.ledger.mkdir(mode=0o700)
        self.model = "qwen2.5-coder:1.5b"
        self.task = worker.ProviderTask(
            task_id="NF-DEV-05-Q314", project_id="study-project",
            input_sha256="a" * 64, target_path="src/example.py",
            instruction="Write a self-contained function that returns a plus b.")

    def put(self, **kwargs):
        data = {
            "task_id": self.task.task_id, "project_id": self.task.project_id,
            "input_sha256": self.task.input_sha256, "prompt_sha256": "b" * 64,
            "model": self.model, "response_text": "def f(a,b): return a+b",
            "elapsed_ms": 123
        }
        data.update(kwargs)
        return e.persist_model_evidence(self.private, **data)

    def fake_http_reply(self, answer=None):
        if answer is None:
            answer = json.dumps({
                "path": "src/example.py", "content": "def add(a,b): return a+b"
            })
        return json.dumps({
            "model": self.model, "done": True, "response": answer,
            "done_reason": "stop"
        }).encode()

    def generate_with_test_fixture(self, answer=None):
        with patch.object(worker, "check_resources",
                          return_value={"free_ram_bytes": 4 * worker.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post",
                              return_value=self.fake_http_reply(answer)) as send:
                result = worker.execute_one(
                    self.task, model=self.model, ledger_dir=self.ledger,
                    evidence_dir=self.private)
        return result, send.call_count

    def test_record_keeps_exact_raw_text_and_sha_and_false_claims(self):
        answer = 'Привет, Qwen — text with newline\nline two'
        record = self.put(response_text=answer)
        self.assertEqual(record["response_sha256"], sha256(answer.encode()).hexdigest())
        meta = e.verify_model_evidence(self.private, self.task.task_id)
        self.assertEqual(meta, record)
        raw = (self.private / record["evidence_filename"]).read_text()
        data = json.loads(raw)
        self.assertEqual(data["response_text"], answer)
        self.assertFalse(data["independent_provenance_verified"])
        self.assertFalse(data["review_approved"])
        self.assertFalse(data["source_applied"])
        self.assertFalse(data["published"])
        self.assertEqual(data["input_sha256"], "a" * 64)

    def test_write_once_prevents_overwrite_and_replay(self):
        first = self.put()
        original = (self.private / first["evidence_filename"]).read_bytes()
        with self.assertRaises(e.EvidenceError):
            self.put(response_text="forged second model answer")
        self.assertEqual((self.private / first["evidence_filename"]).read_bytes(), original)

    def test_tampered_response_fails_readback(self):
        record = self.put()
        path = self.private / record["evidence_filename"]
        path.write_text(path.read_text().replace("def f(a,b)", "def z(a,b)"))
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.private, self.task.task_id)

    def test_duplicate_json_key_rejected_on_verify(self):
        record = self.put()
        path = self.private / record["evidence_filename"]
        raw = path.read_text().replace('"schema":', '"schema":"forged","schema":', 1)
        path.write_text(raw)
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.private, self.task.task_id)

    def test_symlink_directory_rejected(self):
        alias = self.root / "symlink"
        try:
            alias.symlink_to(self.private, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink privilege unavailable")
        with self.assertRaises(e.EvidenceError):
            e.persist_model_evidence(alias, task_id=self.task.task_id,
                project_id=self.task.project_id, input_sha256="a" * 64,
                prompt_sha256="b" * 64, model=self.model,
                response_text="test", elapsed_ms=1)

    def test_public_directory_rejected_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions only")
        shared = self.root / "world-readable"
        shared.mkdir(mode=0o755)
        with self.assertRaises(e.EvidenceError):
            e.check_evidence_directory(shared)

    def test_actual_worker_path_writes_one_unverified_test_receipt(self):
        result, calls = self.generate_with_test_fixture()
        self.assertEqual(calls, 1)
        self.assertEqual(result["status"], "PROPOSED_UNVERIFIED")
        self.assertFalse(result["review_approved"])
        self.assertEqual(result["model"], self.model)
        meta = e.verify_model_evidence(self.private, self.task.task_id)
        self.assertEqual(result["response_sha256"], meta["response_sha256"])
        self.assertEqual(result["prompt_sha256"],
                         json.loads((self.private / meta["evidence_filename"]).read_text())["prompt_sha256"])
        self.assertFalse((self.root / "src" / "example.py").exists())

    def test_inference_duplicate_id_does_not_call_http_again(self):
        answer = self.fake_http_reply()
        with patch.object(worker, "check_resources",
                          return_value={"free_ram_bytes": 4 * worker.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post", return_value=answer) as send:
                first = worker.execute_one(self.task, model=self.model,
                                           ledger_dir=self.ledger, evidence_dir=self.private)
                second = worker.execute_one(self.task, model=self.model,
                                            ledger_dir=self.ledger, evidence_dir=self.private)
        self.assertEqual(first["status"], "PROPOSED_UNVERIFIED")
        self.assertEqual(second["status"], "BLOCKED")
        self.assertEqual(send.call_count, 1)
        self.assertEqual(self.ledger.joinpath("reservations.json").is_file(), True)

    def test_evidence_failure_after_inference_stops_and_does_not_retry(self):
        with patch.object(worker, "check_resources", return_value={"free_ram_bytes": 4 * worker.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post",
                              return_value=self.fake_http_reply()) as send:
                with patch.object(worker, "persist_model_evidence",
                                  side_effect=e.EvidenceError("disk full")):
                    first = worker.execute_one(self.task, model=self.model,
                                               ledger_dir=self.ledger, evidence_dir=self.private)
                second = worker.execute_one(self.task, model=self.model,
                                            ledger_dir=self.ledger, evidence_dir=self.private)
        self.assertEqual(first["status"], "BLOCKED")
        self.assertEqual(first["error_code"], "UNKNOWN_EVIDENCE_WRITE")
        self.assertTrue(first["attempt_consumed"])
        self.assertEqual(second["status"], "BLOCKED")
        self.assertEqual(send.call_count, 1)

    def test_invalid_model_json_keeps_exact_invalid_response_for_review(self):
        result, count = self.generate_with_test_fixture("not a JSON object")
        self.assertEqual(result["status"], "INVALID_MODEL_OUTPUT")
        self.assertEqual(count, 1)
        record = e.verify_model_evidence(self.private, self.task.task_id)
        self.assertEqual(record["response_sha256"], sha256(b"not a JSON object").hexdigest())

    def test_untrusted_evidence_directory_blocks_before_inference(self):
        absent = self.root / "does-not-exist"
        with patch.object(worker, "check_resources",
                          return_value={"free_ram_bytes": 4 * worker.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post") as transport:
                blocked = worker.execute_one(self.task, model=self.model,
                                             ledger_dir=self.ledger, evidence_dir=absent)
                transport.assert_not_called()
        self.assertEqual(blocked["status"], "BLOCKED")
        self.assertFalse(blocked["attempt_consumed"])

    def test_invalid_task_id_rejected(self):
        with self.assertRaises(e.EvidenceError):
            e.evidence_name("../../outside")
        with self.assertRaises(e.EvidenceError):
            self.put(task_id="../../outside")

    def test_cli_requires_unique_task_id_before_preflight(self):
        with patch.object(worker, "check_resources") as preflight:
            with self.assertRaises(SystemExit):
                worker.main(["--safe-smoke", "--model", self.model])
            preflight.assert_not_called()

    def test_readback_missing_file_is_not_a_success(self):
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.private, self.task.task_id)


if __name__ == "__main__":
    unittest.main()
