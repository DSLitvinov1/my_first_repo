"""Targeted tests only for new local Ollama worker and real-path guardrails.

Ollama HTTP is replaced by a loopback fixture; these are NOT real model tests.
"""
import json
import tempfile
import threading
import unittest
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import local_qwen
import ollama_worker as w


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nf-provider-worker-")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.task = w.ProviderTask(
            task_id="provider-task-001", project_id="study-sandbox",
            input_sha256="a" * 64, target_path="src/example.py",
            instruction="Implement add(a,b), returning a+b.")
        self.model = "qwen2.5-coder:1.5b"

    def good_reply(self, content="def add(a, b):\n    return a + b\n"):
        return json.dumps({
            "done": True, "model": self.model,
            "response": json.dumps({"path": "src/example.py", "content": content}),
            "done_reason": "stop",
        }).encode("utf-8")

    def test_compact_previously_installed_qwen_allowed(self):
        self.assertIn(self.model, local_qwen.ALLOWED_MODELS)

    def test_target_traversal_rejected(self):
        for candidate in ("../x.py", "src/../main.py", "/etc/a.py",
                          "src\\evil.py", "src/.hidden.py", "src//double.py", "other/hi.py"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    w.validate_target(candidate)

    def test_unknown_request_fields_blocked(self):
        data = dict(schema=w.SCHEMA_REQUEST, task_id="ok",
                    project_id="ok", input_sha256="b" * 64,
                    target_path="src/ok.py", instruction="write simple code",
                    privilege="write")
        with self.assertRaises(ValueError):
            w.ProviderTask.from_json(data)

    def test_model_not_installed_stops_before_reservation(self):
        with patch.object(w, "installed_model_info",
                          side_effect=w.PreflightBlocked("BLOCKED_MODEL_NOT_INSTALLED")):
            with patch.object(local_qwen, "_loopback_post") as inference:
                r = w.execute_one(self.task, model=self.model, ledger_dir=self.folder)
        self.assertEqual(r["error_code"], "BLOCKED_MODEL_NOT_INSTALLED")
        self.assertFalse(r["attempt_consumed"])
        self.assertFalse((self.folder / "reservations.json").exists())
        inference.assert_not_called()

    def test_low_ram_blocks_before_reservation(self):
        with patch.object(w, "installed_model_info",
                          return_value={"model": self.model, "model_disk_bytes": 1_000_000_000}):
            with patch.object(w, "physical_free_memory_bytes", return_value=1024):
                with self.assertRaises(w.PreflightBlocked) as ctx:
                    w.check_resources(self.model)
        self.assertEqual(ctx.exception.code, "BLOCKED_RESOURCE")

    def test_low_ram_short_circuits_ollama_tags(self):
        with patch.object(w, "physical_free_memory_bytes", return_value=515497984):
            with patch.object(w, "installed_model_info") as tags:
                with self.assertRaises(w.PreflightBlocked) as error:
                    w.check_resources(self.model)
                self.assertEqual(error.exception.code, "BLOCKED_RESOURCE")
                tags.assert_not_called()

    def test_success_proposal_is_not_approved_or_written(self):
        with patch.object(w, "check_resources",
                          return_value={"model": self.model, "free_ram_bytes": 4 * w.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post",
                              return_value=self.good_reply()) as call:
                r = w.execute_one(self.task, model=self.model, ledger_dir=self.folder)
        self.assertEqual(r["status"], "PROPOSED_UNVERIFIED")
        self.assertTrue(r["observed_local_reply"])
        self.assertFalse(r["review_approved"])
        self.assertFalse(r["published"])
        self.assertEqual(r["api_cost_usd"], 0)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(r["proposed_files"][0]["relative_path"], "src/example.py")
        self.assertFalse(r["proposed_files"][0]["applied"])
        self.assertEqual(
            r["proposed_files"][0]["content_sha256"],
            sha256(r["proposed_files"][0]["content"].encode()).hexdigest())
        self.assertFalse((self.folder / "src" / "example.py").exists())

    def test_replay_same_task_inhibits_second_http_request(self):
        with patch.object(w, "check_resources",
                          return_value={"model": self.model, "free_ram_bytes": 4 * w.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post",
                              return_value=self.good_reply()) as call:
                first = w.execute_one(self.task, model=self.model, ledger_dir=self.folder)
                again = w.execute_one(self.task, model=self.model, ledger_dir=self.folder)
        self.assertEqual(first["status"], "PROPOSED_UNVERIFIED")
        self.assertEqual(again["status"], "BLOCKED")
        self.assertEqual(again["error_code"], "BLOCKED_DUPLICATE_OR_LEDGER")
        self.assertEqual(call.call_count, 1)

    def test_reply_target_escaping_is_rejected(self):
        with self.assertRaises(ValueError):
            w._safe_proposal(json.dumps({"path": "src/../evil.py", "content": "X"}),
                             "src/example.py")

    def test_bad_json_retains_proof_only_of_stub_response(self):
        with patch.object(w, "check_resources",
                          return_value={"model": self.model, "free_ram_bytes": 4 * w.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post",
                              return_value=self.good_reply(content="abc")):
                r = w.execute_one(self.task, model=self.model, ledger_dir=self.folder)
        self.assertEqual(r["status"], "PROPOSED_UNVERIFIED")
        self.assertEqual(r["proposed_files"][0]["content"], "abc")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            w._safe_proposal('{"path":"src/example.py","path":"src/example.py","content":"x"}',
                             "src/example.py")

    def test_invalid_model_proposal_keeps_response_digest(self):
        invalid = json.dumps({"model": self.model, "response": "not json", "done": True}).encode()
        with patch.object(w, "check_resources",
                          return_value={"model": self.model, "free_ram_bytes": 4 * w.ONE_GIB}):
            with patch.object(local_qwen, "_loopback_post", return_value=invalid):
                r = w.execute_one(self.task, model=self.model, ledger_dir=self.folder)
        self.assertEqual(r["status"], "INVALID_MODEL_OUTPUT")
        self.assertIsNotNone(r["response_sha256"])
        self.assertTrue(r["observed_local_reply"])
        self.assertFalse(r["proposed_files"])

    def test_tags_http_loopback_fixture(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/api/tags":
                    self.send_error(404)
                    return
                data = json.dumps({"models": [{"name": "qwen2.5-coder:1.5b",
                                                "size": 1_000_000_000}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(w, "TAGS_URL",
                              f"http://127.0.0.1:{server.server_port}/api/tags"):
                actual = w.installed_model_info(self.model)
                self.assertEqual(actual["model_disk_bytes"], 1_000_000_000)
                with self.assertRaises(w.PreflightBlocked) as ctx:
                    w.installed_model_info("qwen3:4b")
                self.assertEqual(ctx.exception.code, "BLOCKED_MODEL_NOT_INSTALLED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_real_environment_diagnosis_does_not_call_inference(self):
        with patch.object(w, "installed_model_info",
                          side_effect=w.PreflightBlocked("BLOCKED_OLLAMA_UNAVAILABLE")):
            with patch.object(local_qwen, "_loopback_post") as inference:
                with self.assertRaises(w.PreflightBlocked):
                    w.check_resources(self.model)
            inference.assert_not_called()


if __name__ == "__main__":
    unittest.main()
