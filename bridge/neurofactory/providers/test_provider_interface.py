"""Only new CORE input boundary tests; no model process or external calls."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import provider_interface as i
import ollama_worker as worker


class CoreBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.payload = json.dumps({
            "schema": worker.SCHEMA_REQUEST,
            "task_id": "provider-task-once",
            "project_id": "approved-study",
            "input_sha256": "a" * 64,
            "target_path": "src/example.py",
            "instruction": "Implement a self-contained add function.",
        }).encode("utf-8")

    def test_valid_task_is_parsed(self):
        self.assertEqual(i.parse_core_request(self.payload).task_id, "provider-task-once")

    def test_json_duplicate_keys_rejected(self):
        bad = self.payload.decode().replace(
            '"task_id":', '"task_id":"forged", "task_id":')
        with self.assertRaises(i.InvalidCoreRequest):
            i.parse_core_request(bad.encode())

    def test_unapproved_caller_rejected_before_any_model(self):
        with patch.object(i, "execute_one") as model:
            with self.assertRaises(PermissionError):
                i.produce_unverified_result(self.payload, ledger_dir=Path("."))
            model.assert_not_called()

    def test_bad_type_and_size_rejected(self):
        for payload in (None, {}, b"", b"x" * 8193):
            with self.subTest(kind=type(payload)):
                with self.assertRaises(i.InvalidCoreRequest):
                    i.parse_core_request(payload)

    def test_unknown_schema_field_rejected(self):
        obj = json.loads(self.payload)
        obj["approved"] = True
        with self.assertRaises(i.InvalidCoreRequest):
            i.parse_core_request(json.dumps(obj).encode())

    def test_explicit_trusted_call_passes_only_validated_dataclass(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(i, "execute_one", return_value={"status": "BLOCKED"}) as run:
                result = i.produce_unverified_result(
                    self.payload, trusted_core_call=True, ledger_dir=Path(tmp))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIs(type(run.call_args.args[0]), worker.ProviderTask)


if __name__ == "__main__":
    unittest.main()
