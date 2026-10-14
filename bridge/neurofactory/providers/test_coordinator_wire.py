"""Targeted negative tests against coordinator's current v1 provider-wire packet."""
import copy
import json
import unittest

import coordinator_adapter as adapter


class CoordinatorWireTests(unittest.TestCase):
    def setUp(self):
        self.packet = {
            "schema": "neurofactory.coordination.provider_bridge.v1",
            "request": {
                "schema": "neurofactory.providers.request.v1",
                "task_id": "NF-DEV-05-Q123",
                "project_id": "study-project",
                "input_sha256": "b" * 64,
                "target_path": "src/generated.py",
                "instruction": "Implement a harmless function returning the sum of two numbers.",
            },
            "binding": {
                "task_id": "NF-DEV-05-Q123",
                "project_id": "study-project",
                "source_sha": "a" * 40,
                "source_sha256": "c" * 64,
                "core_target": "bridge/neurofactory/development/core_owned/sandbox_demo.py",
                "provider_target": "src/generated.py",
                "model": "qwen2.5-coder:1.5b",
                "input_sha256": "b" * 64,
            },
            "permissions": {"execution": False, "retry": False,
                            "publication": False, "paid_api": False},
        }

    def parse(self, packet=None, units=5000):
        return adapter.parse_new_coordinator_wire(
            json.dumps(self.packet if packet is None else packet).encode(),
            trusted_budget_units=units)

    def test_current_coordinator_wire_translates_without_side_effects(self):
        result = self.parse()
        self.assertEqual(result.task.task_id, "NF-DEV-05-Q123")
        self.assertEqual(result.task.target_path, "src/generated.py")
        self.assertEqual(result.source_sha, "a" * 40)
        self.assertEqual(result.model, "qwen2.5-coder:1.5b")

    def test_executable_permission_is_rejected(self):
        data=copy.deepcopy(self.packet)
        data["permissions"]["execution"] = True
        with self.assertRaises(ValueError):self.parse(data)

    def test_mismatched_input_sha_is_rejected(self):
        data=copy.deepcopy(self.packet)
        data["request"]["input_sha256"] = "0" * 64
        with self.assertRaises(ValueError):self.parse(data)

    def test_foreign_core_scope_is_rejected(self):
        data=copy.deepcopy(self.packet)
        data["binding"]["core_target"] = "bridge/neurofactory/review_owned/test.py"
        with self.assertRaises(ValueError):self.parse(data)

    def test_foreign_provider_scope_is_rejected(self):
        data=copy.deepcopy(self.packet)
        data["request"]["target_path"] = data["binding"]["provider_target"] = "../test.py"
        with self.assertRaises(ValueError):self.parse(data)

    def test_untrusted_budget_rejected(self):
        with self.assertRaises(ValueError):self.parse(units=100)
        with self.assertRaises(ValueError):self.parse(units=True)

    def test_duplicate_json_fields_rejected(self):
        packet=json.dumps(self.packet)
        duplicate=packet.replace('"schema":', '"schema":"forged","schema":',1)
        with self.assertRaises(ValueError):
            adapter.parse_new_coordinator_wire(duplicate.encode(),trusted_budget_units=5000)

    def test_unknown_extra_permission_rejected(self):
        data=copy.deepcopy(self.packet)
        data["permissions"]["send_email"] = False
        with self.assertRaises(ValueError):self.parse(data)


if __name__ == "__main__":
    unittest.main()
