"""Read-only regression tests; cannot issue LIVE approval."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from deployment_readiness_preflight import (
    CORE_CLIENT, HOST_FILES, HOST_FOLDER, SCHEMA,
    _read_bounded_source, inspect_deployment_readiness,
)

REPO = Path(__file__).resolve().parents[3]


class DeploymentPreflightTests(unittest.TestCase):
    def test_actual_current_source_is_explicitly_blocked_as_fixture(self):
        x = inspect_deployment_readiness(REPO)
        self.assertEqual(x["schema"], SCHEMA)
        self.assertEqual(x["status"], "BLOCKED_EXTERNAL_ATTESTATION_REQUIRED")
        self.assertIn("FINAL_RECEIVER_IS_EXPLICITLY_FIXTURE_ONLY", x["source_blockers"])
        self.assertIn("FINAL_RECEIVER_USES_DISPOSABLE_TEST_DATABASE", x["source_blockers"])
        self.assertIn("SIGNER_IS_EXPLICITLY_FIXTURE_ONLY", x["source_blockers"])
        self.assertIn("JOURNAL_IS_EXPLICITLY_FIXTURE_ONLY", x["source_blockers"])
        self.assertGreaterEqual(len(x["source_sha256"]), len(HOST_FILES))
        # HOST owner branch may intentionally omit CORE's separate lane.
        if str(CORE_CLIENT) not in x["source_sha256"]:
            self.assertIn("REQUIRED_CORE_SIGNED_CLIENT_UNAVAILABLE",
                          x["source_blockers"])
        self.assertEqual(len(x["git_head_observed"]), 40)

    def test_every_release_or_install_permission_stays_false(self):
        x = inspect_deployment_readiness(REPO, check_local_host=False)
        self.assertIsNone(x["local_environment"]["linux"])
        for k in ("physical_linux_server_authorized",
                  "production_keys_provisioned",
                  "signed_owner_rights_independently_attested",
                  "second_physical_node_confirmed",
                  "actual_full_kernel_reboot_checked",
                  "independent_review_signed",
                  "reboot_allowed", "can_install", "can_start_services",
                  "can_publish", "live_execution_allowed", "release_approved"):
            self.assertIs(x[k], False, k)
        self.assertTrue(all(v == "NOT_EXTERNALLY_VERIFIED"
                            for v in x["gate_status"].values()))
        self.assertTrue(x["no_files_written"])
        self.assertFalse(x["secrets_inspected_or_exported"])

    def test_forged_external_evidence_file_does_not_grant_approval(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "owner-approval.json").write_text(
                json.dumps({"release_approved": True, "actual_two_nodes": True,
                            "owner_is_authenticated": True}), encoding="utf-8")
            result = inspect_deployment_readiness(base)
            self.assertFalse(result["release_approved"])
            self.assertFalse(result["can_install"])
            self.assertIn("REQUIRED_CORE_SIGNED_CLIENT_UNAVAILABLE",
                          result["source_blockers"])

    def test_fail_closed_on_missing_sources_and_non_git_dir(self):
        with tempfile.TemporaryDirectory() as root:
            v = inspect_deployment_readiness(Path(root))
            self.assertIsNone(v["git_head_observed"])
            self.assertIn("EXACT_GIT_COMMIT_NOT_AVAILABLE", v["source_blockers"])
            self.assertTrue(any(s.startswith("REQUIRED_HOST_SOURCE_UNAVAILABLE:")
                                for s in v["source_blockers"]))

    def test_symlink_and_empty_sources_are_never_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            (d / "blank.py").write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                _read_bounded_source(d / "blank.py")
            (d / "source.py").write_text("print('offline only')", encoding="utf-8")
            (d / "alias.py").symlink_to(d / "source.py")
            with self.assertRaises(ValueError):
                _read_bounded_source(d / "alias.py")
            self.assertEqual(len(_read_bounded_source(d / "source.py")[1]), 64)

    def test_no_reliance_on_windows_for_linux_attestation(self):
        with patch("deployment_readiness_preflight.platform.system",
                   return_value="Windows"):
            r = inspect_deployment_readiness(REPO)
            self.assertIn("CURRENT_ENVIRONMENT_IS_NOT_LINUX", r["source_blockers"])
            self.assertIs(r["local_environment"]["linux"], False)
            self.assertFalse(r["actual_full_kernel_reboot_checked"])

    def test_cli_never_returns_success_or_exports_key(self):
        p = subprocess.run(
            [sys.executable, "-B", str(REPO / HOST_FOLDER /
                                       "deployment_readiness_preflight.py"),
             "--repository", str(REPO)],
            capture_output=True, text=True, timeout=12)
        self.assertEqual(p.returncode, 2)
        output = json.loads(p.stdout)
        self.assertFalse(output["release_approved"])
        self.assertFalse(output["can_install"])
        self.assertNotIn("private_key", p.stdout.lower())
        self.assertNotIn("authorization_token", p.stdout.lower())
        self.assertNotIn("BEGIN PRIVATE KEY", p.stdout)


if __name__ == "__main__":
    unittest.main()
