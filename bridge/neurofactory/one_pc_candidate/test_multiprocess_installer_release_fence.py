"""One-PC prerelease installer authority separation regression.

Does NOT compile/reinstall anything. Existing installer is verified by prior
unchanged Windows Actions; this test proves new isolated IPC/operator sources
are NOT included in the unprivileged per-user installer. An installer with
built-in signing or CORE pipe authority would violate the trust boundary.
"""
from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
ONE = ROOT / "bridge/neurofactory/one_pc_candidate"


class ExistingInstallerAuthorityBoundary(unittest.TestCase):
    def test_existing_inno_per_user_installer_excludes_trusted_signer_and_ipc(self):
        text = (ONE / "windows_setup/NeurofactoryLocalDraft.iss").read_text(
            encoding="utf-8-sig")
        self.assertRegex(text, r"(?mi)^PrivilegesRequired=lowest\s*$")
        self.assertRegex(text, r"(?mi)^OutputBaseFilename=Neurofactory-Local-Draft-Setup$")
        files = text.split("[Files]", 1)[1].split("[Icons]", 1)[0]
        self.assertIn("local_workspace.py", files)
        self.assertIn("signed_owner_admission.py", files)
        privileged = (
            "windows_owner_controller_candidate.py",
            "windows_owner_offline_cli.py",
            "windows_core_admission_ipc_ci.py",
            "windows_core_admission_client_process_ci.py",
            "test_windows_core_admission_ipc_ci.py",
            "windows_scm_sandbox_receiver.py",  # pinned *component* allowed only
            "windows_scm_core_admission_ci.py",  # NEW private SCM cannot enter UI
            "test_windows_scm_core_admission_ci.py",
        )
        # Explicitly refuse privileged modules inside app (including a
        # recursive wildcard). Pinned read-only *components* have a separate
        # manifest requiring all authority flags false.
        app_sources = [
            x for x in files.splitlines()
            if re.search(r'(?i)DestDir:.*\{app\}\\app', x)
        ]
        self.assertTrue(app_sources)
        for line in app_sources:
            self.assertNotRegex(line, r'(?i)Source:[^\n]*\\app\\\*')
            self.assertFalse(any(name in line for name in privileged))
        self.assertNotIn("SourceRoot}\\app\\*", files)
        self.assertFalse(any("windows_owner" in line or "core_admission_ipc"
                             in line for line in files.splitlines()))
        print("NF_INSTALLER_SEPARATE_WINDOWS_OWNER_SIGNER_NOT_BUNDLED=PASS")

    def test_unprivileged_launcher_cannot_claim_or_sign_core(self):
        launcher = (ONE / "windows_setup/start_neurofactory.cmd").read_text(
            encoding="utf-8-sig").lower()
        for forbidden in (
            "windows_owner_controller", "signed_enqueue_only",
            "windows_core_admission_ipc", "sc.exe",
            "net user", "qwen pull", "ollama pull",
        ):
            self.assertNotIn(forbidden, launcher)
        self.assertIn("local_workspace.py", launcher)
        self.assertIn("локаль", launcher)
        print("NF_INSTALLER_EXISTING_APP_REMAINS_DRAFT_ONLY=PASS")

    def test_immutable_components_manifest_does_not_auto_enable_execution(self):
        text = (ONE / "stage_runtime_sources.py").read_text(encoding="utf-8")
        manifest_section = text.split('manifest={', 1)[1].split(
            '(components/"manifest.json")', 1)[0]
        for field in ("core_queue_wired", "host_service_enrolled",
                      "model_weights_verified", "release_approved",
                      "handoff_enabled", "independent_review_complete"):
            self.assertIn(f'"{field}":False', manifest_section)
        print("NF_INSTALLER_IMMUTABLE_PINNED_COMPONENTS_LIVE_FLAGS=FALSE")


if __name__ == "__main__":
    unittest.main()
