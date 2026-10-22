"""Focused read-only physical preflight tests; mock SCM, no product start."""
from __future__ import annotations
from pathlib import Path
from unittest.mock import patch, Mock
import os
import sqlite3
import tempfile
import unittest

from physical_windows_acceptance import observe, PhysicalAcceptanceDenied

class PhysicalWindowsPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-physical-preflight-only-")
        self.root=Path(self.tmp.name).resolve()
        self.app=self.root/"app"
        self.user=self.root/"user"
        self.app.mkdir()
        self.user.mkdir()
        for name in ("app/local_workspace.py","ui/index.html",
                     "ui/integrations.js","runtime/python.exe",
                     "start_neurofactory.cmd"):
            item=self.app/name
            item.parent.mkdir(parents=True,exist_ok=True)
            item.write_bytes(b'fixture-only')
        loaded=self.app/"app/installed_integrity.py"
        loaded.write_text(
            "def verify(path):\n"
            "    return {'files_verified':15,'live_execution_allowed':False}\n")
        (self.app/"components").mkdir()
        db=self.user/"workspace.sqlite3"
        with sqlite3.connect(db) as con:
            con.execute("PRAGMA user_version=3")
            con.execute("CREATE TABLE harmless(x INTEGER)")
            con.commit()
        self.nosvc=patch(
            "physical_windows_acceptance.subprocess.run",
            return_value=Mock(returncode=1060,stdout="[SC] OpenService FAILED 1060",stderr=""))
        self.nosvc.start()

    def tearDown(self):
        self.nosvc.stop()
        self.tmp.cleanup()

    def test_acceptance_is_readonly_and_never_releases(self):
        result=observe(self.app,self.user)
        self.assertEqual(result["installed_pinned_component_count"],15)
        self.assertEqual(result["database_schema_version"],3)
        self.assertEqual(result["release_status"],"BLOCKED_OWNER_OPERATOR_INDEPENDENT_REVIEW")
        for field in ("production_handoff_allowed","auto_execution_allowed",
                      "production_scm_service_verified_on_this_pc",
                      "signed_independent_review_approved",
                      "actual_qwen_inference_verified_on_this_pc"):
            self.assertFalse(result[field])
        self.assertTrue(result["read_only"])
        print("NF_PHYSICAL_PILOT_READONLY_RELEASE_FENCE=PASS")

    def test_test_fixture_service_never_authorizes_physical_use(self):
        self.nosvc.stop()
        with patch("physical_windows_acceptance.subprocess.run",
                   return_value=Mock(returncode=0,stdout="RUNNING",stderr="")):
            with self.assertRaises(PhysicalAcceptanceDenied):
                observe(self.app,self.user)
        self.nosvc.start()

    def test_modified_pinned_component_fails_closed(self):
        (self.app/"app/installed_integrity.py").write_text(
            "def verify(path):\n"
            "    return {'files_verified':14,'live_execution_allowed':False}\n")
        with self.assertRaises(PhysicalAcceptanceDenied):
            observe(self.app,self.user)

    def test_unrecognized_sqlite_schema_denied(self):
        with sqlite3.connect(self.user/"workspace.sqlite3") as con:
            con.execute("PRAGMA user_version=999")
        with self.assertRaises(PhysicalAcceptanceDenied):
            observe(self.app,self.user)

    def test_linked_program_file_never_attested(self):
        (self.app/"ui/integrations.js").unlink()
        try:
            (self.app/"ui/integrations.js").symlink_to(self.app/"ui/index.html")
        except OSError:
            self.skipTest("Windows developer-mode symlink unavailable")
        with self.assertRaises(PhysicalAcceptanceDenied):
            observe(self.app,self.user)

if __name__=="__main__":
    unittest.main()
