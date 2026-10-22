"""New read-only physical inspection tests. No installed source is executed."""
from __future__ import annotations
from hashlib import sha1,sha256
import json
from contextlib import closing
from pathlib import Path
from unittest.mock import patch, Mock
import os
import sqlite3
import tempfile
import unittest

from physical_windows_acceptance import observe, PhysicalAcceptanceDenied

COMMIT="1c4ccd7d64e87e284a3796b3432f13910a48679c"

class PhysicalWindowsPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-physical-readonly-test-")
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
        self.malicious_marker=self.root/"malicious-module-executed.txt"
        # This is intentionally untrusted / executable Python; the observer
        # MUST check its existence without importing or evaluating it.
        (self.app/"app/installed_integrity.py").write_text(
            "from pathlib import Path\n"
            "Path("+repr(str(self.malicious_marker))+").write_text('unsafe')\n"
            "def verify(path):\n    raise RuntimeError('MUST NEVER BE LOADED')\n")
        components=self.app/"components"
        (components/"core").mkdir(parents=True)
        self.anchors={}
        entries=[]
        for i in range(15):
            name="fixture"+str(i)+".py"
            data=("fixture-only-pinned-module-"+str(i)).encode()
            (components/"core"/name).write_bytes(data)
            blob=sha1(b"blob "+str(len(data)).encode()+b"\x00"+data).hexdigest()
            self.anchors["core/"+name]=blob
            entries.append({
                "role":"core","file":name,"source_commit":COMMIT,
                "git_blob":blob,"sha256":sha256(data).hexdigest(),"bytes":len(data)
            })
        self.fakepin={"core":(COMMIT,tuple("fixture"+str(i)+".py" for i in range(15)))}
        from physical_windows_acceptance import MANIFEST_FIELDS
        doc={
            "schema":"neurofactory.installed_components.v1",
            "source":"pinned_git_blobs_only",
            "core_queue_wired":False,
            "host_service_enrolled":False,
            "model_weights_verified":False,
            "release_approved":False,
            "handoff_enabled":False,
            "independent_review_complete":False,
            "entries":entries,
        }
        self.assertEqual(set(doc),MANIFEST_FIELDS)
        self.manifest=components/"manifest.json"
        self.manifest.write_text(json.dumps(doc),encoding="utf-8")
        with closing(sqlite3.connect(self.user/"workspace.sqlite3")) as con:
            con.execute("PRAGMA user_version=3")
            con.execute("CREATE TABLE harmless(x INTEGER)")
            con.commit()
        self.nosvc=patch("physical_windows_acceptance.subprocess.run",
                         return_value=Mock(returncode=1060,stdout="[SC] OpenService FAILED 1060",stderr=""))
        self.nosvc.start()
        self.p1=patch("physical_windows_acceptance.PINNED",self.fakepin)
        self.p2=patch("physical_windows_acceptance.ANCHORED_BLOBS",self.anchors)
        self.p1.start();self.p2.start()

    def tearDown(self):
        self.p2.stop();self.p1.stop();self.nosvc.stop()
        self.tmp.cleanup()

    def test_acceptance_reads_pinned_bytes_never_runs_installed_modules(self):
        result=observe(self.app,self.user)
        self.assertEqual(result["installed_pinned_component_count"],15)
        self.assertEqual(result["database_schema_version"],3)
        self.assertFalse(self.malicious_marker.exists())
        self.assertEqual(result["release_status"],"BLOCKED_OWNER_OPERATOR_INDEPENDENT_REVIEW")
        for field in ("production_handoff_allowed","auto_execution_allowed",
                      "production_scm_service_verified_on_this_pc",
                      "signed_independent_review_approved",
                      "actual_qwen_inference_verified_on_this_pc"):
            self.assertFalse(result[field])
        self.assertTrue(result["read_only"])
        print("NF_PHYSICAL_READONLY_BYTES_NOT_IMPORTED_AND_RELEASE_BLOCKED=PASS")

    def test_ci_only_scm_service_never_authorizes_physical_use(self):
        self.nosvc.stop()
        with patch("physical_windows_acceptance.subprocess.run",
                   return_value=Mock(returncode=0,stdout="RUNNING",stderr="")):
            with self.assertRaises(PhysicalAcceptanceDenied):
                observe(self.app,self.user)
        self.nosvc.start()

    def test_modified_pinned_component_hash_denied(self):
        (self.app/"components/core/fixture2.py").write_text("tampered",encoding="utf-8")
        with self.assertRaises(PhysicalAcceptanceDenied):
            observe(self.app,self.user)

    def test_manifest_claiming_release_or_host_enrollment_is_refused(self):
        doc=json.loads(self.manifest.read_text())
        doc["host_service_enrolled"]=True
        self.manifest.write_text(json.dumps(doc))
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
