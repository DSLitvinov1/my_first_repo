"""Strict offline preflight tests; no real Windows or accounts used."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from private_preflight_one import inspect, verify_manifest,check_local_work,REQUIRED

class PrivatePreflightTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def setup_manifest(self):
        names=set(REQUIRED)
        names.update("extra%d.txt"%i for i in range(26-len(names)))
        files={}
        for name in names:
            body=b"synthetic harmless test content"
            (self.root/name).write_bytes(body)
            files[name]=hashlib.sha256(body).hexdigest()
        (self.root/"manifest.json").write_text(json.dumps({
            "schema":"nf.workone.personal-bundle.v1",
            "file_digests":files,
            "contains_secrets":False,
            "installs_windows_service":False,
        }),encoding="utf8")
        return files

    def test_no_manifest_is_not_packaged(self):
        self.assertEqual(verify_manifest(self.root)["state"],"not_packaged")

    def test_packaged_files_verified_exactly(self):
        self.setup_manifest()
        self.assertEqual(verify_manifest(self.root)["state"],"verified")

    def test_tampered_file_rejected(self):
        self.setup_manifest()
        (self.root/"work_server.py").write_text("tampered content")
        self.assertEqual(verify_manifest(self.root)["reason"],"MANIFEST_DIGEST_MISMATCH")

    def test_manifest_path_traversal_refused(self):
        files=self.setup_manifest()
        data=json.loads((self.root/"manifest.json").read_text())
        data["file_digests"]["../escaped"]="b"*64
        (self.root/"manifest.json").write_text(json.dumps(data))
        self.assertEqual(verify_manifest(self.root)["state"],"invalid")

    def test_manifest_extra_secret_denied(self):
        self.setup_manifest()
        data=json.loads((self.root/"manifest.json").read_text())
        data["contains_secrets"]=True
        (self.root/"manifest.json").write_text(json.dumps(data))
        self.assertEqual(verify_manifest(self.root)["state"],"invalid")

    def test_preflight_does_not_require_live_http(self):
        self.setup_manifest()
        result=inspect(self.root,check_http=False)
        self.assertTrue(result["no_mutations"])
        self.assertTrue(result["no_accounts_accessed"])
        self.assertTrue(result["remote_devices_not_tested"])
        self.assertEqual(result["local_work"]["state"],"not_checked")

    def test_no_foreign_host_even_in_test(self):
        with self.assertRaises(ValueError):
            check_local_work("http://example.org")

    def test_offline_fail_closed(self):
        with patch("private_preflight_one.urlopen",side_effect=OSError("no server")):
            response=check_local_work()
        self.assertEqual(response["state"],"not_running")
        self.assertNotIn("access_token",str(response))


if __name__=="__main__":
    unittest.main()
