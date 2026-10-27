"""Read-only review ZIP preflight; no key download, installs or service starts."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from vps_witness_systemd.verify_witness_source_archive import (
    verify_archive,OperatorArchiveDenied,_EXPECTED,
)

class ReviewArchiveNegativeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve()
        self.path=self.root/"review.zip"
        self.source=Path(__file__).resolve().parent
        self.files={name:(self.source/name).read_bytes() for name in _EXPECTED}
    def tearDown(self):self.temp.cleanup()
    def create(self,*,bad_manifest=False,extra=None,modified=None):
        files=self.files.copy()
        if modified:
            files[modified]=files[modified]+b"\nUNAPPROVED_MODIFICATION\n"
        manifest={"schema":"nf.vps_witness.source_review_bundle.v1",
                  "source_sha40":"b"*40,
                  "mode":"UNSIGNED_OPERATOR_REVIEW_NO_KEYS_NO_PRODUCTION",
                  "files":[
                      {"path":name,"sha256":hashlib.sha256(body).hexdigest(),
                       "bytes":len(body)}
                      for name,body in self.files.items()
                  ]}
        if bad_manifest:manifest["mode"]="RELEASE_APPROVED"
        with zipfile.ZipFile(self.path,"w",zipfile.ZIP_DEFLATED) as zip:
            for name,data in files.items():
                zip.writestr(name,data)
            if extra:
                zip.writestr(extra,b"FOREIGN")
            zip.writestr("source-manifest.json",json.dumps(manifest))
        return hashlib.sha256(self.path.read_bytes()).hexdigest()
    def test_accept_hash_verified_review_only_without_install_authority(self):
        h=self.create()
        result=verify_archive(path=self.path,operator_approved_archive_sha256=h)
        self.assertEqual(result["verified_files"],len(_EXPECTED))
        self.assertFalse(result["may_install_or_activate"])
        self.assertFalse(result["reviewer_signature_verified"])
    def test_deny_operator_pin_replaced(self):
        self.create()
        with self.assertRaises(OperatorArchiveDenied):
            verify_archive(path=self.path,operator_approved_archive_sha256="0"*64)
    def test_deny_internal_file_tamper_even_when_outer_hash_recomputed(self):
        h=self.create(modified="external_highwater_daemon.py")
        with self.assertRaises(OperatorArchiveDenied):
            verify_archive(path=self.path,operator_approved_archive_sha256=h)
    def test_deny_manifest_promotes_to_release(self):
        h=self.create(bad_manifest=True)
        with self.assertRaises(OperatorArchiveDenied):
            verify_archive(path=self.path,operator_approved_archive_sha256=h)
    def test_deny_extra_source(self):
        h=self.create(extra="../outside.py")
        with self.assertRaises(OperatorArchiveDenied):
            verify_archive(path=self.path,operator_approved_archive_sha256=h)
    def test_deny_missing_archive(self):
        with self.assertRaises(OperatorArchiveDenied):
            verify_archive(path=self.root/"missing.zip",operator_approved_archive_sha256="b"*64)

if __name__=="__main__":unittest.main()
