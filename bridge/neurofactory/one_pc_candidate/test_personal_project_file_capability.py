"""One bounded regression for owner-reviewed CORE/Qwen HOST project files.

Tests a real cryptographic owner signature, one CREATE_NEW effect and refusal
of path traversal, unsigned permission changes, unsupported model and replay.
No external SSH, Windows SCM or user machine required.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from personal_ssh_highwater import _canon
from personal_project_file_effect import (
    PROJECT_FILE_ACTION,PROJECT_FILE_SCHEMA,OWNER_FILE_DOMAIN,
    CORE_PERMISSION_SCHEMA,MAX_CONTENT,ProjectFileDenied,
    apply_approved_project_file,check_core_permission,safe_project_name,
)
from personal_windows_host_service import _signed_body

TASK="a"*32
PROJECT="b"*32
SOURCE_SHA="c"*40
MACHINE_HASH="d"*64
PACKAGE_HASH="e"*64


def packet(signer,*,relative_path="draft.md",text="Safe code example\n",
           model="qwen3.5:9b"):
    digest=sha256(text.encode("utf-8")).hexdigest()
    body={
        "schema":PROJECT_FILE_SCHEMA,
        "task_id":TASK,
        "project_id":PROJECT,
        "nonce":"f"*32,
        "external_epoch":2,
        "issued_unix":100,
        "expires_unix":180,
        "source_sha40":SOURCE_SHA,
        "machine_sha256":MACHINE_HASH,
        "package_sha256":PACKAGE_HASH,
        "operation":PROJECT_FILE_ACTION,
        "relative_path":relative_path,
        "text":text,
        "content_sha256":digest,
        "core_permission":{
            "schema":CORE_PERMISSION_SCHEMA,
            "task_id":TASK,
            "project_id":PROJECT,
            "model":model,
            "draft_sha256":digest,
            "operation":PROJECT_FILE_ACTION,
            "relative_path":relative_path,
            "content_sha256":digest,
            "max_bytes":MAX_CONTENT,
            "owner_reviewed":True,
        },
    }
    return {**body,"owner_signature_base64":base64.b64encode(
        signer.sign(OWNER_FILE_DOMAIN+_canon(body))).decode("ascii")}


class OwnerReviewedProjectAction(unittest.TestCase):
    def setUp(self):
        self.signer=Ed25519PrivateKey.generate()
        self.operator={
            "source_sha40":SOURCE_SHA,
            "machine_sha256":MACHINE_HASH,
            "package_sha256":PACKAGE_HASH,
        }
        self.folder=tempfile.TemporaryDirectory(prefix="nf-safe-project-")
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name)
        (self.root/PROJECT).mkdir()

    def test_owner_signed_core_qwen_file_create_once(self):
        req=packet(self.signer)
        body=_signed_body(req,self.operator,self.signer.public_key(),now=102)
        result=apply_approved_project_file(
            signed_body=body,projects_root=self.root)
        self.assertEqual(result["status"],"OWNER_CORE_QWEN_PROJECT_FILE_CREATED")
        self.assertFalse(result["executed_generated_code"])
        self.assertEqual((self.root/PROJECT/"draft.md").read_bytes(),
                         b"Safe code example\n")
        with self.assertRaises(ProjectFileDenied):
            apply_approved_project_file(
                signed_body=body,projects_root=self.root)

    def test_tamper_rejected_before_external_reservation(self):
        original=packet(self.signer)
        for modification in ("text","relative_path","core_permission"):
            candidate=dict(original)
            if modification=="text":
                candidate["text"]="malicious file"
            elif modification=="relative_path":
                candidate["relative_path"]="other.md"
            else:
                candidate["core_permission"]={**original["core_permission"],
                                              "owner_reviewed":False}
            with self.subTest(modification=modification):
                with self.assertRaises((ValueError,InvalidSignature)):
                    _signed_body(candidate,self.operator,
                                 self.signer.public_key(),now=102)
        self.assertFalse((self.root/PROJECT/"draft.md").exists())

    def test_no_unsafe_filename_or_broad_model(self):
        for forbidden in ("../hello.md","con.md","CON.txt","dir/script.py",
                          r"..\hello.md","first..second.py",
                          "C:\\windows\\a.py","evil.exe","a.bat",
                          ".env","hello.js:evil","foo "):
            with self.subTest(name=forbidden):
                with self.assertRaises(ProjectFileDenied):
                    safe_project_name(forbidden)
        with self.assertRaises(ProjectFileDenied):
            check_core_permission({key:value for key,value in
                                  packet(self.signer,model="untrusted-model").items()
                                  if key!="owner_signature_base64"})

if __name__=="__main__":
    unittest.main()
