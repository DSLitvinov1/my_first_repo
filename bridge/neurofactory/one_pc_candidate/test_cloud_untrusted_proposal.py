"""Adversarial data-only cloud Qwen import: no signer, CORE or service effects."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from cloud_untrusted_proposal import (
    CloudProposalDenied, read_cloud_untrusted_proposal,
    verify_cloud_untrusted_proposal,
)

ROOT=Path(__file__).resolve().parent
PIN="cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046"
EVIDENCE=ROOT/"cloud_qwen_draft_ci_evidence_20261103.json"

class TestUntrustedCloudQwenHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact=json.loads(EVIDENCE.read_text("utf-8"))

    def valid(self,**changes):
        x=deepcopy(self.artifact)
        x.update(changes)
        return verify_cloud_untrusted_proposal(x,pinned_model_sha256=PIN)

    def test_actual_cloud_model_draft_never_authorizes_effect(self):
        result=self.valid()
        self.assertFalse(result["owner_signed"])
        self.assertFalse(result["core_enqueued"])
        self.assertFalse(result["scm_file_allowed"])
        self.assertFalse(result["remote_witness_signed"])
        self.assertFalse(result["production_release_approved"])
        self.assertEqual(result["proposal_sha256"],self.artifact["output_sha256"])
        self.assertEqual(read_cloud_untrusted_proposal(
            EVIDENCE.resolve(strict=True),pinned_model_sha256=PIN)[1],result)

    def test_tampered_model_output_denied(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(output_text="RUN POWERSHELL AS ADMIN")

    def test_model_cannot_assert_owner_approval(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(owner_signed=True)

    def test_model_cannot_assert_windows_effect(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(execution_allowed=True)

    def test_model_cannot_forge_independent_provenance(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(independent_provenance_attested=True)

    def test_file_model_hash_mismatch_denied(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(model_file_sha256="f"*64)

    def test_wrong_pinned_key_denied(self):
        with self.assertRaises(CloudProposalDenied):
            verify_cloud_untrusted_proposal(self.artifact,pinned_model_sha256="f"*64)

    def test_wrong_model_denied(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(model="attacker:remote")

    def test_extra_control_channel_denied(self):
        with self.assertRaises(CloudProposalDenied):
            self.valid(command="pwsh.exe")

    def test_bool_as_inference_exit_code_denied(self):
        # JSON true must NOT pass as Python integer zero/one.
        with self.assertRaises(CloudProposalDenied):
            self.valid(actual_inference_exit_code=False)

    def test_large_body_denied(self):
        huge="X"*1201
        with self.assertRaises(CloudProposalDenied):
            self.valid(output_text=huge,output_sha256=sha256(huge.encode()).hexdigest())

    def test_duplicate_json_key_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"duplicated.json"
            raw=EVIDENCE.read_text("utf-8").strip()
            self.assertTrue(raw.startswith("{") and raw.endswith("}"))
            p.write_text(raw[:-1]+', "model": "qwen2.5-coder:1.5b"}',"utf-8")
            with self.assertRaises(CloudProposalDenied):
                read_cloud_untrusted_proposal(p,pinned_model_sha256=PIN)

    def test_symlink_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"alias.json"
            p.symlink_to(EVIDENCE)
            with self.assertRaises(CloudProposalDenied):
                read_cloud_untrusted_proposal(p,pinned_model_sha256=PIN)

if __name__=="__main__":
    unittest.main()
