"""Actual restricted SCM remote-required fail-closed policy negatives (Windows CI).

No operator private keys, credentials, network service or real file effects are
created. Positive real Ed25519+mTLS+CORE tests remain in existing modules.
"""
from __future__ import annotations

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
import os
import tempfile
import unittest
import sys

from scm_witness_service_policy import (
    load_scm_witness_guard, ScmWitnessPolicyDenied, POLICY_FILE, SCHEMA,
)
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/"trusted_host"))
from windows_named_pipe_pilot_receiver import (
    serve_one_pilot,WindowsReceiverDenied,
)
from windows_scm_sandbox_receiver import (
    NeurofactorySandboxReceiverCI,CONFIG_FIELDS,
)


@unittest.skipUnless(os.name=="nt","Windows service and physical ACL only")
class ActualScmWitnessPolicyNegatives(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix="nf-real-scm-mtls-guard-")
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name).resolve()
        self.args=dict(
            operator_service_root=self.root,core_state=self.root,
            expected_spec_sha256="a"*64,
            expected_payload_sha256="b"*64,
            expected_owner="worker-one",
            actual_worker_sid="S-1-5-21-12345-67890-12345-1101",
            actual_service_sid="S-1-5-80-1-2-3-4-5",
            recipient_owner_public=Ed25519PrivateKey.generate().public_key(),
        )

    def test_missing_operator_remote_policy_is_fatal(self):
        with self.assertRaises(ScmWitnessPolicyDenied):
            load_scm_witness_guard(**self.args)
        self.assertFalse((self.root/POLICY_FILE).exists())

    def test_remote_policy_not_created_from_worker_or_model(self):
        with self.assertRaises(ScmWitnessPolicyDenied):
            load_scm_witness_guard(**self.args)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_partial_operator_policy_refuses_before_remote(self):
        p=self.root/POLICY_FILE
        p.write_text(json.dumps({"schema":SCHEMA,"claim":{"task_id":"unknown"},
            "operator_expected":{"worker_sid":self.args["actual_worker_sid"]},
            "padding":"a"*250}),encoding="ascii")
        with self.assertRaises(ScmWitnessPolicyDenied):
            load_scm_witness_guard(**self.args)

    def test_duplicate_operator_config_keys_refused(self):
        p=self.root/POLICY_FILE
        p.write_text('{"schema":"'+SCHEMA+'","schema":"'+SCHEMA+
            '","padding":"'+("x"*250)+'"}',encoding="ascii")
        with self.assertRaises(ScmWitnessPolicyDenied):
            load_scm_witness_guard(**self.args)

    def test_witness_callback_mandatory_pre_pipe_and_pre_file(self):
        pipe=r"\\.\pipe\neurofactory-pilot-101010101010101010101010"
        with self.assertRaises(WindowsReceiverDenied):
            serve_one_pilot(pipe,self.root,object(),
                self.args["actual_worker_sid"],
                recipient_core_guard=lambda p: None,
                require_signed_external_witness=True)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_core_callback_also_mandatory(self):
        pipe=r"\\.\pipe\neurofactory-pilot-101010101010101010101010"
        with self.assertRaises(WindowsReceiverDenied):
            serve_one_pilot(pipe,self.root,object(),
                self.args["actual_worker_sid"],
                recipient_signed_witness_guard=lambda p: object(),
                require_signed_external_witness=True)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_service_protects_exact_config_shape(self):
        self.assertNotIn("remote_claim_from_worker",CONFIG_FIELDS)
        self.assertNotIn("remote_signing_private",CONFIG_FIELDS)
        self.assertNotIn("witness_claim",CONFIG_FIELDS)

    def test_actual_service_receiver_has_no_production_name(self):
        self.assertIn("CI",NeurofactorySandboxReceiverCI._svc_name_)
        self.assertIn("DISPOSABLE",NeurofactorySandboxReceiverCI._svc_description_)


if __name__=="__main__":
    unittest.main(verbosity=2)
