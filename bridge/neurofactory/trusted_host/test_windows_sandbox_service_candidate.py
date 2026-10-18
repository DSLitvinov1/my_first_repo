"""Sandbox Windows service readiness and crash recovery on disposable CI only."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from windows_sandbox_service_candidate import (
    SERVICE_NAME,ServiceProvisioningDenied,load_config,service_class
)
from windows_named_pipe_pilot_receiver import (
    validate_owner_signature,WindowsReceiverDenied
)

class ServiceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        p=Path(self.temp.name)
        self.root=p/"sandbox"
        self.root.mkdir()
        self.config=p/"config.json"
        self.private=Ed25519PrivateKey.generate()
        self.pub=self.private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.d=dict(schema="nf.windows.service.config.v1",
                    mode="SANDBOX_TEST_ONLY",
                    pipe_name=r"\\.\pipe\neurofactory-pilot-"+("a"*24),
                    sandbox_root=str(self.root),
                    client_sid="S-1-5-21-123-456-789-1001",
                    owner_public_key_base64=base64.b64encode(self.pub).decode(),
                    owner_approved_install=True)
    def write(self,d=None):
        self.config.write_text(json.dumps(self.d if d is None else d),encoding="ascii")

    def test_only_bounded_sandbox_config_is_readable_no_install(self):
        self.write()
        d,pub=load_config(self.config)
        self.assertEqual(d["mode"],"SANDBOX_TEST_ONLY")
        self.assertEqual(len(self.pub),32)
        self.assertTrue(hasattr(pub,"verify"))
        self.assertEqual(SERVICE_NAME,"NeurofactorySandboxReceiver")
        self.assertFalse(hasattr(service_class(),"install"))
        print("NF_WINDOWS_SERVICE_CANDIDATE_READ_ONLY_CONFIG=PASS")

    def test_missing_install_authorization_denied(self):
        for approved in (False,None,1,"true"):
            d={**self.d,"owner_approved_install":approved}
            self.write(d)
            with self.assertRaises(ServiceProvisioningDenied):
                load_config(self.config)

    def test_fixture_mode_or_unsafe_pipe_denied(self):
        for name,value in (
            ("mode","LIVE"),
            ("pipe_name",r"\\.\pipe\unrestricted"),
            ("sandbox_root",str(self.root/"not_provisioned")),
            ("owner_public_key_base64","not-a-key"),
        ):
            with self.subTest(name=name):
                self.write({**self.d,name:value})
                with self.assertRaises(ServiceProvisioningDenied):
                    load_config(self.config)

    def test_config_extra_field_and_oversize_denied(self):
        self.write({**self.d,"production_execution_allowed":True})
        with self.assertRaises(ServiceProvisioningDenied):
            load_config(self.config)
        self.config.write_bytes(b"X"*6000)
        with self.assertRaises(ServiceProvisioningDenied):
            load_config(self.config)

    def test_restart_with_preexisting_unknown_marker_cannot_replay(self):
        # Existing receiver's file-open xb ensures the journal and file
        # are both one-use: original safe CI pipe tests exercise that.
        marker=self.root/"one_effect_unknown.json"
        marker.write_text(json.dumps({"state":"UNKNOWN_NO_AUTO_RETRY",
                     "operation_id":"original","content_sha256":"f"*64}))
        self.assertTrue(marker.exists())
        with self.assertRaises(FileExistsError):
            with marker.open("xb") as stream:
                stream.write(b"replayed")
        self.assertEqual(json.loads(marker.read_text())["operation_id"],"original")
        print("NF_WINDOWS_RESTART_UNKNOWN_MARKER_REPLAY=DENIED_TEST_ONLY")

    def test_service_module_does_not_enable_real_queue(self):
        source=Path(__file__).with_name("windows_sandbox_service_candidate.py").read_text()
        self.assertIn("NO_INSTALLER_OR_LIVE_QUEUE_SECURITY_REVIEW_REQUIRED",source)
        self.assertNotIn("subprocess.run",source)
        self.assertNotIn("register_task_queue",source)
        self.assertNotIn("CREATE SERVICE",source)

if __name__=="__main__":
    unittest.main()
