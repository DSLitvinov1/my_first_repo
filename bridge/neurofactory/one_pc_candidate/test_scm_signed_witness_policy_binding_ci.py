"""Operator-sealed Windows SCM policy to real Ed25519 owner/reviewer and CORE.

The injected remote ACK is a valid independently signed cryptographic fixture
but the network exchange is deliberately mocked in THIS unit test. The real
TLS transport is separately covered by test_scm_real_tls_witness_to_ci_file;
the actual Windows SCM startup fail-closed is covered by its own CI test.
"""
from __future__ import annotations
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scm_witness_service_policy import (
    load_scm_witness_guard,ScmWitnessPolicyDenied,SCHEMA,POLICY_FILE)
from scm_one_effect_witness_fence import RecipientFenceUnknown
from test_scm_one_effect_witness_fence import SignedRecipientWitnessFenceTests
from remote_highwater_client import RemoteHighwaterDenied


@unittest.skipUnless(os.name=="nt","Actual Windows path semantics required")
class SignedScmPolicyToRealCoreTest(unittest.TestCase):
    def setUp(self):
        self.fixture=SignedRecipientWitnessFenceTests(
            "test_exact_live_claim_three_signatures_witness_once_durable")
        self.fixture.setUp()
        self.addCleanup(lambda:(self.fixture.tearDown(),self.fixture.doCleanups()))
        self.temp=tempfile.TemporaryDirectory(prefix="nf-sealed-scm-witness-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.fx=self.fixture.fx
        self.policy={
            "schema":SCHEMA,
            "pinned_owner_public_base64":self.pub(self.fx.owner),
            "pinned_reviewer_public_base64":self.pub(self.fx.reviewer),
            "pinned_witness_public_base64":self.pub(self.fx.witness),
            "pinned_witness_id":"external-independent-review-test",
            "operator_expected":self.fx.expected,
            "trusted_minimum_remote_epoch":5,
            "tls_hostname":"witness.private.example","tls_port":443,
            "tls_ca_path":"C:\\operator\\ca.crt",
            "tls_client_cert_path":"C:\\operator\\client.crt",
            "tls_client_key_path":"C:\\operator\\client.key",
            "tls_server_der_sha256":"a"*64,
            "operator_attempt_dir":str(self.fixture.attempt_dir),
            "operator_fence_dir":str(self.fixture.fence_dir),
            "claim":self.fx.claim,
            "owner_signature":self.fx.role("owner"),
            "reviewer_signature":self.fx.role("reviewer"),
            "witness_claim":self.fx.remote,
        }
        self.args=dict(
            operator_service_root=self.root,core_state=self.fixture.state,
            expected_spec_sha256=self.fixture.digest,
            expected_payload_sha256=self.fixture.body["content_sha256"],
            expected_owner="worker-one",
            actual_worker_sid=self.fx.claim["worker_sid"],
            actual_service_sid=self.fx.claim["service_sid"],
        )

    @staticmethod
    def pub(key):
        raw=key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def write(self,doc=None):
        data=self.policy if doc is None else doc
        (self.root/POLICY_FILE).write_text(
            json.dumps(data,sort_keys=True,separators=(",",":")),encoding="ascii")

    def test_valid_three_signatures_live_core_and_signed_ack_once(self):
        self.write()
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as remote:
            gate=load_scm_witness_guard(**self.args)
            proof=gate(self.fixture.body)
            self.assertEqual(proof["status"],
                "LOCAL_INTENT_AND_SIGNED_WITNESS_ACK_OBSERVED_LAB_ONLY")
            self.assertFalse(proof["recipient_file_effect_granted_for_production"])
            self.assertFalse(proof["automatic_retry_allowed"])
            self.assertEqual(remote.call_count,1)
            with self.assertRaises(RecipientFenceUnknown):
                load_scm_witness_guard(**self.args)(self.fixture.body)
            self.assertEqual(remote.call_count,1)

    def test_real_core_scope_wrong_before_network(self):
        self.write()
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            gate=load_scm_witness_guard(**self.args)
            with self.assertRaises(ScmWitnessPolicyDenied):
                gate({**self.fixture.body,"task_id":"other-task"})
            self.assertEqual(self.fixture.stage(),[])
            remote.assert_not_called()

    def test_actual_worker_sid_mismatch_no_remote_reservation(self):
        self.write()
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(ScmWitnessPolicyDenied):
                load_scm_witness_guard(**{**self.args,
                    "actual_worker_sid":"S-1-5-21-999-888-777-666"})
            self.assertEqual(self.fixture.stage(),[])
            remote.assert_not_called()

    def test_actual_service_sid_mismatch_no_remote_reservation(self):
        self.write()
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(ScmWitnessPolicyDenied):
                load_scm_witness_guard(**{**self.args,
                    "actual_service_sid":"S-1-5-80-9-9-9-9-9"})
            self.assertEqual(self.fixture.stage(),[])
            remote.assert_not_called()

    def test_remote_ack_lost_burns_one_use_fence_no_retry(self):
        self.write()
        with patch("protected_host_remote_bridge._wire_exchange",
                   side_effect=RemoteHighwaterDenied("lost after commit")) as remote:
            with self.assertRaises(RecipientFenceUnknown):
                load_scm_witness_guard(**self.args)(self.fixture.body)
            with self.assertRaises(RecipientFenceUnknown):
                load_scm_witness_guard(**self.args)(self.fixture.body)
            self.assertEqual(remote.call_count,1)

    def test_forged_reviewer_before_effect_rejected(self):
        broken={**self.policy,
            "reviewer_signature":self.fx.role(
                "reviewer",key=Ed25519PrivateKey.generate())}
        self.write(broken)
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(RecipientFenceUnknown):
                load_scm_witness_guard(**self.args)(self.fixture.body)
            self.assertEqual(self.fixture.stage()[0][0],"UNKNOWN_NO_AUTO_RETRY")
            remote.assert_not_called()

    def test_extra_keys_never_grant_service_permission(self):
        self.write({**self.policy,"execute":"cmd.exe /C anything"})
        with self.assertRaises(ScmWitnessPolicyDenied):
            load_scm_witness_guard(**self.args)
        self.assertEqual(self.fixture.stage(),[])


if __name__=="__main__":
    unittest.main(verbosity=2)
