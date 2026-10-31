"""Focused one-attempt signed HOST -> remote mTLS witness bridge validation.

Reuses existing real-Ed25519 operator/owner/reviewer/witness fixture, no fake
signatures or executable Qwen model. The network call is mocked here; true
TLS 1.3 server/client was previously verified in the existing dedicated E2E.
"""
from pathlib import Path
import tempfile
import sqlite3
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_protected_host_task_authority import SignedTaskBoundToActualExternalClaim
from remote_highwater_client import RemoteHighwaterDenied
from protected_host_remote_bridge import (
    OneShotHostWitnessBridge,BridgeDenied,BridgeUnknown,
)

class SignedRemoteServiceBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="nf-host-attempt-test-")
        self.addCleanup(self.temp.cleanup)
        self.attempt_dir=Path(self.temp.name).resolve()
        self.fx=SignedTaskBoundToActualExternalClaim(
            "test_all_real_signatures_match_never_grants_execution")
        self.fx.setUp()
        self.inputs=dict(
            pinned_owner_public=self.fx.owner.public_key(),
            pinned_reviewer_public=self.fx.reviewer.public_key(),
            pinned_witness_public=self.fx.witness.public_key(),
            pinned_witness_id="external-independent-review-test",
            operator_expected=dict(self.fx.expected),
            trusted_minimum_remote_epoch=5,
            tls_hostname="witness.private.example",
            tls_port=443,
            tls_ca=Path("C:/operator/ca.crt"),
            tls_client_cert=Path("C:/operator/client.crt"),
            tls_client_key=Path("C:/operator/client.key"),
            pinned_tls_server_der_sha256="a"*64,
            operator_protected_attempt_dir=self.attempt_dir,
        )
    def client(self, **changes):
        params=dict(self.inputs)
        params.update(changes)
        return OneShotHostWitnessBridge(**params)
    def call(self, client, **changes):
        params=dict(
            claim=self.fx.claim,
            owner_signature=self.fx.role("owner"),
            reviewer_signature=self.fx.role("reviewer"),
            witness_claim=self.fx.remote,
            now_unix=self.fx.now,
        )
        params.update(changes)
        return client.reserve_and_verify_once(**params)

    def test_genuine_three_role_signed_ack_follows_only_one_network_reservation(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as network:
            bridge=self.client()
            result=self.call(bridge)
            self.assertEqual(network.call_count,1)
            self.assertEqual(result["external_epoch"],5)
            self.assertTrue(result["owner_signature_verified"])
            self.assertTrue(result["reviewer_signature_verified"])
            self.assertTrue(result["witness_signature_verified"])
            for field in ("physical_independence_attested",
                          "trusted_os_service_identity_attested",
                          "actual_core_lease_attested",
                          "production_service_install_allowed",
                          "production_task_effect_allowed",
                          "automatic_retry_allowed",
                          "production_release_approved"):
                self.assertIs(result[field],False)
            with self.assertRaises(BridgeUnknown):self.call(bridge)
            self.assertEqual(network.call_count,1)

    def test_fake_owner_denied_before_ever_reserving_remote(self):
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.call(self.client(),
                          owner_signature=self.fx.role(
                              "owner",key=Ed25519PrivateKey.generate()))
            self.assertEqual(net.call_count,0)

    def test_fake_reviewer_denied_before_ever_reserving_remote(self):
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.call(self.client(),
                          reviewer_signature=self.fx.role(
                              "reviewer",key=Ed25519PrivateKey.generate()))
            self.assertEqual(net.call_count,0)

    def test_wrong_operator_pinned_machine_denied_without_reserve(self):
        wrong=dict(self.fx.expected,machine_identity_sha256="b"*64)
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.call(self.client(operator_expected=wrong))
            self.assertEqual(net.call_count,0)

    def test_wrong_signed_remote_nonce_denied_without_reserve(self):
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.call(self.client(),witness_claim={
                    **self.fx.remote,"nonce":"f"*64})
            self.assertEqual(net.call_count,0)

    def test_expired_owner_task_denied_before_reserve(self):
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.call(self.client(),now_unix=self.fx.claim["expires_unix"])
            self.assertEqual(net.call_count,0)

    def test_epoch_floor_rollback_denied_without_reserve(self):
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.call(self.client(trusted_minimum_remote_epoch=6))
            self.assertEqual(net.call_count,0)

    def test_forged_witness_reply_is_unknown_and_never_retried(self):
        forgery=self.fx.ack(signer=Ed25519PrivateKey.generate())
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=forgery) as net:
            bridge=self.client()
            with self.assertRaises(BridgeUnknown):self.call(bridge)
            with self.assertRaises(BridgeUnknown):self.call(bridge)
            self.assertEqual(net.call_count,1)

    def test_ack_loss_marks_attempt_spent_before_network(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   side_effect=RemoteHighwaterDenied("lost connection")) as net:
            bridge=self.client()
            with self.assertRaises(BridgeUnknown):self.call(bridge)
            with self.assertRaises(BridgeUnknown):self.call(bridge)
            self.assertEqual(net.call_count,1)

    def test_new_service_instance_denies_replay_after_real_sqlite_commit(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as net:
            self.call(self.client())
            self.assertEqual(net.call_count,1)
            with self.assertRaises(BridgeUnknown):
                self.call(self.client())  # distinct process-like Python instance
            self.assertEqual(net.call_count,1)
        with sqlite3.connect(str(self.attempt_dir/"signed-witness-attempts.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0],1)

    def test_lost_ack_durable_across_new_instance(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   side_effect=RemoteHighwaterDenied("lost after remote COMMIT")) as net:
            with self.assertRaises(BridgeUnknown):self.call(self.client())
            with self.assertRaises(BridgeUnknown):self.call(self.client())
            self.assertEqual(net.call_count,1)

    def test_invalid_or_missing_operator_sealed_journal_denies_before_wire(self):
        absent=self.attempt_dir/"operator-did-not-provision"
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeUnknown):
                self.call(self.client(operator_protected_attempt_dir=absent))
            self.assertEqual(net.call_count,0)

    def test_corrupted_journal_schema_never_releases_remote_request(self):
        with sqlite3.connect(str(self.attempt_dir/"signed-witness-attempts.sqlite3")) as db:
            db.execute("CREATE TABLE attempts (fake TEXT)")
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeUnknown):self.call(self.client())
            self.assertEqual(net.call_count,0)

    def test_ledger_refuses_second_approved_task_with_same_epoch(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as net:
            self.call(self.client())
            altered=dict(self.fx.claim,task_id="nf-new-task-approved")
            expected=dict(self.fx.expected,task_id=altered["task_id"])
            witness=dict(self.fx.remote)
            # First bridge retains a stable separately pinned operator scope;
            # this second instance could have another signed task, but the
            # same remote epoch must be rejected by its LOCAL durability fence.
            second=self.client(operator_expected=expected)
            with self.assertRaises(BridgeUnknown):
                self.call(second,claim=altered,
                          owner_signature=self.fx.role("owner",claim=altered),
                          reviewer_signature=self.fx.role("reviewer",claim=altered),
                          witness_claim=witness)
            self.assertEqual(net.call_count,1)

    def test_same_key_owner_and_reviewer_cannot_form_host_bridge(self):
        with self.assertRaises(BridgeDenied):
            self.client(pinned_reviewer_public=self.fx.owner.public_key())

if __name__=="__main__":
    unittest.main()
