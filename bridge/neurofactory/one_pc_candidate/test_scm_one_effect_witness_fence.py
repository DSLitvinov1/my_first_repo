"""Disposable real CORE SQLite + signed 3-role witness receipt -> durable one-use gate."""
from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_scm_recipient_core_claim_guard import RecipientClaimGateTest
from test_protected_host_task_authority import SignedTaskBoundToActualExternalClaim
from protected_host_task_authority import _canon
from protected_host_remote_bridge import OneShotHostWitnessBridge
from protected_host_attempt_ledger import provision_empty_attempt_ledger_offline
from protected_host_core_witness_binding import exact_core_effect_sha256
from remote_highwater_client import RemoteHighwaterDenied
from scm_one_effect_witness_fence import (
    OneShotScmRecipientFence, RecipientFenceDenied, RecipientFenceUnknown,
    provision_empty_recipient_fence_offline,
)

class SignedRecipientWitnessFenceTests(RecipientClaimGateTest):
    def setUp(self):
        super().setUp()
        self.operator=tempfile.TemporaryDirectory(prefix="nf-operator-fence-")
        self.addCleanup(self.operator.cleanup)
        self.fence_dir=Path(self.operator.name).resolve()
        self.local_witness=tempfile.TemporaryDirectory(prefix="nf-operator-attempt-")
        self.addCleanup(self.local_witness.cleanup)
        self.attempt_dir=Path(self.local_witness.name).resolve()
        provision_empty_recipient_fence_offline(self.fence_dir)
        provision_empty_attempt_ledger_offline(self.attempt_dir)
        self.fx=SignedTaskBoundToActualExternalClaim("test_all_real_signatures_match_never_grants_execution")
        self.fx.setUp()
        for key,value in (
            ("task_id",self.spec["task_id"]),
            ("project_id",self.spec["project_id"]),
            ("source_sha40",self.spec["source_sha"]),
            ("payload_sha256",self.body["content_sha256"]),
            ("operation_sha256",exact_core_effect_sha256(self.digest,self.body["content_sha256"])),
        ):
            self.fx.claim[key]=value
            self.fx.expected[key]=value
            if key in self.fx.remote:
                self.fx.remote[key]=value
        self.fx.evidence["source_sha40"]=self.fx.remote["source_sha40"]
        self.fx.evidence["claim_sha256"]=sha256(_canon(self.fx.remote)).hexdigest()

    def bridge(self):
        return OneShotHostWitnessBridge(
            pinned_owner_public=self.fx.owner.public_key(),
            pinned_reviewer_public=self.fx.reviewer.public_key(),
            pinned_witness_public=self.fx.witness.public_key(),
            pinned_witness_id="external-independent-review-test",
            operator_expected=dict(self.fx.expected),
            trusted_minimum_remote_epoch=5,
            tls_hostname="witness.private.example",tls_port=443,
            tls_ca=Path("C:/operator/ca.crt"),
            tls_client_cert=Path("C:/operator/client.crt"),
            tls_client_key=Path("C:/operator/client.key"),
            pinned_tls_server_der_sha256="a"*64,
            operator_protected_attempt_dir=self.attempt_dir)

    def fence(self):
        return OneShotScmRecipientFence(
            operator_fence_dir=self.fence_dir,
            core_state=self.state,
            expected_spec_sha256=self.digest,
            expected_payload_sha256=self.body["content_sha256"],
            expected_owner="worker-one",
            bridge=self.bridge())

    def call(self,fence,**overrides):
        p=dict(
            body=self.body,claim=self.fx.claim,
            owner_signature=self.fx.role("owner"),
            reviewer_signature=self.fx.role("reviewer"),
            witness_claim=self.fx.remote)
        p.update(overrides)
        return fence.reserve_once(**p)

    def stage(self):
        with closing(sqlite3.connect(
                (self.fence_dir/"recipient-one-effect-intents.sqlite3").as_uri()+"?mode=ro",
                uri=True)) as db:
            return db.execute("SELECT disposition,ack_observation_sha256 FROM one_effect_intents").fetchall()

    def test_exact_live_claim_three_signatures_witness_once_durable(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as remote:
            result=self.call(self.fence())
            self.assertEqual(remote.call_count,1)
            self.assertEqual(result["status"],
                "LOCAL_INTENT_AND_SIGNED_WITNESS_ACK_OBSERVED_LAB_ONLY")
            self.assertFalse(result["recipient_file_effect_granted_for_production"])
            self.assertFalse(result["distributed_atomic_transaction_attested"])
            self.assertEqual(self.stage()[0][0],"ACK_OBSERVED_NO_EFFECT_AUTHORITY")
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(remote.call_count,1)
            self.assertEqual(len(self.stage()),1)

    def test_lost_ack_spent_and_reboot_like_new_instance_never_retries(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   side_effect=RemoteHighwaterDenied("ACK lost after remote commit")) as remote:
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(self.stage(),[("UNKNOWN_NO_AUTO_RETRY",None)])
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(remote.call_count,1)

    def test_genuine_owner_signature_but_wrong_signed_payload_denied_before_network(self):
        other={**self.fx.claim,"payload_sha256":"f"*64}
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(RecipientFenceDenied):
                self.call(self.fence(),claim=other,
                          owner_signature=self.fx.role("owner",claim=other),
                          reviewer_signature=self.fx.role("reviewer",claim=other))
            remote.assert_not_called()
            self.assertEqual(self.stage(),[])

    def test_expired_core_lease_never_consumes_or_contacts_witness(self):
        self.update("UPDATE single_job SET lease_until=? WHERE singleton=1",
                    (int(time.time())-1,))
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(ValueError):
                self.call(self.fence())
            remote.assert_not_called()
            self.assertEqual(self.stage(),[])

    def test_replay_on_second_bridge_even_after_valid_ack_denied(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as remote:
            first=self.fence()
            self.call(first)
            with self.assertRaises(RecipientFenceUnknown):
                self.call(first)
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(remote.call_count,1)

    def test_forged_reviewer_causes_unknown_fence_no_network(self):
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence(),reviewer_signature=self.fx.role(
                    "reviewer",key=Ed25519PrivateKey.generate()))
            self.assertEqual(remote.call_count,0)
            self.assertEqual(self.stage(),[("UNKNOWN_NO_AUTO_RETRY",None)])
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())

    def test_remote_ack_invalid_signature_is_unknown_no_repeat(self):
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack(signer=Ed25519PrivateKey.generate())) as remote:
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(self.stage(),[("UNKNOWN_NO_AUTO_RETRY",None)])
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(remote.call_count,1)

    def test_core_changes_while_remote_signs_denies_after_ack(self):
        def changed(**kw):
            self.update("UPDATE single_job SET lease_until=lease_until-1 WHERE singleton=1")
            return self.fx.ack()
        with patch("protected_host_remote_bridge._wire_exchange",side_effect=changed) as remote:
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertEqual(remote.call_count,1)
            self.assertEqual(self.stage(),[("UNKNOWN_NO_AUTO_RETRY",None)])

    def test_missing_fence_db_is_not_recreated(self):
        db=self.fence_dir/"recipient-one-effect-intents.sqlite3"
        db.unlink()
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            self.assertFalse(db.exists())
            remote.assert_not_called()

    def test_corrupt_fence_schema_denies_before_network(self):
        with closing(sqlite3.connect(self.fence_dir/"recipient-one-effect-intents.sqlite3")) as db, db:
            db.execute("DROP TABLE one_effect_intents")
            db.execute("CREATE TABLE one_effect_intents (invalid TEXT)")
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(RecipientFenceUnknown):
                self.call(self.fence())
            remote.assert_not_called()

    def test_missing_core_database_denies_without_local_fence(self):
        self.db.unlink()
        with patch("protected_host_remote_bridge._wire_exchange") as remote:
            with self.assertRaises(ValueError):
                self.call(self.fence())
            self.assertEqual(self.stage(),[])
            remote.assert_not_called()

    def test_no_offline_provision_again_even_when_empty(self):
        with self.assertRaises(RecipientFenceDenied):
            provision_empty_recipient_fence_offline(self.fence_dir)


if __name__=="__main__":
    unittest.main(verbosity=2)
