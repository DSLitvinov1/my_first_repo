"""Actual disposable CORE SQLite -> real Ed25519 remote-ACK boundary tests.

No paid model/production SCM/hardware permissions. Real OneTaskCore enqueue+
claim and SQLite DB, distinct ephemeral signing keys, mock NETWORK ONLY.
"""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_core_readonly_observer import CoreReadOnlyIntegration
from test_protected_host_task_authority import SignedTaskBoundToActualExternalClaim
from protected_host_task_authority import _canon
from protected_host_attempt_ledger import provision_empty_attempt_ledger_offline
from protected_host_remote_bridge import OneShotHostWitnessBridge,BridgeDenied
from protected_host_core_witness_binding import (
    bind_core_and_reserve_witness_once,CoreWitnessBindingDenied,
    CoreWitnessBindingUnknown,
)

class ProtectedHostRealCoreWitnessTests(CoreReadOnlyIntegration):
    def setUp(self):
        super().setUp()
        self.fx=SignedTaskBoundToActualExternalClaim(
            "test_all_real_signatures_match_never_grants_execution")
        self.fx.setUp()
        now=self.fx.now
        replacements={
            "task_id":self.spec["task_id"],
            "project_id":self.spec["project_id"],
            "source_sha40":self.spec["source_sha"],
        }
        for key,value in replacements.items():
            self.fx.claim[key]=value
            self.fx.expected[key]=value
            if key=="source_sha40":
                self.fx.remote[key]=value
                self.fx.evidence[key]=value
        self.fx.evidence["claim_sha256"]=hashlib.sha256(
            _canon(self.fx.remote)).hexdigest()
        self.operator=tempfile.TemporaryDirectory(prefix="nf-real-core-signed-")
        self.addCleanup(self.operator.cleanup)
        self.attempt_dir=Path(self.operator.name).resolve()
        provision_empty_attempt_ledger_offline(self.attempt_dir)
        self.signed_bridge=OneShotHostWitnessBridge(
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
    def invoke(self,**overrides):
        args=dict(
            core_state_dir=self.state,bridge=self.signed_bridge,
            claim=self.fx.claim,owner_signature=self.fx.role("owner"),
            reviewer_signature=self.fx.role("reviewer"),
            witness_claim=self.fx.remote,now_unix=self.fx.now,
        )
        args.update(overrides)
        return bind_core_and_reserve_witness_once(**args)
    def _claim(self):
        self.enqueue()
        self.core.claim("observer-worker",now=self.fx.now,lease_seconds=120)

    def test_real_core_claimed_signed_remote_ack_no_write_permission(self):
        self._claim()
        with patch("protected_host_remote_bridge._wire_exchange",
                   return_value=self.fx.ack()) as net:
            proof=self.invoke()
            self.assertEqual(net.call_count,1)
        self.assertEqual(proof["status"],
                         "LOCAL_CORE_SCOPE_MATCHED_AND_SIGNED_REMOTE_ACK_TEST_NO_EFFECT")
        for field in ("actual_core_lease_transaction_attested",
                      "windows_scm_sid_acl_attested",
                      "physically_independent_witness_attested",
                      "production_file_effects_allowed",
                      "automatic_retry_allowed","production_release_approved"):
            self.assertIs(proof[field],False)
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_queued_task_denied_before_remote_or_ledger_reservation(self):
        self.enqueue()
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(CoreWitnessBindingDenied):self.invoke()
            net.assert_not_called()

    def test_wrong_exact_task_and_project_denied_before_remote(self):
        self._claim()
        for key,value in (("task_id","NF-DEV-05-Q002"),
                          ("project_id","other-core-project"),
                          ("source_sha40","f"*40)):
            altered={**self.fx.claim,key:value}
            with patch("protected_host_remote_bridge._wire_exchange") as net:
                with self.assertRaises(CoreWitnessBindingDenied):
                    self.invoke(claim=altered)
                net.assert_not_called()

    def test_expired_core_lease_denied_before_remote(self):
        self.enqueue()
        self.core.claim("observer-worker",now=self.fx.now-300,lease_seconds=30)
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(CoreWitnessBindingDenied):self.invoke()
            net.assert_not_called()

    def test_forged_owner_denied_even_when_core_matches(self):
        self._claim()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        forged=self.fx.role("owner",key=Ed25519PrivateKey.generate())
        with patch("protected_host_remote_bridge._wire_exchange") as net:
            with self.assertRaises(BridgeDenied):
                self.invoke(owner_signature=forged)
            net.assert_not_called()

    def test_core_changes_after_witness_ack_unknown_no_permission(self):
        self._claim()
        def mutate_core(**kw):
            # Remote may reserve before local CORE changes. This is NEVER
            # proof that a production file effect is still admissible.
            with self.core._connect() as db:
                db.execute("UPDATE single_job SET lease_until=lease_until-1")
            return self.fx.ack()
        with patch("protected_host_remote_bridge._wire_exchange",
                   side_effect=mutate_core) as net:
            with self.assertRaises(CoreWitnessBindingUnknown):self.invoke()
            self.assertEqual(net.call_count,1)
        self.assertNotIn("production",str(self.core.snapshot().get("state")))

if __name__=="__main__":
    unittest.main()
