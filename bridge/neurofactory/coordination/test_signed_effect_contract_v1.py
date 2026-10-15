"""Scoped consistency checks for future signed per-event effect contract only.

No issuer, connection, service or real queue is started by these checks.
"""
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent

def spec(name):
    return json.loads((HERE/name).read_text(encoding="utf-8"))

class SignedEffectContractChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wire=spec("central-multipc-transaction-v1.json")
        cls.trust=spec("trust-host-boundary-v1.json")
        cls.events=cls.wire["events"]

    def test_effect_signed_fields_include_epoch_and_idempotency(self):
        minimum={"lease_epoch","worker_id","fencing_token_sha256","idempotency_key"}
        fields=set(self.events["effect_readback_signed_fields"])
        self.assertTrue(minimum <= fields)
        self.assertTrue(minimum <= set(self.events["required_fields"]))
        self.assertTrue(minimum <= set(self.trust["proposed_event"]["required_fields"]))

    def test_event_kind_specific_fields_exact(self):
        lease={"lease_epoch","worker_id","fencing_token_sha256"}
        effect={"idempotency_key"}
        expected={"AUTHORIZE_TASK":set(),"LEASE_CLAIM":lease,
                  "PRE_SIDE_EFFECT":lease|effect,
                  "EFFECT_READBACK":lease|effect,
                  "MANUAL_STOP":lease}
        actual=self.events["per_event_required_fields"]
        self.assertEqual(set(actual),set(expected))
        for kind in expected:
            with self.subTest(kind=kind):
                self.assertEqual(set(actual[kind]),expected[kind])

    def test_trust_and_dispatch_are_same_contract(self):
        event_fields=self.events["per_event_required_fields"]
        trust_fields=self.trust["proposed_event"]["event_specific_fields"]
        self.assertEqual(event_fields,trust_fields)
        common=set(self.events["signed_payload_common_fields"])
        self.assertEqual(common,set(self.trust["proposed_event"]["common_signed_payload_fields"]))
        self.assertEqual(
            set(self.events["detached_envelope_fields"]),
            set(self.trust["proposed_event"]["detached_signed_envelope_fields"])
        )
        self.assertEqual(set(self.events["required_fields"]),
                         set(self.trust["proposed_event"]["required_fields"])
                         - {"schema"})

    def test_pinned_expectations_not_from_signed_payload(self):
        expected={"task_id","input_core_sha40","issuer_identity","issuer_key_id",
                  "prior_event_digest_sha256","event_sequence","lease_epoch",
                  "worker_id","fencing_token_sha256","idempotency_key"}
        self.assertEqual(set(self.events["external_pins_required_for_effect"]),expected)
        self.assertIn("independent",self.events["security_semantics"].lower())

    def test_no_live_claim_from_cryptographic_test_success(self):
        gates=self.wire["security_gates"]
        self.assertEqual(gates["release"],"BLOCKED")
        self.assertIn("NOT_DEPLOYED",gates["independent_signing_issuer"])
        self.assertFalse(self.events["publisher_allowed"])
        self.assertFalse(self.wire["topology"]["issuer_deployed"])
        self.assertFalse(self.wire["topology"]["central_host_deployed"])
        self.assertEqual(gates["handoff"],"PAUSED_BY_USER")

    def test_mismatch_and_retry_cannot_be_implicitly_allowed(self):
        sm=self.wire["status_machine"]
        self.assertIs(sm["after_unknown_automatic_retry"],False)
        self.assertIs(sm["after_pre_side_effect_reassignment"],False)
        self.assertIs(self.wire["claim"]["multiple_winner_permission"],False)
        self.assertIs(self.wire["events"]["independently_trusted_issuer"],False)

if __name__=="__main__":
    unittest.main()
