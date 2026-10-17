"""Host witness signatures are only OBSERVATIONS, not operator permission."""
import base64
import copy
import hashlib
import json
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from two_node_witness_diagnostic import inspect_two_node_witnesses, WitnessRejected

NOW = 1800000000
SHA0 = "0" * 64

class TwoPhysicalNodeClaimsTests(unittest.TestCase):
    def setUp(self):
        self.a = Ed25519PrivateKey.generate()
        self.b = Ed25519PrivateKey.generate()
        self.keys = {"node-alpha": self.a, "node-beta": self.b}
        self.pins = {
            "node-alpha": {
                "public_key": self.a.public_key(),
                "physical_claim_sha256": hashlib.sha256(b"test-only-label-A").hexdigest()
            },
            "node-beta": {
                "public_key": self.b.public_key(),
                "physical_claim_sha256": hashlib.sha256(b"test-only-label-B").hexdigest()
            }
        }
        self.expect = {
            "challenge_sha256": hashlib.sha256(b"operator-onetime-test-challenge").hexdigest(),
            "operation_id": "nf-trial-one",
            "task_id": "NF-DEV-05-Q991",
            "project_id": "nf-sandbox",
            "core_sha40": "4a068968d5a34d0f7998b7da4d22640160b90b23",
            "host_sha40": "3101875b4f56ae83b0cc92300aca9544a5ad21ed",
            "content_sha256": hashlib.sha256(b"inert-checkpoint-bytes").hexdigest(),
        }
        self.packets = [
            self.packet("node-alpha","ONE_SYNTHETIC_EFFECT"),
            self.packet("node-beta","DENIED_NO_EFFECT")
        ]

    def payload(self, node, outcome):
        return {
            "schema": "neurofactory.two_node_witness.v1",
            "node_id": node,
            "attempt_nonce": hashlib.sha256(node.encode()+b"nonce").hexdigest(),
            "physical_claim_sha256": self.pins[node]["physical_claim_sha256"],
            "outcome": outcome,
            "effects_count": 1 if outcome=="ONE_SYNTHETIC_EFFECT" else 0,
            "receipt_sha256": hashlib.sha256(node.encode()+b"receipt").hexdigest()
                              if outcome=="ONE_SYNTHETIC_EFFECT" else SHA0,
            "journal_sha256": hashlib.sha256(node.encode()+b"journal").hexdigest(),
            "measured_unix": NOW-10,
            "live_execution_allowed": False,
            **self.expect
        }

    @staticmethod
    def signed(payload, private):
        data=json.dumps(payload,sort_keys=True,ensure_ascii=True,
                        separators=(",",":"),allow_nan=False).encode("ascii")
        return {
            "payload":copy.deepcopy(payload),
            "signature_base64":base64.b64encode(private.sign(data)).decode("ascii")
        }

    def packet(self, node, outcome, **mod):
        payload=self.payload(node,outcome)
        payload.update(mod)
        return self.signed(payload,self.keys[node])

    def check(self, packets=None, pins=None, exp=None, now=NOW):
        return inspect_two_node_witnesses(
            self.packets if packets is None else packets,
            operator_pinned_nodes=self.pins if pins is None else pins,
            expected_trial=self.expect if exp is None else exp,
            now_unix=now
        )

    def test_valid_two_distinct_signatures_are_never_release_approval(self):
        result=self.check()
        self.assertEqual(result["signature_checks_passed"],2)
        self.assertEqual(result["status"],"TWO_SIGNED_CLAIMS_PASS_NOT_PHYSICAL_ATTESTATION")
        self.assertEqual(result["nodes_claimed"],["node-alpha","node-beta"])
        self.assertEqual(len(result["report_sha256"]),2)
        for name in (
            "hardware_distinctness_independently_proven",
            "external_operator_authorization_proven",
            "machine_key_custody_attested",
            "protected_server_lease_readback_proven",
            "independent_review_signoff_authenticated",
            "actual_two_physical_hosts_tested_by_this_check",
            "live_execution_allowed","release_approved",
            "publication_allowed","automatic_retry_allowed",
        ):
            self.assertIs(result[name],False,name)

    def test_reversed_arrival_order_is_allowed(self):
        self.assertEqual(self.check(list(reversed(self.packets)))["signature_checks_passed"],2)

    def test_untrusted_different_signer_rejected(self):
        swapped=[self.signed(self.packets[0]["payload"],self.b),self.packets[1]]
        with self.assertRaises(WitnessRejected):
            self.check(swapped)

    def test_node_duplicate_or_unknown_is_rejected(self):
        for pkt in ([self.packets[0],self.packets[0]],
                    [self.packets[0],self.packet("node-beta","DENIED_NO_EFFECT",
                                                 node_id="node-unknown")]):
            with self.subTest(pkt=pkt):
                with self.assertRaises(WitnessRejected):
                    self.check(pkt)

    def test_same_pinned_signer_key_refused_even_for_two_labels(self):
        p=copy.copy(self.pins)
        p["node-beta"]={**p["node-beta"],"public_key":self.a.public_key()}
        with self.assertRaises(WitnessRejected):
            self.check(pins=p)

    def test_same_claimed_physical_device_is_rejected(self):
        p=copy.copy(self.pins)
        p["node-beta"]={**p["node-beta"],
                        "physical_claim_sha256":p["node-alpha"]["physical_claim_sha256"]}
        with self.assertRaises(WitnessRejected):
            self.check(pins=p)

    def test_changed_challenge_core_host_source_and_content_denied(self):
        for field,value in (
            ("challenge_sha256","f"*64),
            ("core_sha40","f"*40),
            ("host_sha40","f"*40),
            ("content_sha256","f"*64),
            ("task_id","NF-DEV-05-Q992"),
            ("operation_id","nf-trial-other"),
            ("project_id","evil-project"),
        ):
            with self.subTest(field=field):
                a=self.packet("node-alpha","ONE_SYNTHETIC_EFFECT",**{field:value})
                with self.assertRaises(WitnessRejected):
                    self.check([a,self.packets[1]])

    def test_modified_signed_payload_is_rejected(self):
        altered=copy.deepcopy(self.packets)
        altered[0]["payload"]["journal_sha256"]="f"*64
        with self.assertRaises(WitnessRejected):
            self.check(altered)

    def test_both_winners_both_losers_and_nonsense_count_rejected(self):
        for packets in (
            [self.packet("node-alpha","ONE_SYNTHETIC_EFFECT"),
             self.packet("node-beta","ONE_SYNTHETIC_EFFECT")],
            [self.packet("node-alpha","DENIED_NO_EFFECT"),
             self.packet("node-beta","DENIED_NO_EFFECT")],
            [self.packet("node-alpha","ONE_SYNTHETIC_EFFECT",effects_count=2),
             self.packets[1]],
            [self.packet("node-alpha","ONE_SYNTHETIC_EFFECT",effects_count=True),
             self.packets[1]],
        ):
            with self.subTest(outcomes=[x["payload"]["outcome"] for x in packets]):
                with self.assertRaises(WitnessRejected):
                    self.check(packets)

    def test_attempt_nonce_replay_cross_node_denied(self):
        same=self.packets[0]["payload"]["attempt_nonce"]
        p=self.packet("node-beta","DENIED_NO_EFFECT",attempt_nonce=same)
        with self.assertRaises(WitnessRejected):
            self.check([self.packets[0],p])

    def test_old_future_or_boolean_timestamps_rejected(self):
        for measured in (NOW-301,NOW+301,True):
            with self.subTest(ts=measured):
                p=self.packet("node-beta","DENIED_NO_EFFECT",measured_unix=measured)
                with self.assertRaises(WitnessRejected):
                    self.check([self.packets[0],p])
        with self.assertRaises(WitnessRejected):
            self.check(now=True)

    def test_time_skew_between_two_nodes_denied(self):
        a=self.packet("node-alpha","ONE_SYNTHETIC_EFFECT",measured_unix=NOW-130)
        b=self.packet("node-beta","DENIED_NO_EFFECT",measured_unix=NOW+10)
        with self.assertRaises(WitnessRejected):
            self.check([a,b])

    def test_missing_and_extra_signed_fields_rejected(self):
        bad=copy.deepcopy(self.packets[0])
        bad["payload"].pop("operation_id")
        with self.assertRaises(WitnessRejected):
            self.check([bad,self.packets[1]])
        added=self.packet("node-alpha","ONE_SYNTHETIC_EFFECT",release_approved=True)
        with self.assertRaises(WitnessRejected):
            self.check([added,self.packets[1]])

    def test_bad_signature_and_truncated_envelope_rejected(self):
        for sig in ("","?"*88,"A"*88,123,None):
            with self.subTest(sig=sig):
                p=copy.deepcopy(self.packets[0])
                p["signature_base64"]=sig
                with self.assertRaises(WitnessRejected):
                    self.check([p,self.packets[1]])
        with self.assertRaises(WitnessRejected):
            self.check([{"payload":self.packets[0]["payload"]},self.packets[1]])

    def test_zero_receipt_for_winner_or_nonzero_loser_denied(self):
        for node,outcome,receipt in (
            ("node-alpha","ONE_SYNTHETIC_EFFECT",SHA0),
            ("node-beta","DENIED_NO_EFFECT","f"*64),
        ):
            with self.subTest(node=node):
                wrong=self.packet(node,outcome,receipt_sha256=receipt)
                packets=[wrong,self.packets[1]] if node=="node-alpha" else [self.packets[0],wrong]
                with self.assertRaises(WitnessRejected):
                    self.check(packets)

    def test_no_trust_pins_from_report_and_malformed_operator_input(self):
        with self.assertRaises(WitnessRejected):
            self.check(pins={})
        with self.assertRaises(WitnessRejected):
            self.check(pins={"node-alpha":{"public_key":self.a.public_key(),
                                           "physical_claim_sha256":self.pins["node-alpha"]["physical_claim_sha256"]},
                                  "node-beta":{"public_key":"caller-provided-key",
                                               "physical_claim_sha256":self.pins["node-beta"]["physical_claim_sha256"]}})
        with self.assertRaises(WitnessRejected):
            self.check(exp={**self.expect,"extra":True})

    def test_invalid_types_denied_not_crash_outside_error_type(self):
        for change in (
            {"outcome":[]},{"outcome":{}},{"effects_count":[]},
            {"physical_claim_sha256":[]},{"receipt_sha256":[]},
            {"live_execution_allowed":True},{"live_execution_allowed":1},
            {"attempt_nonce":[]},
        ):
            with self.subTest(change=change):
                pkt=self.packet("node-beta","DENIED_NO_EFFECT",**change)
                with self.assertRaises(WitnessRejected):
                    self.check([self.packets[0],pkt])

if __name__=="__main__":
    unittest.main()
