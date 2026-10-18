"""Synthetic signatures test document consistency; never physical Windows attestation."""
import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from windows_two_node_evidence_validator import (
    EvidenceRejected, canonical, sha, check, main,
)

DOMAIN=b"NF_TWO_NODE_EVIDENCE_V1\x00"
ROOT0="0"*64
ROOT1="1"*64
ROOT2="2"*64

class EvidenceValidatorTests(unittest.TestCase):
    def setUp(self):
        self.keys={r:Ed25519PrivateKey.generate() for r in
                   ("operator","a","b","reviewer")}
        self.pins={role:base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
            for role,key in self.keys.items()}
        self.sources={"core":"a"*40,"host":"b"*40,"witness":"c"*40}
        self.scope={
            "core_sha":self.sources["core"],"host_sha":self.sources["host"],
            "witness_sha":self.sources["witness"],
            "node_a":"hardware-A-enrollment-ref",
            "node_b":"hardware-B-enrollment-ref",
        }
        fp=sha(self.scope)
        def envelope(role, body):
            return {"body":body,"signature_base64":self.sign(role,body)}
        def report(role, phase, when, root=ROOT0, seq=0):
            body={
                "schema":"nf.two_node.device_report.v1",
                "scope_sha256":fp,
                "device_id":self.scope["node_a" if role=="a" else "node_b"],
                "role":"RECEIVER_A" if role=="a" else "WITNESS_B",
                "phase":phase,
                "boot_marker":("A" if role=="a" else "B") +
                              ("-boot-before-ID-01" if phase=="BEFORE"
                               else "-boot-after-ID-02"),
                "observed_utc":"2026-10-18T08:00:00Z" if phase=="BEFORE"
                               else "2026-10-18T10:00:00Z",
            }
            if role=="b":
                body["ledger_sequence"]=seq
                body["ledger_root_sha256"]=root
            return envelope(role,body)
        operator={
            "schema":"nf.two_node.operator.v1", "scope_sha256":fp,
            "physical_test_authorized":True,
            "production_execution_authorized":False,
        }
        review={
            "schema":"nf.two_node.independent_review.v1",
            "scope_sha256":fp,"decision":"APPROVE_SANDBOX_ONLY",
            "reviewed_utc":"2026-10-18T11:00:00Z",
            "reviewed_core_sha":self.sources["core"],
            "reviewed_host_sha":self.sources["host"],
            "reviewed_witness_sha":self.sources["witness"],
        }
        trials=[]
        for i,case in enumerate((
                "FORGED_OWNER","WRONG_PEER_IDENTITY","EXPIRED_FENCE",
                "LOST_ACK","ONE_SUCCESS","DB_ROLLBACK_REPLAY")):
            seq=0 if i<=2 else 1 if i==3 else 2
            root=ROOT0 if seq==0 else ROOT1 if seq==1 else ROOT2
            body={
                "schema":"nf.two_node.case.v1","scope_sha256":fp,
                "case":case,
                "outcome":"COMPLETED_INERT_ONLY" if case=="ONE_SUCCESS"
                          else "UNKNOWN_NO_RETRY" if case=="LOST_ACK"
                          else "DENIED",
                "file_delta":1 if case=="ONE_SUCCESS" else 0,
                "witness_sequence":seq,
                "witness_root_sha256":root,
                "auto_retry_allowed":False,
                "observed_utc":"2026-10-18T09:0"+str(i)+":00Z",
            }
            trials.append({"body":body,"signature_a":self.sign("a",body),
                           "signature_b":self.sign("b",body)})
        self.manifest={
            "schema":"nf.windows.two_node_evidence.v1",
            "scope":self.scope,
            "operator":envelope("operator",operator),
            "a_before":report("a","BEFORE",""),
            "a_after":report("a","AFTER",""),
            "b_before":report("b","BEFORE","",ROOT0,0),
            "b_after":report("b","AFTER","",ROOT2,2),
            "trials":trials,
            "review":envelope("reviewer",review),
        }

    def sign(self, role, body):
        return base64.b64encode(self.keys[role].sign(DOMAIN+canonical(body))).decode()

    def resign(self, path, role):
        body=self.manifest[path]["body"]
        self.manifest[path]["signature_base64"]=self.sign(role,body)

    def resign_trial(self, i):
        body=self.manifest["trials"][i]["body"]
        self.manifest["trials"][i]["signature_a"]=self.sign("a",body)
        self.manifest["trials"][i]["signature_b"]=self.sign("b",body)

    def invoke(self):
        return check(self.manifest,self.pins,self.sources)

    def test_synthetic_complete_signatures_never_grant_production(self):
        report=self.invoke()
        self.assertTrue(report["signed_claims_structurally_consistent"])
        self.assertEqual(report["status"],
                         "DOCUMENTARY_CONSISTENCY_ONLY_NOT_RELEASE_AUTHORITY")
        for field in ("physical_devices_independently_attested",
                      "protected_key_custody_independently_attested",
                      "actual_os_reboots_independently_attested",
                      "can_install_services","can_reboot_devices",
                      "can_enable_production_queue","can_resume_handoff",
                      "production_release_allowed"):
            self.assertIs(report[field],False)

    def test_missing_or_forged_operator_approval_denied(self):
        self.manifest["operator"]["body"]["physical_test_authorized"]=False
        with self.assertRaises(EvidenceRejected):self.invoke()
        self.manifest["operator"]["body"]["physical_test_authorized"]=True
        self.resign("operator","operator")
        self.manifest["operator"]["body"]["production_execution_authorized"]=True
        self.resign("operator","operator")
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_unenrolled_or_same_identity_signer_denied(self):
        self.pins["b"]=self.pins["a"]
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_same_physical_machine_id_claim_denied(self):
        self.scope["node_b"]=self.scope["node_a"]
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_no_real_boot_marker_change_denied(self):
        self.manifest["a_after"]["body"]["boot_marker"]=(
            self.manifest["a_before"]["body"]["boot_marker"])
        self.resign("a_after","a")
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_invalid_boot_time_order_denied(self):
        self.manifest["b_after"]["body"]["observed_utc"]="2026-10-17T08:00:00Z"
        self.resign("b_after","b")
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_no_witness_highwater_after_restart_denied(self):
        self.manifest["b_after"]["body"]["ledger_sequence"]=0
        self.resign("b_after","b")
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_forged_witness_signature_denied(self):
        self.manifest["b_after"]["signature_base64"]=self.sign(
            "a",self.manifest["b_after"]["body"])
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_wrong_exact_source_sha_denied(self):
        changed=dict(self.sources, host="f"*40)
        with self.assertRaises(EvidenceRejected):
            check(self.manifest,self.pins,changed)

    def test_missing_review_signature_denied(self):
        self.manifest["review"]["signature_base64"]="A"*88
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_unrecognized_production_review_verdict_denied(self):
        self.manifest["review"]["body"]["decision"]="APPROVE_PRODUCTION"
        self.resign("review","reviewer")
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_only_five_trials_instead_of_six_denied(self):
        self.manifest["trials"].pop()
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_duplicate_success_and_replay_denied(self):
        self.manifest["trials"][5]["body"]["case"]="ONE_SUCCESS"
        self.resign_trial(5)
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_lost_ack_must_advance_witness_highwater(self):
        self.manifest["trials"][3]["body"]["witness_sequence"]=0
        self.manifest["trials"][3]["body"]["witness_root_sha256"]=ROOT0
        self.resign_trial(3)
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_replay_must_not_advance_witness_highwater(self):
        self.manifest["trials"][5]["body"]["witness_sequence"]=3
        self.manifest["trials"][5]["body"]["witness_root_sha256"]="3"*64
        self.resign_trial(5)
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_single_forged_trial_signer_denied(self):
        self.manifest["trials"][4]["signature_b"]=self.sign(
            "a", self.manifest["trials"][4]["body"])
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_untrusted_manifest_keys_are_not_used_as_pins(self):
        fake=Ed25519PrivateKey.generate()
        self.manifest["owner_public"]=base64.b64encode(
            fake.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        with self.assertRaises(EvidenceRejected):self.invoke()

    def test_cli_never_returns_success_even_with_consistent_synthetic_input(self):
        with tempfile.TemporaryDirectory(prefix="nf-evidence-ci-") as root:
            paths=[]
            for name,data in (("manifest",self.manifest),
                              ("pins",self.pins),("sources",self.sources)):
                p=Path(root)/(name+".json")
                p.write_text(json.dumps(data),encoding="utf-8")
                paths.append(str(p))
            from unittest.mock import patch
            with patch("sys.argv",["validator","--manifest",paths[0],
                 "--trusted-pins",paths[1],"--expected-sources",paths[2]]):
                self.assertEqual(main(),2)

if __name__=="__main__":
    unittest.main()
