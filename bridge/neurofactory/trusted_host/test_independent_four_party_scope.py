"""Independent cryptographic verifier tests: no network, filesystem effects,
secrets persisted, production permissions or trusted physical machines."""
import base64
import copy
import hashlib
import json
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from independent_four_party_scope import (
    DOMAIN, ROLES, ProductionScopeRejected,
    inspect_signed_four_party_scope,
)

NOW = 1_800_000_000


def digest(v):
    return hashlib.sha256(v.encode()).hexdigest()


class FourPartyScopeTests(unittest.TestCase):
    def setUp(self):
        self.secret = {role: Ed25519PrivateKey.generate() for role in ROLES}
        self.pins = {role: k.public_key() for role, k in self.secret.items()}
        self.scope = dict(
            owner_id="owner-101",
            repository="DSLitvinov1/my_first_repo",
            github_user_id="151650108",
            repository_id="723328237",
            project_id="nf-sandbox",
            task_id="NF-DEV-05-Q999",
            operation_id="op-unique-12",
            worker_id="worker-01",
            source_sha40="a" * 40,
            source_file_sha256=digest("source"),
            target="bridge/neurofactory/development/core_owned/one_result.txt",
            content_sha256=digest("content"),
            policy_sha256=digest("policy"),
            lease_epoch=7,
            fencing_token_sha256=digest("fence"),
            idempotency_key=digest("idempotency"),
            challenge_sha256=digest("one-time challenge"),
        )
        raw=json.dumps(self.scope,sort_keys=True,separators=(",",":"),
                       allow_nan=False,ensure_ascii=True).encode("ascii")
        self.scope_hash=hashlib.sha256(raw).hexdigest()
        self.bodies={
            "operator":{
                "schema":"neurofactory.attested.operator.v1",
                "scope_sha256":self.scope_hash,
                "owner_id":self.scope["owner_id"],
                "repository":self.scope["repository"],
                "github_user_id":self.scope["github_user_id"],
                "repository_id":self.scope["repository_id"],
                "permission":"admin",
                "source":"AUTHENTICATED_GITHUB_API_OBSERVED_BY_OPERATOR",
                "checked_unix":NOW-4,
                "expires_unix":NOW+90,
            },
            "owner":{
                "schema":"neurofactory.attested.owner.v1",
                "scope_sha256":self.scope_hash,
                "expires_unix":NOW+50,
            },
            "host":{
                "schema":"neurofactory.attested.host.v1",
                "scope_sha256":self.scope_hash,
                "lease_epoch":7,
                "fencing_token_sha256":self.scope["fencing_token_sha256"],
                "state":"CLAIMED",
                "issued_unix":NOW-2,
                "expires_unix":NOW+15,
            },
            "witness":{
                "schema":"neurofactory.attested.witness.v1",
                "scope_sha256":self.scope_hash,
                "commit_sequence":12,
                "protected_journal_root_sha256":digest("witness-ledger-tip"),
                "reservation_status":"UNKNOWN_DURABLY_RESERVED_NO_AUTO_RETRY",
                "issued_unix":NOW-3,
                "expires_unix":NOW+45,
            },
        }
        self.packets={role:self.sign(role) for role in ROLES}

    def sign(self, role, body=None):
        p=copy.deepcopy(self.bodies[role] if body is None else body)
        raw=json.dumps(p,sort_keys=True,separators=(",",":"),
                       ensure_ascii=True,allow_nan=False).encode("ascii")
        sig=self.secret[role].sign(DOMAIN+role.encode()+b"\x00"+raw)
        return {"body":p, "signature_base64":base64.b64encode(sig).decode("ascii")}

    def check(self, *, pins=None, scope=None, docs=None, now=NOW):
        source=self.packets if docs is None else docs
        return inspect_signed_four_party_scope(
            pinned_public_keys=self.pins if pins is None else pins,
            expected_effect=self.scope if scope is None else scope,
            signed_operator_acl=source["operator"],
            signed_owner_grant=source["owner"],
            signed_host_lease=source["host"],
            signed_external_witness=source["witness"],now_unix=now)

    def with_field(self,role,field,value):
        docs=dict(self.packets)
        docs[role]=self.sign(role,{**self.bodies[role],field:value})
        return docs

    def test_positive_all_four_cryptographic_scopes_still_no_authority(self):
        r=self.check()
        self.assertEqual(r["signature_checks_passed"],4)
        self.assertEqual(r["status"],
                         "FOUR_PINNED_SIGNATURES_SCOPE_MATCH_NO_EXECUTION_AUTHORITY")
        self.assertEqual(len(set(r["pinned_public_key_sha256"].values())),4)
        self.assertEqual(len(r["signed_document_sha256"]),4)
        self.assertEqual(r["handoff"],"PAUSED_BY_USER")
        for k in (
            "external_live_github_acl_rechecked_here",
            "external_witness_durable_storage_observed_here",
            "real_hardware_key_custody_attested_here",
            "live_lease_locked_to_effect_here",
            "idempotency_persisted_outside_db_here",
            "actual_kernel_reboot_recovery_verified_here",
            "two_distinct_physical_nodes_proven_here",
            "independent_reviewer_approval_received_here",
            "live_execution_allowed",
            "release_approved",
            "automatic_retry_allowed",
            "production_execution_authority",
        ):
            self.assertIs(r[k],False,k)

    def test_attacker_invalid_signature_each_role_denied(self):
        for role in ROLES:
            with self.subTest(role=role):
                docs=dict(self.packets)
                foreign=Ed25519PrivateKey.generate()
                pkt=self.packets[role]
                docs[role]={"body":pkt["body"],"signature_base64":
                    base64.b64encode(foreign.sign(b"attacker")).decode()}
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=docs)

    def test_missing_operator_pins_or_key_reuse_denied(self):
        for keys in ({}, {**self.pins,"witness":self.pins["owner"]},
                     {**self.pins,"host":"fake key"}, self.pins | {"extra":self.pins["owner"]}):
            with self.subTest(keys=list(keys)):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(pins=keys)

    def test_signed_operator_wrong_owner_repo_or_permission_denied(self):
        for name,value in (
            ("owner_id","other-owner"),
            ("repository","Attacker/other_repo"),
            ("github_user_id","9999999"),
            ("repository_id","9999999"),
            ("permission","read"),
            ("source","UNTRUSTED_LOCAL_CALLBACK"),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=self.with_field("operator",name,value))

    def test_old_or_expired_operator_evidence_denied(self):
        for f,v in (("checked_unix",NOW-301),
                    ("checked_unix",NOW+1),
                    ("expires_unix",NOW),
                    ("expires_unix",NOW+400),
                    ("checked_unix",True)):
            with self.subTest(f=f,v=v):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=self.with_field("operator",f,v))

    def test_owner_grant_wrong_expiry_or_wrong_signer_denied(self):
        for v in (NOW-1,NOW+400,True,"1800000010"):
            with self.subTest(expires=v):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=self.with_field("owner","expires_unix",v))

    def test_host_stale_epoch_fencing_or_claim_denied(self):
        for f,v in (("lease_epoch",8),("lease_epoch",True),
                    ("fencing_token_sha256","f"*64),
                    ("state","UNKNOWN"),
                    ("issued_unix",NOW-100),
                    ("expires_unix",NOW)):
            with self.subTest(f=f,v=v):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=self.with_field("host",f,v))

    def test_witness_missing_durable_ack_or_bad_ledger_denied(self):
        for f,v in (
            ("reservation_status","COMPLETED_TEST"),
            ("commit_sequence",0),
            ("commit_sequence",True),
            ("protected_journal_root_sha256","not_sha"),
            ("issued_unix",NOW-120),
            ("expires_unix",NOW),
        ):
            with self.subTest(f=f):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=self.with_field("witness",f,v))

    def test_wrong_scope_and_source_even_with_correct_four_keys_denied(self):
        for f,v in (
            ("repository","Attacker/other"),
            ("source_sha40","b"*40),
            ("source_file_sha256","b"*64),
            ("content_sha256","b"*64),
            ("task_id","NF-DEV-05-Q998"),
            ("operation_id","op-unique-13"),
            ("idempotency_key","b"*64),
            ("lease_epoch",8),
            ("challenge_sha256","b"*64),
        ):
            with self.subTest(f=f):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(scope={**self.scope,f:v})

    def test_path_traversal_and_noncanonical_scope_denied(self):
        for path in ("../../etc/passwd",
                     "bridge/neurofactory/development/core_owned/../other.py",
                     "bridge/neurofactory/development/core_owned/.hidden",
                     "bridge/neurofactory/development/core_owned/out\\evil",
                     "/tmp/evil"):
            with self.subTest(path=path):
                with self.assertRaises(ProductionScopeRejected):
                    self.check(scope={**self.scope,"target":path})

    def test_extra_missing_wrong_type_signatures_denied(self):
        for role in ROLES:
            with self.subTest(role=role):
                p=copy.deepcopy(self.packets)
                p[role]["body"]["extra"]={"release_approved":True}
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=p)
        for raw in ("",None,True,"?"*88,123):
            with self.subTest(sig=raw):
                p=copy.deepcopy(self.packets)
                p["host"]["signature_base64"]=raw
                with self.assertRaises(ProductionScopeRejected):
                    self.check(docs=p)

    def test_fixture_mode_flags_cannot_grant_execution(self):
        with patch.dict(os.environ,{"NF_RECEIVER_OS_FIXTURE_ONLY":"1",
                                    "NF_OPERATOR_ANCHOR_FIXTURE_ONLY":"1",
                                    "NF_HOST_RECEIVER_FIXTURE_ONLY":"1"}):
            r=self.check()
            self.assertFalse(r["live_execution_allowed"])
            self.assertFalse(r["production_execution_authority"])

    def test_boolean_expiry_and_external_report_replay_do_not_approve(self):
        with self.assertRaises(ProductionScopeRejected):
            self.check(now=True)
        # A pure signature verifier cannot ensure persistent one-use storage.
        # An identical second verification must NEVER be described as an
        # authorized second effect.
        for _ in range(2):
            self.assertFalse(self.check()["live_execution_allowed"])
            self.assertFalse(self.check()["automatic_retry_allowed"])

    def test_mismatched_key_owner_witness_signatures_not_interchangeable(self):
        docs=dict(self.packets)
        docs["owner"]=self.packets["witness"]
        with self.assertRaises(ProductionScopeRejected):
            self.check(docs=docs)


if __name__ == "__main__":
    unittest.main()
