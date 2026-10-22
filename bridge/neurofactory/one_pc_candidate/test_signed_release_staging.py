"""New and ONLY relevant release-staging tests. No model, SCM or live install."""
from __future__ import annotations
import base64
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from signed_release_staging import (
    BASE_FIELDS, DOMAIN_OWNER, DOMAIN_REVIEW, INSTALLER_SOURCE_COMMIT,
    SCHEMA, SCOPE, StagingDenied, _canon, _privileged_acl,
    operator_stage_signed_candidate, verify_two_person_signatures,
)

NOW=1792640000

def pub(key):
    return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)

class ExactReviewedQuarantine(unittest.TestCase):
    def setUp(self):
        self.owner=Ed25519PrivateKey.generate()
        self.reviewer=Ed25519PrivateKey.generate()
        self.owner_public=pub(self.owner)
        self.review_public=pub(self.reviewer)
        self.base={
            "schema":SCHEMA,
            "scope":SCOPE,
            "source_commit":INSTALLER_SOURCE_COMMIT,
            "installer_sha256":"648dc60f51390578c1835ca46b5151b61f1cb64858c34d6e164a8092381e35cf",
            "installer_run_id":39701930342,
            "scm_run_id":39702159425,
            "qwen_run_id":39702865907,
            "nonce":"a"*32,
            "issued_unix":NOW-5,
            "expires_unix":NOW+200,
        }

    def approve(self,body=None):
        b=deepcopy(self.base if body is None else body)
        return {**b,
            "owner_signature_base64":base64.b64encode(
                self.owner.sign(DOMAIN_OWNER+_canon(b))).decode(),
            "reviewer_signature_base64":base64.b64encode(
                self.reviewer.sign(DOMAIN_REVIEW+_canon(b))).decode(),
        }

    def verify(self,app,owner=None,reviewer=None,now=NOW,expected=None):
        return verify_two_person_signatures(
            app,
            self.owner_public if owner is None else owner,
            self.review_public if reviewer is None else reviewer,
            expected_source_commit=expected or INSTALLER_SOURCE_COMMIT,now=now)

    def test_two_actual_independent_signatures_only_stage_never_execution(self):
        received=self.verify(self.approve())
        self.assertTrue(received["owner_approved_exact_staging"])
        self.assertTrue(received["reviewer_approved_exact_staging"])
        self.assertEqual(received["status"],"TWO_PERSON_SIGNATURES_VERIFIED_QUARANTINE_ONLY")
        for k in ("production_execution_authorized",
                  "service_enrollment_authorized","automated_install_authorized",
                  "live_qwen_core_host_authority",
                  "independent_physical_acceptance_complete",
                  "external_antirollback_witness_verified"):
            self.assertFalse(received[k],k)
        print("NF_TWO_DISTINCT_INDEPENDENT_ED25519_STAGING_SIGNERS=PASS_NOT_PRODUCTION")

    def test_reviewer_signature_forgery_and_owner_signature_forgery(self):
        signed=self.approve()
        for signer_field in ("reviewer_signature_base64","owner_signature_base64"):
            altered=deepcopy(signed)
            altered[signer_field]=base64.b64encode(
                Ed25519PrivateKey.generate().sign(b"not a valid scope")).decode()
            with self.subTest(signer_field=signer_field),self.assertRaises(StagingDenied):
                self.verify(altered)

    def test_wrong_reviewed_source_artifact_digest_and_evidence_run(self):
        for field,replacement in (
                ("source_commit","0"*40),
                ("installer_sha256","f"*64),
                ("installer_run_id",42),
                ("scm_run_id",1),
                ("qwen_run_id",11)):
            body={**self.base,field:replacement}
            with self.subTest(field=field),self.assertRaises(StagingDenied):
                self.verify(self.approve(body))

    def test_scope_nonce_expiry_rollback_and_excessive_lifetime_denied(self):
        for field,value in (
                ("scope","PRODUCTION_EXECUTION_ALLOWED"),
                ("nonce","abc"),
                ("expires_unix",NOW-1),
                ("expires_unix",NOW+100000),
                ("issued_unix",NOW+50)):
            body={**self.base,field:value}
            with self.subTest(field=field,value=value),self.assertRaises(StagingDenied):
                self.verify(self.approve(body))

    def test_two_people_must_not_share_one_key(self):
        with self.assertRaises(StagingDenied):
            self.verify(self.approve(),reviewer=self.owner_public)
        with self.assertRaises(StagingDenied):
            self.verify(self.approve(),owner=self.review_public)

    def test_signature_domain_separation_prevents_role_swap(self):
        altered=self.approve()
        altered["owner_signature_base64"],altered["reviewer_signature_base64"]=(
            altered["reviewer_signature_base64"],altered["owner_signature_base64"])
        with self.assertRaises(StagingDenied):
            self.verify(altered)

    def test_duplicate_key_extraneous_field_and_invalid_encoding(self):
        packet=self.approve()
        for extra in ({"extra":"unreviewed"}, {"scope":True}):
            with self.subTest(extra=extra),self.assertRaises(StagingDenied):
                self.verify({**packet,**extra})
        packet["reviewer_signature_base64"]="*bad*"
        with self.assertRaises(StagingDenied):
            self.verify(packet)

    def test_wrong_expected_source_must_not_validate(self):
        with self.assertRaises(StagingDenied):
            self.verify(self.approve(),expected="d"*40)

    def test_nonwindows_operator_staging_fails_before_fs_mutation(self):
        if os.name!="nt":
            with tempfile.TemporaryDirectory() as d:
                p=Path(d)
                with self.assertRaises(StagingDenied):
                    operator_stage_signed_candidate(
                        p/"not-a-real-installer.exe",p/"not-real.json",
                        expected_source_commit=INSTALLER_SOURCE_COMMIT)
                self.assertEqual(list(p.iterdir()),[])

if __name__=="__main__":
    unittest.main()
