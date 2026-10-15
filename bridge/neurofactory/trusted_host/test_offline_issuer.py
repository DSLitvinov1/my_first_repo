"""Adversarial tests of offline-only signed-link format (keys generated in memory)."""
import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offline_issuer import (
    IssuerBoundaryError, sign_offline_fixture,
    verify_with_externally_pinned_state
)

TASK="NF-DEV-05-Q001"
CORE="a"*40
PREV="0"*64

def event(seq=1,prev=PREV):
    return {"schema":"neurofactory.trusted_checkpoint_event.v1",
            "task_id":TASK,"project_id":"nf-sandbox",
            "input_core_sha40":CORE,"source_file_sha256":"b"*64,
            "input_task_sha256":"c"*64,"event_kind":"AUTHORIZE_TASK",
            "event_sequence":seq,"prior_event_digest_sha256":prev,
            "core_checkpoint_digest_sha256":"d"*64,
            "issuer_identity":"issuer-test-id","issuer_key_id":"test-key-01",
            "issued_at_utc":"2026-10-15T00:00:00Z"}

class OfflineIssuerTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.public=self.key.public_key()

    def check(self,signed,seq=1,prev=PREV,pub=None,core=CORE):
        return verify_with_externally_pinned_state(
            pub if pub is not None else self.public,signed,
            expected_task_id=TASK,expected_core_sha40=core,
            expected_issuer_identity="issuer-test-id",
            expected_key_id="test-key-01",
            externally_pinned_prev_digest=prev,
            externally_pinned_next_sequence=seq
        )

    def test_one_valid_link_still_never_authorizes_real_execution(self):
        signed=sign_offline_fixture(self.key,event())
        out=self.check(signed)
        self.assertEqual(out["event_sequence"],1)
        self.assertTrue(out["matches_supplied_external_anchor"])
        for label in ("separate_signer_host_attested","live_execution_allowed",
                      "publication_allowed","automatic_retry_allowed"):
            self.assertFalse(out[label])
        self.assertEqual(out["handoff"],"PAUSED_BY_USER")

    def test_next_link_requires_exact_externally_pinned_parent(self):
        first=self.check(sign_offline_fixture(self.key,event()))
        head=first["reported_receipt_digest_sha256"]
        later=sign_offline_fixture(self.key,event(2,head))
        self.assertEqual(self.check(later,2,head)["event_sequence"],2)
        with self.assertRaises(IssuerBoundaryError):self.check(later,2,PREV)

    def test_replay_of_previous_sequence_rejected(self):
        signed=sign_offline_fixture(self.key,event())
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed,2,"e"*64)

    def test_wrong_public_key_rejected(self):
        fake=Ed25519PrivateKey.generate()
        signed=sign_offline_fixture(fake,event())
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed)

    def test_fake_public_verifier_object_rejected(self):
        class FakeVerifier:
            def verify(self,*args):return None
        signed=sign_offline_fixture(self.key,event())
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed,pub=FakeVerifier())

    def test_tampered_content_after_signature_rejected(self):
        signed=sign_offline_fixture(self.key,event())
        signed["payload"]["source_file_sha256"]="f"*64
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed)

    def test_bool_sequence_or_float_sequence_rejected(self):
        for value in (True,1.0,"1"):
            p=event();p["event_sequence"]=value
            with self.subTest(v=value),self.assertRaises(IssuerBoundaryError):
                sign_offline_fixture(self.key,p)

    def test_rogue_approve_or_field_injection_rejected(self):
        for rogue in ("REVIEW_OK","PUBLISHED",[],True):
            p=event();p["event_kind"]=rogue
            with self.subTest(value=str(rogue)),self.assertRaises(IssuerBoundaryError):
                sign_offline_fixture(self.key,p)
        p=event();p["execution_allowed"]=True
        with self.assertRaises(IssuerBoundaryError):
            sign_offline_fixture(self.key,p)

    def test_wrong_source_sha_rejected(self):
        signed=sign_offline_fixture(self.key,event())
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed,core="f"*40)

    def test_wrong_signature_encoding_rejected(self):
        signed=sign_offline_fixture(self.key,event())
        signed["signature_base64"]="invalid!!!"
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed)

    def test_unauthorized_claim_approval_cannot_be_derived(self):
        signed=sign_offline_fixture(self.key,event())
        original=copy.deepcopy(signed)
        out=self.check(signed)
        self.assertEqual(signed,original)
        self.assertFalse(out["external_anchor_provenance_supplied_by_host"])
        self.assertNotIn("issuer_secret",out)
        self.assertNotIn("approved",out)
        self.assertFalse(out["publication_allowed"])

    def test_signed_record_cannot_claim_external_provenance_via_field(self):
        signed=sign_offline_fixture(self.key,event())
        signed["issuer_attested"]=True
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed)

if __name__=="__main__":
    unittest.main()
