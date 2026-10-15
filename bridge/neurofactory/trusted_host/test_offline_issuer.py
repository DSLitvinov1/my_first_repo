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

    def effect(self, kind="EFFECT_READBACK", epoch=7, key="e"*64):
        p=event()
        p["event_kind"]=kind
        p["lease_epoch"]=epoch
        p["worker_id"]="worker-test"
        p["fencing_token_sha256"]="f"*64
        p["idempotency_key"]=key
        return p

    def verify_effect(self, signed, epoch=7, key="e"*64,
                      worker="worker-test", fence="f"*64):
        return verify_with_externally_pinned_state(
            self.public,signed,expected_task_id=TASK,
            expected_core_sha40=CORE,
            expected_issuer_identity="issuer-test-id",
            expected_key_id="test-key-01",
            externally_pinned_prev_digest=PREV,
            externally_pinned_next_sequence=1,
            externally_pinned_lease_epoch=epoch,
            externally_pinned_worker_id=worker,
            externally_pinned_fencing_token_sha256=fence,
            externally_pinned_idempotency_key=key
        )

    def test_real_signature_with_proper_effect_binding_remains_non_live(self):
        p=self.effect()
        signed=sign_offline_fixture(self.key,p)
        v=self.verify_effect(signed)
        self.assertTrue(v["lease_and_effect_binding_reported"])
        self.assertFalse(v["external_anchor_provenance_supplied_by_host"])
        self.assertFalse(v["live_execution_allowed"])

    def test_real_signature_without_lease_epoch_is_rejected(self):
        p=self.effect()
        del p["lease_epoch"]
        with self.assertRaises(IssuerBoundaryError):
            sign_offline_fixture(self.key,p)

    def test_real_signature_without_idempotency_key_is_rejected(self):
        p=self.effect()
        del p["idempotency_key"]
        with self.assertRaises(IssuerBoundaryError):
            sign_offline_fixture(self.key,p)

    def test_valid_signature_for_old_epoch_denied_by_pinned_state(self):
        signed=sign_offline_fixture(self.key,self.effect(epoch=6))
        with self.assertRaises(IssuerBoundaryError):
            self.verify_effect(signed,epoch=7)

    def test_valid_signature_for_other_effect_key_denied(self):
        signed=sign_offline_fixture(self.key,self.effect(key="a"*64))
        with self.assertRaises(IssuerBoundaryError):
            self.verify_effect(signed,key="e"*64)

    def test_valid_signature_for_other_worker_or_token_denied(self):
        signed=sign_offline_fixture(self.key,self.effect())
        for kwargs in ({"worker":"worker-other"},{"fence":"a"*64}):
            with self.subTest(kwargs=kwargs),self.assertRaises(IssuerBoundaryError):
                self.verify_effect(signed,**kwargs)

    def test_pinned_values_must_be_provided_for_effect(self):
        signed=sign_offline_fixture(self.key,self.effect())
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed)
        with self.assertRaises(IssuerBoundaryError):
            self.verify_effect(signed,key=None)

    def test_bool_or_float_epoch_denied_even_under_valid_key(self):
        for value in (True,7.0,"7",0):
            p=self.effect(epoch=value)
            with self.subTest(value=value),self.assertRaises(IssuerBoundaryError):
                sign_offline_fixture(self.key,p)

    def test_mismatched_event_specific_fields_denied(self):
        for kind in ("LEASE_CLAIM","PRE_SIDE_EFFECT","EFFECT_READBACK","MANUAL_STOP"):
            p=self.effect(kind)
            if kind in ("LEASE_CLAIM","MANUAL_STOP"):
                p.pop("idempotency_key")
            signed=sign_offline_fixture(self.key,p)
            if kind in ("PRE_SIDE_EFFECT","EFFECT_READBACK"):
                self.assertTrue(self.verify_effect(signed)["lease_and_effect_binding_reported"])
            else:
                result=verify_with_externally_pinned_state(
                    self.public,signed,
                    expected_task_id=TASK,expected_core_sha40=CORE,
                    expected_issuer_identity="issuer-test-id",
                    expected_key_id="test-key-01",
                    externally_pinned_prev_digest=PREV,
                    externally_pinned_next_sequence=1,
                    externally_pinned_lease_epoch=7,
                    externally_pinned_worker_id="worker-test",
                    externally_pinned_fencing_token_sha256="f"*64
                )
                self.assertTrue(result["lease_and_effect_binding_reported"])
            x=dict(p)
            if kind in ("LEASE_CLAIM","MANUAL_STOP"):
                x["idempotency_key"]="e"*64
            else:
                x.pop("idempotency_key")
            with self.subTest(kind=kind),self.assertRaises(IssuerBoundaryError):
                sign_offline_fixture(self.key,x)

    def test_pinned_bool_epoch_always_denied(self):
        signed=sign_offline_fixture(self.key,self.effect())
        with self.assertRaises(IssuerBoundaryError):
            self.verify_effect(signed,epoch=True)

if __name__=="__main__":
    unittest.main()
