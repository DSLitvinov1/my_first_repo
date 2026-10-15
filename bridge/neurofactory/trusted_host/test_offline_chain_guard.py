import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from offline_issuer import IssuerBoundaryError,sign_offline_fixture,verify_with_externally_pinned_state
from offline_chain_guard import verify_pinned_chain

TASK="NF-DEV-05-Q001"
CORE="a"*40
GENESIS="0"*64

def payload(seq,prev):
    return dict(schema="neurofactory.trusted_checkpoint_event.v1",
                task_id=TASK,project_id="nf-sandbox",input_core_sha40=CORE,
                source_file_sha256="b"*64,input_task_sha256="c"*64,
                policy_sha256="9"*64,target="src/test_part.py",
                event_kind="AUTHORIZE_TASK",event_sequence=seq,
                prior_event_digest_sha256=prev,core_checkpoint_digest_sha256="d"*64,
                issuer_identity="issuer-test-id",issuer_key_id="test-key-01",
                issued_at_utc="2026-10-15T00:00:00Z")

class OfflineChainGuardTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.pin=dict(expected_task_id=TASK,expected_core_sha40=CORE,
                      expected_issuer_identity="issuer-test-id",
                      expected_key_id="test-key-01",
                      expected_project_id="nf-sandbox",
                      expected_source_file_sha256="b"*64,
                      expected_input_task_sha256="c"*64,
                      expected_policy_sha256="9"*64,
                      expected_target="src/test_part.py")
        first=sign_offline_fixture(self.key,payload(1,GENESIS))
        first_digest=verify_with_externally_pinned_state(
            self.key.public_key(),first,
            externally_pinned_prev_digest=GENESIS,
            externally_pinned_next_sequence=1,**self.pin
        )["reported_receipt_digest_sha256"]
        second=sign_offline_fixture(self.key,payload(2,first_digest))
        second_digest=verify_with_externally_pinned_state(
            self.key.public_key(),second,
            externally_pinned_prev_digest=first_digest,
            externally_pinned_next_sequence=2,**self.pin
        )["reported_receipt_digest_sha256"]
        self.entries=[first,second]
        self.kw=dict(trusted_public_key=self.key.public_key(),signed_events=self.entries,
                     externally_pinned_genesis_digest=GENESIS,
                     externally_pinned_start_sequence=1,
                     externally_pinned_final_sequence=2,
                     externally_pinned_final_digest=second_digest,**self.pin)

    def check(self,**replacement):
        x=dict(self.kw);x.update(replacement)
        return verify_pinned_chain(**x)

    def test_complete_two_link_chain_has_no_live_rights(self):
        x=self.check()
        self.assertEqual(x["verified_links"],2)
        for f in ("external_issuer_deployed","independent_external_pin_attested",
                  "antirollback_storage_implemented","live_execution_allowed",
                  "automatic_retry_allowed","publication_allowed"):
            self.assertIs(x[f],False)

    def test_truncated_chain_fails_when_external_final_head_pinned(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed_events=self.entries[:1])

    def test_duplicate_first_link_fails(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed_events=[self.entries[0],self.entries[0]])

    def test_reordered_entries_fail(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed_events=list(reversed(self.entries)))

    def test_valid_re_signed_rollback_still_fails_final_head(self):
        alt=sign_offline_fixture(self.key,payload(1,GENESIS))
        self.assertNotIn("private_key",self.check())
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_final_digest="f"*64)

    def test_wrong_policy_pin_fails_even_with_valid_signature(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(expected_policy_sha256="f"*64)

    def test_wrong_signed_project_scope_fails(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(expected_project_id="other-project")

    def test_wrong_signer_fails(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(trusted_public_key=Ed25519PrivateKey.generate().public_key())

    def test_bool_and_float_final_sequence_fail(self):
        for x in (True,2.0,"2"):
            with self.subTest(x=x),self.assertRaises(IssuerBoundaryError):
                self.check(externally_pinned_final_sequence=x)

    def test_final_digest_not_sha256_fails(self):
        for x in ("not-a-digest","f"*63,"F"*64,True):
            with self.subTest(x=str(x)),self.assertRaises(IssuerBoundaryError):
                self.check(externally_pinned_final_digest=x)

    def test_empty_or_wrong_length_fails_closed(self):
        for x in ([],self.entries[:1],self.entries+[self.entries[0]]):
            with self.subTest(n=len(x)),self.assertRaises(IssuerBoundaryError):
                self.check(signed_events=x)

    def test_signed_records_unchanged(self):
        prior=copy.deepcopy(self.entries)
        self.check()
        self.assertEqual(self.entries,prior)
if __name__=="__main__":unittest.main()
