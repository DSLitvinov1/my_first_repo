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
                     externally_pinned_final_digest=second_digest,
                     externally_pinned_event_contexts=[
                         {"event_kind":"AUTHORIZE_TASK"},
                         {"event_kind":"AUTHORIZE_TASK"}],**self.pin)

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

class MixedLifecycleChainTests(unittest.TestCase):
    """Each expected lease/effect context comes from the independent fixture."""
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
        self.fence="7"*64
        self.effect="e"*64
        self.contexts=[
            {"event_kind":"AUTHORIZE_TASK"},
            {"event_kind":"LEASE_CLAIM","lease_epoch":9,"worker_id":"host-1",
             "fencing_token_sha256":self.fence},
            {"event_kind":"EFFECT_READBACK","lease_epoch":9,"worker_id":"host-1",
             "fencing_token_sha256":self.fence,"idempotency_key":self.effect}
        ]
        parent=GENESIS
        self.signed=[]
        for i,(kind,params) in enumerate(zip(
                ("AUTHORIZE_TASK","LEASE_CLAIM","EFFECT_READBACK"),
                self.contexts),1):
            rec=payload(i,parent)
            rec["event_kind"]=kind
            if "lease_epoch" in params:
                rec.update(lease_epoch=params["lease_epoch"],
                           worker_id=params["worker_id"],
                           fencing_token_sha256=params["fencing_token_sha256"])
            if "idempotency_key" in params:
                rec["idempotency_key"]=params["idempotency_key"]
            signed=sign_offline_fixture(self.key,rec)
            single=verify_with_externally_pinned_state(
                self.key.public_key(),signed,externally_pinned_prev_digest=parent,
                externally_pinned_next_sequence=i,
                externally_pinned_lease_epoch=params.get("lease_epoch"),
                externally_pinned_worker_id=params.get("worker_id"),
                externally_pinned_fencing_token_sha256=params.get("fencing_token_sha256"),
                externally_pinned_idempotency_key=params.get("idempotency_key"),
                **self.pin)
            parent=single["reported_receipt_digest_sha256"]
            self.signed.append(signed)
        self.kw=dict(trusted_public_key=self.key.public_key(),
                     signed_events=self.signed,
                     externally_pinned_genesis_digest=GENESIS,
                     externally_pinned_start_sequence=1,
                     externally_pinned_final_sequence=3,
                     externally_pinned_final_digest=parent,
                     externally_pinned_event_contexts=self.contexts,**self.pin)

    def check(self,**overrides):
        d=dict(self.kw)
        d.update(overrides)
        return verify_pinned_chain(**d)

    def test_exact_three_kind_chain_passes_but_remains_nonlive(self):
        result=self.check()
        self.assertEqual(result["verified_links"],3)
        self.assertIs(result["live_execution_allowed"],False)
        self.assertIs(result["antirollback_storage_implemented"],False)

    def test_stale_lease_epoch_does_not_validate_signed_chain(self):
        p=copy.deepcopy(self.contexts)
        p[1]["lease_epoch"]=8
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_event_contexts=p)

    def test_other_idempotency_key_is_rejected(self):
        p=copy.deepcopy(self.contexts)
        p[2]["idempotency_key"]="f"*64
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_event_contexts=p)

    def test_mismatched_expected_event_kind_is_rejected(self):
        p=copy.deepcopy(self.contexts)
        p[0]["event_kind"]="LEASE_CLAIM"
        p[0].update(lease_epoch=9,worker_id="host-1",fencing_token_sha256=self.fence)
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_event_contexts=p)

    def test_unpinned_context_or_malformed_pin_shape_rejected(self):
        for contexts in (None,[],self.contexts[:2],
                         [{"event_kind":"AUTHORIZE_TASK"}]*3):
            with self.subTest(ctx=str(contexts)),self.assertRaises(IssuerBoundaryError):
                self.check(externally_pinned_event_contexts=contexts)

    def test_extra_privilege_on_authorize_context_rejected(self):
        p=copy.deepcopy(self.contexts)
        p[0]["idempotency_key"]=self.effect
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_event_contexts=p)

    def test_wrong_worker_and_fence_do_not_validate(self):
        for attr,value in (("worker_id","host-2"),("fencing_token_sha256","8"*64)):
            p=copy.deepcopy(self.contexts)
            p[2][attr]=value
            with self.subTest(field=attr),self.assertRaises(IssuerBoundaryError):
                self.check(externally_pinned_event_contexts=p)

    def test_reordered_signed_lifecycle_events_denied(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(signed_events=list(reversed(self.signed)))

    def test_wrong_final_pinned_head_denied(self):
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_final_digest="f"*64)

    def test_bool_epoch_rejected_without_cast(self):
        p=copy.deepcopy(self.contexts)
        p[1]["lease_epoch"]=True
        with self.assertRaises(IssuerBoundaryError):
            self.check(externally_pinned_event_contexts=p)

if __name__=="__main__":unittest.main()
