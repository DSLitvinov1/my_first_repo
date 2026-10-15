"""Targeted coordinator read-only witness boundary negative tests."""
import copy
import unittest
from mvp_host_witness_boundary import BoundaryError, inspect_host_witness

TASK='NF-DEV-05-Q001'
def core():
    return dict(schema='neurofactory.coordination.core_preview_inspection.v1',
        task_id=TASK,source_sha='a'*40,source_sha256='b'*64,
        input_sha256='c'*64,provider_relative_path='src/a.py',
        format_compatible=True,task_source_authenticated=False,
        approval_origin_authenticated=False,lease_proven=False,source_verified=False,
        external_execution_allowed=False,automatic_retry_allowed=False,
        publication_allowed=False,handoff='PAUSED_BY_USER')
def host(status='SIGNED_WITNESS_MATCHES_TEST_DB'):
    return dict(schema='neurofactory.trusted_host.offline_witness_comparison.v1',
        task_id=TASK,status=status,witness_receipt_sha256='d'*64,
        checkpoint_matches_signed_witness=status=='SIGNED_WITNESS_MATCHES_TEST_DB',
        externally_pinned_key_provenance_attested=False,
        externally_pinned_witness_sequence_durably_protected=False,
        independent_host_operator_approval=False,live_execution_allowed=False,
        publication_allowed=False,automatic_retry_allowed=False,
        handoff='PAUSED_BY_USER')
class Targeted(unittest.TestCase):
    def check(self,c=None,h=None,task=TASK):
        return inspect_host_witness(core() if c is None else c,
            host() if h is None else h,expected_task_id=task)
    def test_positive_diagnostic_stays_blocked(self):
        v=self.check()
        self.assertEqual(v['integration_gate'],'BLOCKED_NONLIVE_DIAGNOSTIC_ONLY')
        self.assertNotEqual(v['proposed_source_file_sha256'],v['proposed_input_task_sha256'])
        for key in ('provenance_authenticated','owner_authorization_verified',
                    'central_cas_and_receiver_fencing_verified','live_execution_allowed',
                    'automatic_retry_allowed','publication_allowed'):
            self.assertIs(v[key],False)
    def test_rollback_diagnostic_stays_blocked(self):
        self.assertEqual(self.check(h=host('UNKNOWN_OR_ROLLBACK'))['integration_gate'],
            'BLOCKED_NONLIVE_DIAGNOSTIC_ONLY')
    def test_wrong_task_denied(self):
        h=host();h['task_id']='NF-DEV-05-Q002'
        with self.assertRaises(BoundaryError):self.check(h=h)
    def test_bad_task_type_denied(self):
        for x in (True,1,None,'Q001'):
            with self.subTest(x=x),self.assertRaises(BoundaryError):self.check(task=x)
    def test_injected_approval_denied(self):
        h=host();h['owner_approval']=True
        with self.assertRaises(BoundaryError):self.check(h=h)
    def test_false_proof_flags_denied(self):
        for key in ('externally_pinned_key_provenance_attested',
                    'externally_pinned_witness_sequence_durably_protected',
                    'independent_host_operator_approval','live_execution_allowed',
                    'publication_allowed','automatic_retry_allowed'):
            h=host();h[key]=True
            with self.subTest(key=key),self.assertRaises(BoundaryError):self.check(h=h)
    def test_checkpoint_contradiction_denied(self):
        for s in ('SIGNED_WITNESS_MATCHES_TEST_DB','UNKNOWN_OR_ROLLBACK'):
            h=host(s);h['checkpoint_matches_signed_witness']=not h['checkpoint_matches_signed_witness']
            with self.subTest(status=s),self.assertRaises(BoundaryError):self.check(h=h)
    def test_receipt_format_denied(self):
        for x in (True,0,'wrong'):
            h=host();h['witness_receipt_sha256']=x
            with self.subTest(x=x),self.assertRaises(BoundaryError):self.check(h=h)
    def test_core_forged_authority_denied(self):
        for key in ('task_source_authenticated','approval_origin_authenticated','lease_proven',
                    'source_verified','external_execution_allowed','automatic_retry_allowed',
                    'publication_allowed'):
            c=core();c[key]=True
            with self.subTest(key=key),self.assertRaises(BoundaryError):self.check(c=c)
    def test_traversal_denied(self):
        for x in ('src/../other.py','docs/.hidden','src//a.py','/outside',True):
            c=core();c['provider_relative_path']=x
            with self.subTest(x=x),self.assertRaises(BoundaryError):self.check(c=c)
    def test_invalid_dict_denied(self):
        for c,h in (({},host()),(core(),{}),([],host()),(core(),[])):
            with self.assertRaises(BoundaryError):self.check(c=c,h=h)
    def test_invalid_status_denied(self):
        h=host();h['status']='APPROVED'
        with self.assertRaises(BoundaryError):self.check(h=h)
    def test_handoff_both_paused(self):
        for side in ('core','host'):
            c=core();h=host();(c if side=='core' else h)['handoff']='ACTIVE'
            with self.subTest(side=side),self.assertRaises(BoundaryError):self.check(c=c,h=h)
    def test_no_mutations(self):
        c=core();h=host();cp=copy.deepcopy(c);hp=copy.deepcopy(h)
        self.check(c=c,h=h)
        self.assertEqual(c,cp);self.assertEqual(h,hp)
    def test_bool_checkpoint_not_truthy(self):
        h=host();h['checkpoint_matches_signed_witness']=1
        with self.assertRaises(BoundaryError):self.check(h=h)
if __name__=='__main__':unittest.main()
