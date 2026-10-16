"""Independent-in-spirit author tests for non-authoritative release checklist."""
import copy
import json
import pathlib
import unittest
from release_readiness import ReadinessError,inspect_release_readiness

PATH=pathlib.Path(__file__).with_name('release_readiness_20261016.json')

def candidate():
    return json.loads(PATH.read_text(encoding='utf-8'))

class ReleaseReadinessTests(unittest.TestCase):
    def check(self,d=None):
        return inspect_release_readiness(candidate() if d is None else d)
    def test_all_ten_real_blockers_reported(self):
        r=self.check()
        self.assertEqual(r['required_gates'],10)
        self.assertEqual(len(r['pending_gate_ids']),10)
        self.assertEqual(r['independently_authenticated_gate_count'],0)
        self.assertEqual(r['status'],'BLOCKED_EXTERNAL_TRUST_NOT_DEPLOYED')
        self.assertEqual(r['handoff'],'PAUSED_BY_USER')
    def test_never_promote_any_synthetic_metadata(self):
        r=self.check()
        for k in ('source_origin_authenticated','external_signer_authenticated',
                  'independent_release_review_authenticated','live_execution_allowed',
                  'automatic_retry_allowed','publication_allowed','merge_allowed',
                  'paid_api_allowed'):
            self.assertIs(r[k],False)
        self.assertTrue(all(x['external_release_authority_authenticated'] is False
                            for x in r['gates']))
    def test_forged_positive_gate_denied(self):
        for value in ('APPROVED','VERIFIED_EXTERNALLY','READY',True,1):
            d=candidate();d['gates'][0]['reported_state']=value
            with self.subTest(value=value),self.assertRaises(ReadinessError):self.check(d)
    def test_forged_extra_approval_denied(self):
        d=candidate();d['gates'][1]['signed_approval']=True
        with self.assertRaises(ReadinessError):self.check(d)
    def test_missing_gate_denied(self):
        d=candidate();d['gates'].pop()
        with self.assertRaises(ReadinessError):self.check(d)
    def test_duplicate_gate_denied(self):
        d=candidate();d['gates'][2]['id']=d['gates'][1]['id']
        with self.assertRaises(ReadinessError):self.check(d)
    def test_wrong_project_denied(self):
        d=candidate();d['project']='another-project'
        with self.assertRaises(ReadinessError):self.check(d)
    def test_untrusted_sha_denied(self):
        for val in (True,'main','g'*40,'a'*64):
            d=candidate();d['gates'][0]['source_sha']=val
            with self.subTest(value=str(val)[:10]),self.assertRaises(ReadinessError):self.check(d)
    def test_type_smuggling_denied(self):
        for x in (None,[],1,True,{'schema':'fake'}):
            with self.subTest(value=str(x)[:20]),self.assertRaises(ReadinessError):self.check(x)
    def test_control_chars_or_giant_note_denied(self):
        for val in ('bad\nsecret','x'*301,''):
            d=candidate();d['gates'][0]['evidence_note']=val
            with self.subTest(value=val[:12]),self.assertRaises(ReadinessError):self.check(d)
    def test_no_mutation(self):
        d=candidate();b=copy.deepcopy(d)
        self.check(d)
        self.assertEqual(b,d)
    def test_reordered_report_never_releases(self):
        d=candidate();d['gates'].reverse()
        r=self.check(d)
        self.assertFalse(r['live_execution_allowed'])
        self.assertEqual(len(r['pending_gate_ids']),10)
    def test_all_advisory_statuses_remain_blocked(self):
        states=('NOT_STARTED','OFFLINE_ONLY','INCOMPLETE','REVIEW_PENDING','DEPLOYMENT_MISSING','UNKNOWN')
        for state in states:
            d=candidate()
            for x in d['gates']:x['reported_state']=state
            with self.subTest(state=state):
                r=self.check(d)
                self.assertFalse(r['publication_allowed'])
                self.assertEqual(r['status'],'BLOCKED_EXTERNAL_TRUST_NOT_DEPLOYED')
    def test_unrecognized_lane_denied(self):
        d=candidate();d['gates'][0]['lane']='ATTACKER'
        with self.assertRaises(ReadinessError):self.check(d)

if __name__=='__main__':
    unittest.main()
