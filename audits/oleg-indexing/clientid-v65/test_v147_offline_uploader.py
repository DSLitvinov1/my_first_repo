import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).parents[1] / 'code'
sys.path.insert(0, str(ROOT))
import v147_offline_uploader as mod

NOW = 1800000000
def record(*, site='potrebpravo.ru', test=False, eligible=True):
    return {
        'deal_id': 12345,
        'site': site,
        'form_code': 'crm_form_fhi3n' if site == 'potrebpravo.ru' else 'crm_form_ep5fd',
        'crm_source': 'Сайт — Защита прав потребителей' if site == 'potrebpravo.ru' else 'Сайт — Семейное право',
        'client_id': '1234567890123456789',
        'analytics_consent_confirmed': True,
        'lead_consent_confirmed': True,
        'crm_stage': 'В работе',
        'crm_stage_verified': True,
        'event_timestamp': NOW - 100,
        'is_test': test,
        'qualified_lead_confirmed': eligible,
        'responsible_oleg_verified': True
    }

class FakeHttp:
    def __init__(self, *, wrong_goal=False, status=200, err=False):
        self.wrong_goal, self.status, self.err = wrong_goal, status, err
        self.gets, self.posts, self.last_payload = 0, 0, b''
    def get(self, url, **kwargs):
        self.gets += 1
        counter = int(url.split('/counter/')[1].split('/')[0])
        goals = []
        for target, id_ in mod.EXPECTED[counter].items():
            goals.append({'id': id_, 'type': 'action', 'status':'active', 'conditions':
                          [{'type': 'contain' if self.wrong_goal else 'exact', 'url': target}]})
        return SimpleNamespace(status_code=200, json=lambda: {'goals': goals})
    def post(self, url, **kwargs):
        self.posts += 1
        self.last_payload = kwargs['files']['file'][1]
        if self.err:
            raise mod.requests.ConnectionError('connection reset before response')
        return SimpleNamespace(status_code=self.status, json=lambda: {'uploading': {'id': 7788}})

class V147Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.json = self.root/'rows.json'
        self.ledger = self.root/'private'/'dedup.sqlite3'
    def store(self, rows):
        self.json.write_text(json.dumps(rows, ensure_ascii=False),encoding='utf-8')
    def run_upload(self, counter=114249897, *, send=True, http=None):
        return mod.run(self.json, counter, self.ledger,
                       send=send, token='unused_fake_token', http=http, now=NOW)
    def test_dry_run_no_network_and_no_files(self):
        self.store([record()])
        result = self.run_upload(send=False, http=FakeHttp())
        self.assertEqual(result['mode'], 'DRY_RUN_NO_NETWORK')
        self.assertEqual(result['eligible'], 1)
        self.assertFalse(self.ledger.exists())
    def test_qa_deals_blocked_before_api(self):
        self.store([record(test=True)])
        http = FakeHttp()
        result = self.run_upload(http=http)
        self.assertEqual(result['mode'], 'NO_QUALIFIED_EVENTS')
        self.assertEqual((http.gets,http.posts), (0,0))
        self.assertFalse(self.ledger.exists())
    def test_unqualified_deals_blocked(self):
        self.store([record(eligible=False)])
        http = FakeHttp()
        self.assertEqual(self.run_upload(http=http)['mode'], 'NO_QUALIFIED_EVENTS')
        self.assertEqual(http.posts,0)
    def test_goal_must_match_exact(self):
        self.store([record()])
        http=FakeHttp(wrong_goal=True)
        with self.assertRaises(mod.Blocked):
            self.run_upload(http=http)
        self.assertEqual(http.gets,1)
        self.assertEqual(http.posts,0)
        self.assertFalse(self.ledger.exists())
    def test_exact_real_qualified_event_single_upload(self):
        self.store([record()])
        http=FakeHttp()
        result=self.run_upload(http=http)
        self.assertEqual(result['mode'], 'ACCEPTED_PENDING_PROCESSING')
        self.assertEqual(result['submitted'],1)
        self.assertEqual(result['upload_id'],7788)
        self.assertIn(b'oleg_crm_lead_confirmed',http.last_payload)
        self.assertEqual(http.posts,1)
        self.assertEqual(self.ledger.stat().st_mode&0o777,0o600)
        self.assertEqual(self.ledger.parent.stat().st_mode&0o777,0o700)
    def test_idempotency_does_not_post_twice(self):
        self.store([record()])
        first=FakeHttp()
        self.assertEqual(self.run_upload(http=first)['submitted'],1)
        second=FakeHttp()
        self.assertEqual(self.run_upload(http=second)['mode'], 'ALL_ALREADY_RESERVED')
        self.assertEqual(second.posts,0)
    def test_ambiguous_network_does_not_retry(self):
        self.store([record()])
        first=FakeHttp(err=True)
        self.assertEqual(self.run_upload(http=first)['mode'],'POST_OUTCOME_UNKNOWN_DO_NOT_RETRY')
        second=FakeHttp()
        self.assertEqual(self.run_upload(http=second)['mode'],'ALL_ALREADY_RESERVED')
        self.assertEqual(second.posts,0)
    def test_cross_site_input_rejected(self):
        self.store([record(site='semya-yurist.ru')])
        http=FakeHttp()
        with self.assertRaises(mod.Blocked):
            self.run_upload(114249897,http=http)
        self.assertEqual((http.gets,http.posts),(0,0))
    def test_family_goes_only_to_family_counter(self):
        self.store([record(site='semya-yurist.ru')])
        http=FakeHttp()
        res=self.run_upload(114251443,http=http)
        self.assertEqual(res['counter'],114251443)
        self.assertEqual(http.posts,1)
    def test_unexpected_pii_fields_rejected(self):
        wrong=record();wrong['phone']='555'
        self.store([wrong])
        self.assertEqual(self.run_upload(http=FakeHttp())['mode'],'NO_QUALIFIED_EVENTS')
    def test_absent_token_refuses(self):
        self.store([record()])
        with self.assertRaises(mod.Blocked):
            mod.run(self.json,114249897,self.ledger,send=True,token='',http=FakeHttp(),now=NOW)
if __name__ == '__main__':
    unittest.main()
