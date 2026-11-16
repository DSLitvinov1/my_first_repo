import json
import tempfile
import unittest
from pathlib import Path
from timeweb_readonly_route_inventory import inventory

class TimewebReadOnlyInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.home=Path(self.tmp.name).resolve()
        self.consumer=self.home/'potrebpravo.ru'/'public_html'
        self.family=self.home/'semya-yurist.ru'/'public_html'
        for host,root in [('potrebpravo.ru',self.consumer),('semya-yurist.ru',self.family)]:
            (root/'assets').mkdir(parents=True)
            (root/'index.html').write_text('<html>sample</html>',encoding='utf8')
            (root/'assets'/'site.js').write_text(
                'fetch("/api/leads", {method:"POST"}); if (response.ok) alert("ok");',
                encoding='utf8')
            (root/'sitemap.xml').write_text(
                '<urlset><url><loc>https://'+host+'/</loc></url></urlset>',encoding='utf8')
        (self.home/'api').mkdir()
        (self.home/'api'/'handler.php').write_text(
            'if ($path==="/api/leads" && $method==="POST") { /* Bitrix24 CRM_WEBHOOK_URL=SUPER_SECRET_TOKEN */ }',
            encoding='utf8')
        (self.home/'.env').write_text('CRM_WEBHOOK_URL=PRIVATE_KEY',encoding='utf8')
    def tearDown(self):
        self.tmp.cleanup()
    def test_route_candidacy_and_hash_without_disclosing_values_or_fake_confirmation(self):
        report=inventory(self.home,self.home,self.consumer,self.family)
        self.assertEqual(len(report['sites']),2)
        self.assertTrue(any(x['route_reference'] and x['bitrix_reference']
                            for x in report['candidate_backend_files']))
        for site in report['sites']:
            self.assertEqual(site['sitemap_urls'],1)
            self.assertTrue(site['sitemap_host_match'])
            self.assertTrue(site['lead_form_client']['posts_to_api_leads'])
            self.assertFalse(site['lead_form_client']['explicit_readback_proof'])
        self.assertFalse(report['authenticated_real_timeweb_confirmed'])
        self.assertFalse(report['real_post_handler_confirmed'])
        self.assertFalse(report['crm_receipt_confirmed'])
        self.assertFalse(report['server_backup_created'])
        self.assertFalse(report['scan_truncated'])
        receipt=json.dumps(report)
        for secret in ('SUPER_SECRET_TOKEN','PRIVATE_KEY','CRM_WEBHOOK_URL='):
            self.assertNotIn(secret,receipt)
    def test_no_mutations(self):
        originals={str(p):p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        inventory(self.home,self.home,self.consumer,self.family)
        self.assertEqual(originals,{str(p):p.read_bytes() for p in self.home.rglob('*') if p.is_file()})
    def test_reject_docroot_outside_home(self):
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaisesRegex(ValueError,'Untrusted'):
                inventory(self.home,self.home,Path(other),self.family)
    def test_refuse_same_root_for_both_sites(self):
        with self.assertRaisesRegex(ValueError,'Different domains'):
            inventory(self.home,self.home,self.consumer,self.consumer)

if __name__ == '__main__':
    unittest.main()
