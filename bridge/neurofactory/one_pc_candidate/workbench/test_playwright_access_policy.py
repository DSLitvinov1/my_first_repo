import unittest
from playwright_access_policy import (
    classify, exact_origin, expected_config_origins, can_mutate_without_owner_receipt,
    PlaywrightAccessDenied,
)

class PolicyTests(unittest.TestCase):
    def test_exact_service_read(self):
        for domain in ('potrebpravo.ru','semya-yurist.ru','metrika.yandex.ru',
                       'webmaster.yandex.ru','hosting.timeweb.ru',
                       'b24-xlzm11.bitrix24.ru','search.google.com'):
            result=classify('oleg-legal','https://'+domain+'/','inspect')
            self.assertEqual(result.origin,'https://'+domain)
            self.assertEqual(result.state,'ELIGIBLE_FOR_READ')
            self.assertFalse(result.requires_local_owner_approval)
    def test_mutation_needs_real_owner_receipt(self):
        for action in ('click','fill','submit','create_goal','save','edit_website','update_crm_record'):
            result=classify('oleg-legal','https://metrika.yandex.ru/settings',action)
            self.assertEqual(result.state,'PENDING_LOCAL_OWNER_APPROVAL')
            self.assertTrue(result.requires_local_owner_approval)
            self.assertFalse(can_mutate_without_owner_receipt(result,{'approved':True}))
    def test_unpaired_domains_refused(self):
        for url in ('https://evil.example/','https://metrika.yandex.ru.evil.example/',
                    'https://timeweb.ru/','https://127.0.0.1:8080/',
                    'https://bitrix24.ru/','https://secrets.example/'):
            with self.assertRaises(PlaywrightAccessDenied):classify('oleg-legal',url,'inspect')
    def test_unsafe_urls_fail(self):
        for url in ('http://metrika.yandex.ru','https://user:pw@metrika.yandex.ru/',
                    'file:///C:/passwords.txt','https://metrika.yandex.ru:9222/',
                    'https://metrika.yandex.ru/#secret','https://*.yandex.ru/',
                    'https://metrika.yandex.ru\\@evil.example/',
                    'https://metrika.yandex.ru:bad/','HTTPS://metrika.yandex.ru/'):
            with self.assertRaises(PlaywrightAccessDenied):exact_origin(url)
    def test_unsafe_actions_always_denied(self):
        for action in ('export_cookies','export_passwords','raw_cdp','system_shell',
                       'start_ads','pay','delete_account','disable_security',
                       'bulk_export_personal_data','another_unreviewed_action'):
            with self.assertRaises(PlaywrightAccessDenied):
                classify('oleg-legal','https://hosting.timeweb.ru/',action)
    def test_unpaired_project_denied(self):
        with self.assertRaises(PlaywrightAccessDenied):
            classify('another-client','https://metrika.yandex.ru/','inspect')
    def test_approved_hosts_are_exact(self):
        urls=expected_config_origins('oleg-legal')
        self.assertEqual(len(urls),8)
        self.assertEqual(len(urls),len(set(urls)))
        self.assertTrue(all(url.startswith('https://') and '*' not in url for url in urls))
    def test_read_not_mutate(self):
        a=classify('oleg-legal','https://hosting.timeweb.ru/sites','navigate')
        b=classify('oleg-legal','https://hosting.timeweb.ru/sites','publish')
        self.assertEqual(a.state,'ELIGIBLE_FOR_READ')
        self.assertEqual(b.state,'PENDING_LOCAL_OWNER_APPROVAL')

if __name__=='__main__':
    unittest.main()
