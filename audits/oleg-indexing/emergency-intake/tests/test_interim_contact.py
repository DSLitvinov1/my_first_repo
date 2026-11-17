"""No real site content: check the minimal no-PII interim contact builder."""
import unittest
from build_interim_contact_release import homepage,assistant,FORM_OLD,FORM_NEW,JS_FALLBACK,HOST_FORMS
from build_hotfix import OLD_NOTICE,OLD_FALLBACK
def sample_home():
    return ('<html data-form-mode="demo"><p><a href="tel:+79172052125">Позвонить</a>'
        '<a href="mailto:centr-uprav@inbox.ru">Почта</a></p>'
        +OLD_NOTICE+'<form id="lead-form" novalidate hidden aria-disabled="true"></form></html>')
def sample_js():
    return ("crm_form_fhi3n crm_form_ep5fd\n"+FORM_OLD+"\n"+OLD_FALLBACK)
class InterimAvailability(unittest.TestCase):
    def test_both_websites_link_correct_public_form(self):
        for host,id_ in HOST_FORMS.items():
            result=homepage(sample_home(),host)
            self.assertIn('href="https://b24-s2dosa.bitrix24site.ru/'+id_+'/"',result)
            self.assertIn('href="tel:+79172052125"',result)
            self.assertIn('href="mailto:centr-uprav@inbox.ru"',result)
    def test_no_new_data_collector_or_fake_success(self):
        result=homepage(sample_home(),'potrebpravo.ru')
        self.assertNotIn('/emergency-lead.php',result)
        self.assertIn('data-form-mode="demo"',result)
        self.assertIn('id="lead-form" novalidate hidden aria-disabled="true"',result)
        self.assertNotIn('успешно отправлена',result.lower())
    def test_only_one_known_notice_changes(self):
        for host in HOST_FORMS:
            changed=homepage(sample_home(),host)
            prefix,suffix=sample_home().split(OLD_NOTICE)
            self.assertTrue(changed.startswith(prefix) and changed.endswith(suffix))
    def test_current_url_passes_only_present_utm(self):
        result=assistant(sample_js())
        for name in ('utm_source','utm_medium','utm_campaign','utm_term','utm_content'):
            self.assertIn(name,result)
        self.assertIn("const provided = new URLSearchParams(location.search)",result)
        self.assertIn('formLink.searchParams.set(name, v)',result)
        self.assertNotIn('utm_source=organic',result)
    def test_phone_email_independent_of_bitrix_iframe(self):
        result=assistant(sample_js())
        self.assertIn('formStep.insertBefore(fallback, frame)',result)
        self.assertIn("phone.href = 'tel:+79172052125'",result)
        self.assertIn("email.href = 'mailto:centr-uprav@inbox.ru'",result)
        self.assertNotIn("reserve.href = '/emergency-lead.php'",result)
    def test_patch_exact_and_idempotently_rejects_repeat(self):
        result=assistant(sample_js())
        self.assertEqual(result.replace(JS_FALLBACK,OLD_FALLBACK).replace(FORM_NEW,FORM_OLD),sample_js())
        with self.assertRaises(ValueError):assistant(result)
    def test_site_source_drift_blocks(self):
        with self.assertRaises(ValueError):homepage(sample_home().replace(OLD_NOTICE,'unknown'),'potrebpravo.ru')
    def test_unknown_site_blocks(self):
        with self.assertRaises(ValueError):homepage(sample_home(),'other.example')
    def test_qwen_is_not_reintroduced(self):
        with self.assertRaises(ValueError):assistant(sample_js()+'Qwen')
if __name__=='__main__':unittest.main(verbosity=2)
