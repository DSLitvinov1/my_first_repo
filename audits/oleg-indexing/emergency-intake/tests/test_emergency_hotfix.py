"""Offline regression for V17 emergency-link-only hotfix, no production writes."""
import unittest
from build_hotfix import OLD_NOTICE,OLD_FALLBACK,NEW_FALLBACK,patch_home,patch_assistant,HOST_FORMS

def homepage():
    return ('<html><body data-form-mode="demo">'
       '<a href="tel:+79172052125">Позвонить</a>'
       '<a href="mailto:centr-uprav@inbox.ru">Написать</a>'
       +OLD_NOTICE
       +'<form id="lead-form" novalidate hidden aria-disabled="true"></form></body></html>')

def helper():
    return ("crm_form_fhi3n crm_form_ep5fd\n" + OLD_FALLBACK + "\nexisting non-form code")

class AvailabilityHotfixTests(unittest.TestCase):
    def test_two_distinct_correct_form_urls(self):
        for site,form in HOST_FORMS.items():
            revised=patch_home(homepage(),site)
            self.assertEqual(revised.count('href="https://b24-s2dosa.bitrix24site.ru/'+form+'/"'),1)
        self.assertEqual(len(set(HOST_FORMS.values())),2)

    def test_always_visible_internal_backup_on_home(self):
        for site in HOST_FORMS:
            new=patch_home(homepage(),site)
            self.assertIn('href="/emergency-lead.php"',new)
            self.assertIn('href="tel:+79172052125"',new)
            self.assertIn('href="mailto:centr-uprav@inbox.ru"',new)
            self.assertIn('сохранение на сервере, а не регистрацию в CRM',new)

    def test_original_demo_stays_disabled(self):
        for site in HOST_FORMS:
            new=patch_home(homepage(),site)
            self.assertIn('data-form-mode="demo"',new)
            self.assertIn('id="lead-form" novalidate hidden aria-disabled="true"',new)

    def test_no_page_changes_outside_one_notice(self):
        for site in HOST_FORMS:
            revised=patch_home(homepage(),site)
            prefix,suffix=homepage().split(OLD_NOTICE)
            self.assertTrue(revised.startswith(prefix) and revised.endswith(suffix))

    def test_baseline_change_blocks_release(self):
        with self.assertRaisesRegex(ValueError,"anchor mismatch"):
            patch_home(homepage().replace(OLD_NOTICE,'OUTDATED'),"potrebpravo.ru")

    def test_missing_backup_blocks_release(self):
        with self.assertRaisesRegex(ValueError,"source missing"):
            patch_home(homepage().replace('tel:+79172052125','none'),"potrebpravo.ru")

    def test_unverified_legacy_form_cannot_activate(self):
        with self.assertRaisesRegex(ValueError,"must stay disabled"):
            patch_home(homepage().replace('data-form-mode="demo"','data-form-mode="live"'),"semya-yurist.ru")

    def test_assistant_fallback_above_external_iframe(self):
        result=patch_assistant(helper())
        self.assertIn('formStep.insertBefore(fallback, frame)',result)
        self.assertNotIn('formStep.append(fallback);',result)
        self.assertIn("reserve.href = '/emergency-lead.php'",result)

    def test_both_public_forms_preserved_in_assistant(self):
        result=patch_assistant(helper())
        for name in HOST_FORMS.values():
            self.assertEqual(result.count(name),1)

    def test_outage_does_not_require_js_or_external_form_for_primary_backup(self):
        for site in HOST_FORMS:
            html=patch_home(homepage(),site)
            self.assertIn('<a href="/emergency-lead.php">',html)
            self.assertNotIn('Заявка успешно отправлена',html)

    def test_assistant_changes_are_exactly_one_snippet(self):
        result=patch_assistant(helper())
        self.assertEqual(result.replace(NEW_FALLBACK,OLD_FALLBACK),helper())

    def test_qwen_refused(self):
        with self.assertRaisesRegex(ValueError,'Unexpected assistant'):
            patch_assistant(helper()+'Qwen')

    def test_unknown_assistant_source_refused(self):
        with self.assertRaisesRegex(ValueError,'Unexpected assistant'):
            patch_assistant(helper().replace('fallback.append(open','fallback.broken(open'))

    def test_double_patch_refused(self):
        with self.assertRaises(ValueError):
            patch_assistant(patch_assistant(helper()))

if __name__=='__main__':unittest.main(verbosity=2)
