"""Fail-closed tests for Bitrix24 links at the disabled primary lead areas."""
import unittest
from bitrix_primary_contact_v15 import patch, EXACT_OLD, FORM_BY_HOST, PHONE, EMAIL

class PrimaryBitrixV15Tests(unittest.TestCase):
    def fixture(self):
        return ('<body data-form-mode="demo">'
                '<a href="' + PHONE + '">Телефон</a>'
                '<a href="' + EMAIL + '">Почта</a>'
                + EXACT_OLD
                + '<form id="lead-form" novalidate hidden aria-disabled="true">'
                '<input name="name" /></form></body>')

    def test_distinct_form_mapping(self):
        forms = set()
        for host, form in FORM_BY_HOST.items():
            out = patch(self.fixture(), host)
            link = 'https://b24-s2dosa.bitrix24site.ru/' + form + '/'
            self.assertIn(link, out)
            self.assertEqual(out.count('target="_blank" rel="noopener noreferrer"'), 1)
            self.assertEqual(out.count('href="' + link + '"'), 1)
            forms.add(form)
        self.assertEqual(len(forms), 2)

    def test_unverified_original_form_remains_hidden(self):
        out = patch(self.fixture(), 'potrebpravo.ru')
        self.assertIn('data-form-mode="demo"', out)
        self.assertIn('id="lead-form" novalidate hidden aria-disabled="true"', out)

    def test_no_fake_acknowledgment(self):
        out = patch(self.fixture(), 'semya-yurist.ru')
        self.assertNotIn('Заявка успешно отправлена', out)
        self.assertIn('только после подтверждения', out)

    def test_phone_and_mail_independent(self):
        out = patch(self.fixture(), 'potrebpravo.ru')
        self.assertGreaterEqual(out.count('href="' + PHONE + '"'), 2)
        self.assertGreaterEqual(out.count('href="' + EMAIL + '"'), 2)

    def test_no_changes_outside_notice(self):
        raw = self.fixture()
        result = patch(raw, 'potrebpravo.ru')
        pos = raw.index(EXACT_OLD)
        self.assertEqual(result[:pos], raw[:pos])
        self.assertEqual(result[result.index('</div>',pos)+6:],raw[pos+len(EXACT_OLD):])

    def test_rejects_old_form_enabled(self):
        with self.assertRaisesRegex(ValueError,'Do not enable'):
            patch(self.fixture().replace('data-form-mode="demo"','data-form-mode="live"'), 'potrebpravo.ru')

    def test_rejects_missing_contact(self):
        with self.assertRaisesRegex(ValueError,'Contact channels'):
            patch(self.fixture().replace('mailto:centr-uprav@inbox.ru','not-configured'), 'potrebpravo.ru')

    def test_rejects_duplicate_unavailable_message(self):
        with self.assertRaisesRegex(ValueError,'Missing or repeated'):
            patch(self.fixture() + EXACT_OLD, 'potrebpravo.ru')

    def test_rejects_unknown_domain(self):
        with self.assertRaises(ValueError):
            patch(self.fixture(),'unknown-site.ru')

    def test_rejects_second_application(self):
        with self.assertRaisesRegex(ValueError,'Missing or repeated'):
            patch(patch(self.fixture(),'potrebpravo.ru'),'potrebpravo.ru')

if __name__ == '__main__':
    unittest.main(verbosity=2)
