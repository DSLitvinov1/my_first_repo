import hashlib
import unittest
from assistant_sitewide_stage import ASSISTANT, inject_assistant, path_for
class AssistantStageTests(unittest.TestCase):
    def test_inject_once(self):
        original=b'<!doctype html><html><body><main>Hello</main></body></html>'
        new,changed=inject_assistant(original)
        self.assertTrue(changed)
        self.assertIn(ASSISTANT.encode(),new)
        self.assertEqual(new.replace(('\n'+ASSISTANT+'\n').encode(),b'',1),original)
        self.assertEqual(inject_assistant(new),(new,False))
    def test_case_insensitive_body(self):
        raw=b'<HTML><BODY>ok</BODY></HTML>'
        self.assertTrue(inject_assistant(raw)[1])
    def test_missing_body_fails(self):
        with self.assertRaisesRegex(ValueError,'body'):inject_assistant(b'<div>plain</div>')
    def test_ambiguous_body_fails(self):
        with self.assertRaises(ValueError):inject_assistant(b'<body></body></body>')
    def test_invalid_type_fails(self):
        with self.assertRaises(TypeError):inject_assistant('<body></body>')
    def test_original_metrika_consent_untouched(self):
        raw=b'<body><script defer src="/assets/oleg-analytics-v1.js"></script><div id="oleg-analytics-choice"></div></body>'
        new,_=inject_assistant(raw)
        self.assertIn(b'<script defer src="/assets/oleg-analytics-v1.js"></script>',new)
        self.assertIn(b'id="oleg-analytics-choice"',new)
    def test_expected_urls(self):
        self.assertEqual(str(path_for('https://potrebpravo.ru/','potrebpravo.ru')),'index.html')
        self.assertEqual(str(path_for('https://semya-yurist.ru/services/razvod.html','semya-yurist.ru')),'services/razvod.html')
    def test_path_traversal_and_cross_domain_forbidden(self):
        for url in ['https://other.ru/services/a.html','https://potrebpravo.ru/../foo.html','http://potrebpravo.ru/x.html','https://potrebpravo.ru/x.html?a=1','https://potrebpravo.ru/x.html#v','https://evil.com@potrebpravo.ru/x.html']:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):path_for(url,'potrebpravo.ru')
if __name__=='__main__': unittest.main()
