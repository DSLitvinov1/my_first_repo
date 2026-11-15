import tempfile
import unittest
from pathlib import Path

from apply_metrika_goals import prepare, COUNTERS, ANALYTICS, EXTENSION_FILE, BASELINE_VERSIONS, PAGE_COUNTS, digest
from metadata_guard import apply_edits

def source_for(host):
    counter=COUNTERS[host]
    return ("(function(){ const counter = " + counter + ";\n"
            "const key='oleg.analytics.choice.v1';\n"
            "window.ym(counter, 'init', {webvisor: false});\n"
            "function safety() { return !!key; }\n"
            + ("// Test-only placeholder for retained live analytics behavior, including consent lifecycle.\n" * 5)
            + "})();\n").encode('utf-8')

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.extension = EXTENSION_FILE.read_text(encoding='utf-8')
        for host in COUNTERS:
            dirname = self.root / host / 'public_html' / 'assets'
            dirname.mkdir(parents=True)
            (dirname / 'oleg-analytics-v1.js').write_bytes(source_for(host))
            docroot = dirname.parent
            for i in range(PAGE_COUNTS[host]):
                page = docroot / ('index.html' if i == 0 else f'pages/test-{i}.html')
                page.parent.mkdir(parents=True, exist_ok=True)
                prefix = 'assets/' if i == 0 else '../assets/'
                page.write_text(f'<html><head><script src="{prefix}oleg-analytics-v1.js?v={BASELINE_VERSIONS[host]}"></script></head><body>Test fixture</body></html>', encoding='utf-8')
    def tearDown(self):
        self.tmp.cleanup()
    def test_dry_run_and_backup_and_idempotence(self):
        edits = prepare(self.root, self.extension)
        self.assertEqual(len(edits),2 + sum(PAGE_COUNTS.values()))
        for path,item in edits.items():
            self.assertEqual(item['old'],path.read_bytes())
            self.assertNotEqual(item['old'],item['new'])
            if path.name == 'oleg-analytics-v1.js':
                self.assertIn(b'__olegMetrikaIntentGoalsV1',item['new'])
            else:
                self.assertIn(b'oleg-analytics-v1.js?v=',item['new'])
        backup,n = apply_edits(edits,self.root)
        self.assertEqual(n,2 + sum(PAGE_COUNTS.values()))
        for host in COUNTERS:
            expected=source_for(host)
            asset=self.root/host/'public_html'/ANALYTICS
            self.assertNotEqual(asset.read_bytes(),expected)
            self.assertEqual((backup/host/ANALYTICS).read_bytes(),expected)
            new_version = digest(asset.read_bytes())[:8]
            updated = (self.root/host/'public_html'/'index.html').read_text(encoding='utf-8')
            self.assertIn('v=' + new_version, updated)
            self.assertEqual((backup/host/'index.html').read_text(encoding='utf-8').count('v=' + BASELINE_VERSIONS[host]), 1)
        repeat=prepare(self.root,self.extension)
        self.assertTrue(all(x['old']==x['new'] for x in repeat.values()))
    def test_source_drift_blocks_entire_operation(self):
        target=self.root/'semya-yurist.ru'/'public_html'/ANALYTICS
        target.write_text('short or unknown script',encoding='utf-8')
        with self.assertRaises(ValueError):
            prepare(self.root,self.extension)
        self.assertEqual((self.root/'potrebpravo.ru'/'public_html'/ANALYTICS).read_bytes(),source_for('potrebpravo.ru'))
    def test_cross_counter_blocks(self):
        target=self.root/'potrebpravo.ru'/'public_html'/ANALYTICS
        target.write_bytes(source_for('potrebpravo.ru')+b'\n114251443\n')
        with self.assertRaisesRegex(ValueError,'Cross-counter'):
            prepare(self.root,self.extension)
    def test_unknown_existing_extension_blocks(self):
        target=self.root/'potrebpravo.ru'/'public_html'/ANALYTICS
        target.write_bytes(source_for('potrebpravo.ru')+b'\n__olegMetrikaIntentGoalsV1 /* drift */\n')
        with self.assertRaisesRegex(ValueError,'differs'):
            prepare(self.root,self.extension)
    def test_html_version_drift_blocks_deployment(self):
        target=self.root/'potrebpravo.ru'/'public_html'/'index.html'
        target.write_text(target.read_text(encoding='utf-8').replace(BASELINE_VERSIONS['potrebpravo.ru'], 'not-the-expected-version'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'version drift'):
            prepare(self.root,self.extension)
    def test_missing_analytics_in_any_public_page_blocks_deployment(self):
        target=self.root/'semya-yurist.ru'/'public_html'/'index.html'
        target.write_text('<html>Missing analytics script</html>',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'Unexpected number'):
            prepare(self.root,self.extension)
    def test_symlink_asset_blocks(self):
        target=self.root/'potrebpravo.ru'/'public_html'/ANALYTICS
        target.unlink()
        target.symlink_to(self.root/'semya-yurist.ru'/'public_html'/ANALYTICS)
        with self.assertRaisesRegex(ValueError,'unsafe'):
            prepare(self.root,self.extension)

if __name__ == '__main__':
    unittest.main()
