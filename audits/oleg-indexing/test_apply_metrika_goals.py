import tempfile
import unittest
from pathlib import Path

from apply_metrika_goals import prepare, COUNTERS, ANALYTICS, EXTENSION_FILE
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
    def tearDown(self):
        self.tmp.cleanup()
    def test_dry_run_and_backup_and_idempotence(self):
        edits = prepare(self.root, self.extension)
        self.assertEqual(len(edits),2)
        for path,item in edits.items():
            self.assertEqual(item['old'],path.read_bytes())
            self.assertNotEqual(item['old'],item['new'])
            self.assertIn(b'__olegMetrikaIntentGoalsV1',item['new'])
        backup,n = apply_edits(edits,self.root)
        self.assertEqual(n,2)
        for host in COUNTERS:
            expected=source_for(host)
            asset=self.root/host/'public_html'/ANALYTICS
            self.assertNotEqual(asset.read_bytes(),expected)
            self.assertEqual((backup/host/ANALYTICS).read_bytes(),expected)
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
    def test_symlink_asset_blocks(self):
        target=self.root/'potrebpravo.ru'/'public_html'/ANALYTICS
        target.unlink()
        target.symlink_to(self.root/'semya-yurist.ru'/'public_html'/ANALYTICS)
        with self.assertRaisesRegex(ValueError,'unsafe'):
            prepare(self.root,self.extension)

if __name__ == '__main__':
    unittest.main()
