"""V22 realistic full-site fallback rename tests, real backup content, only /tmp."""
import importlib.util, pathlib, tempfile, unittest
from test_v21_timeweb_exchange import fixture, BACKUP
HERE=pathlib.Path(__file__).resolve().parent
SCRIPT=HERE/'v22_timeweb_rename_release.py'
def module():
    spec=importlib.util.spec_from_file_location('v22_isolated',SCRIPT)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
class TestRelease(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='oleg-v22-rename-test-')
        self.h=pathlib.Path(self.tmp.name)
        fixture(self.h)
        self.m=module()
        self.m.H=self.h
        self.m.R=self.h/'.oleg-seo-releases/v19-20261117-safe-seo'
        self.m.BACKUP=BACKUP
        self.m.smoke=lambda x: self.smoke(x)
    def tearDown(self):self.tmp.cleanup()
    def smoke(self,refs):
        n=0
        for site in self.m.SITES:
            for rel in ('index.html','assets/legal-assistant-v4.js','robots.txt','sitemap.xml'):
                self.assertEqual(self.m.sha(self.m.live(site)/rel),refs[site+'/'+rel])
                n+=1
        return n
    def test_prepare_and_live_then_rollback(self):
        b,a=self.m.preflight()
        self.assertEqual(len(b),168)
        self.assertEqual(sum(1 for k in b if a[k]!=b[k]),43)
        self.assertEqual(self.m.prepare()['state'],'READY')
        self.assertEqual(self.m.apply()['state'],'SEO_V15_LIVE_VERIFIED')
        self.assertEqual(self.m.verify()['state'],'PRODUCTION_SEO_VERIFIED')
        self.assertEqual(self.m.recover(b,a)['state'],'ROLLED_BACK_AND_WEB_VERIFIED')
        self.smoke(b)
    def test_missed_second_rename_recovers(self):
        b,a=self.m.preflight();self.m.prepare()
        site=self.m.SITES[0]
        self.m.mark('INSTALLING_NEW',site)
        self.m.move(self.m.live(site),self.m.old(site))
        self.assertFalse(self.m.live(site).exists())
        self.assertEqual(self.m.recover(b,a)['state'],'ROLLED_BACK_AND_WEB_VERIFIED')
        self.smoke(b)
    def test_failure_on_second_site_recovers_both(self):
        b,a=self.m.preflight();self.m.prepare()
        normal=self.m.move
        def fail_specific(src,dest):
            if src==self.m.new('semya-yurist.ru'):raise OSError('simulated outage')
            return normal(src,dest)
        self.m.move=fail_specific
        with self.assertRaises(OSError):self.m.apply()
        self.assertEqual(self.m.read_journal()['phase'],'ORIGINAL_HTTP_VERIFIED')
        self.smoke(b)
    def test_public_http_failure_rolls_back(self):
        b,a=self.m.preflight();self.m.prepare()
        calls=[0]
        def fail_new(ref):
            calls[0]+=1
            if calls[0]==1:raise OSError('simulated HTTP 502')
            return self.smoke(ref)
        self.m.smoke=fail_new
        with self.assertRaises(OSError):self.m.apply()
        self.assertEqual(self.m.read_journal()['phase'],'ORIGINAL_HTTP_VERIFIED')
        self.smoke(b)
    def test_live_source_drift_blocks_before_copy(self):
        file=self.m.live('potrebpravo.ru')/'robots.txt'
        file.write_bytes(file.read_bytes()+b'external')
        with self.assertRaises(self.m.Stop):self.m.prepare()
        self.assertFalse(self.m.journal().exists())
    def test_copy_candidate_drift_is_refused_before_live_rename(self):
        self.m.prepare()
        file=self.m.new('semya-yurist.ru')/'index.html'
        file.write_bytes(b'bad candidate')
        with self.assertRaises(self.m.Stop):self.m.apply()
        self.assertFalse(self.m.old('potrebpravo.ru').exists())
    def test_second_publish_is_refused(self):
        self.m.prepare();self.m.apply()
        with self.assertRaises(self.m.Stop):self.m.apply()
    def test_manual_rollback_after_live_is_repeatable_no_destroy(self):
        b,a=self.m.preflight();self.m.prepare();self.m.apply()
        self.m.recover(b,a)
        self.assertEqual(self.m.recover(b,a)['state'],'ROLLED_BACK_AND_WEB_VERIFIED')
    def test_post_release_foreign_write_blocks_unsafe_revert(self):
        b,a=self.m.preflight();self.m.prepare();self.m.apply()
        file=self.m.live('potrebpravo.ru')/'index.html'
        file.write_bytes(b'outsider wrote here')
        with self.assertRaises(self.m.Stop):self.m.recover(b,a)
        self.assertEqual(file.read_bytes(),b'outsider wrote here')
if __name__=='__main__':unittest.main(verbosity=2)
