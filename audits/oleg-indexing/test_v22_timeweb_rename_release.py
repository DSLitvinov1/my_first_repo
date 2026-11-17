"""V22 portable, synthetic-only directory migration and rollback regression.

No credentials, original client files, or Timeweb access required. The separate
private 168-file Timeweb backup rehearsal was also executed before production.
"""
from __future__ import annotations
import hashlib, importlib.util, json, pathlib, shutil, tempfile, unittest

SCRIPT=pathlib.Path(__file__).with_name('v22_timeweb_rename_release.py')
SITES=('potrebpravo.ru','semya-yurist.ru')
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def load_module():
    spec=importlib.util.spec_from_file_location('oleg_v22_guard_synthetic',SCRIPT)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def make_fixture(home:pathlib.Path):
    release=home/'.oleg-seo-releases/v19-20261117-safe-seo'
    versions=release/'versions'
    versions.mkdir(parents=True)
    # Exactly 84 complete files per site, 168 in all; 43 reviewed changes.
    contents={};reviewed=[]
    for site in SITES:
        basic=['index.html','assets/legal-assistant-v4.js','robots.txt','sitemap.xml']
        basic.extend(f'pages/page-{i:03}.html' for i in range(80))
        assert len(basic)==84
        for rel in basic:
            body=f'OLD:{site}/{rel}\n'.encode()
            contents[site+'/'+rel]=body
            p=home/site/'public_html'/rel
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(body)
        before=home/site/'public_html'
        for version in ('v0','v1'):
            target=versions/version/site/'public_html'
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copytree(before,target)
    for site in SITES:
        count=22 if site=='potrebpravo.ru' else 17
        paths=['index.html','assets/legal-assistant-v4.js']
        paths.extend(f'pages/page-{i:03}.html' for i in range(count))
        # 24 consumer and 19 family -> 43 reviewed modifications.
        for rel in paths:
            old=contents[site+'/'+rel]
            new=b'V15:'+old
            p=versions/'v1'/site/'public_html'/rel
            p.write_bytes(new)
            reviewed.append({'host':site,'path':rel,'original_sha256':sha(old),
                 'proposed_sha256':sha(new),'changed':True})
    assert len(reviewed)==43
    manifest={'status':'OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT','manifest':reviewed}
    (release/'candidate-manifest.json').write_text(json.dumps(manifest))
    (release/'state.json').write_text(json.dumps({'phase':'ORIGINAL_PHYSICAL_RESTORED'}))
    (release/'current').symlink_to('versions/v0')
    backup=home/'.oleg-v22-synthetic-backup'
    backup.write_bytes(b'ONLY_SYNTHETIC_BACKUP_CONTENT_NO_USERS')
    return release,backup

class TestRelease(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='oleg-v22-rename-test-')
        self.h=pathlib.Path(self.tmp.name)
        release,backup=make_fixture(self.h)
        self.m=load_module()
        self.m.H=self.h
        self.m.R=release
        self.m.BACKUP=backup
        self.m.BACKUP_SHA=sha(backup.read_bytes())
        self.m.smoke=lambda refs:self.smoke(refs)
    def tearDown(self):self.tmp.cleanup()
    def smoke(self,refs):
        checks=0
        for site in self.m.SITES:
            for rel in ('index.html','assets/legal-assistant-v4.js','robots.txt','sitemap.xml'):
                self.assertEqual(self.m.sha(self.m.live(site)/rel),refs[site+'/'+rel])
                checks+=1
        return checks
    def test_prepare_publish_verify_rollback(self):
        before,after=self.m.preflight()
        self.assertEqual(len(before),168)
        self.assertEqual(sum(before[k]!=after[k] for k in before),43)
        self.assertEqual(self.m.prepare()['state'],'READY')
        self.assertEqual(self.m.apply()['state'],'SEO_V15_LIVE_VERIFIED')
        self.assertEqual(self.m.verify()['state'],'PRODUCTION_SEO_VERIFIED')
        self.assertEqual(self.m.recover(before,after)['state'],'ROLLED_BACK_AND_WEB_VERIFIED')
        self.smoke(before)
    def test_crash_between_two_renames_recovers_site(self):
        before,after=self.m.preflight();self.m.prepare()
        first=self.m.SITES[0]
        self.m.mark('INSTALLING_NEW',first)
        self.m.move(self.m.live(first),self.m.old(first))
        self.assertFalse(self.m.live(first).exists())
        self.assertEqual(self.m.recover(before,after)['state'],'ROLLED_BACK_AND_WEB_VERIFIED')
    def test_failure_during_second_site_restores_both(self):
        before,after=self.m.preflight();self.m.prepare()
        original=self.m.move
        def fail(src,dst):
            if src==self.m.new('semya-yurist.ru'):raise OSError('Synthetic outage')
            return original(src,dst)
        self.m.move=fail
        with self.assertRaises(OSError):self.m.apply()
        self.assertEqual(self.m.read_journal()['phase'],'ORIGINAL_HTTP_VERIFIED')
        self.smoke(before)
    def test_http_outage_rolls_back(self):
        before,after=self.m.preflight();self.m.prepare()
        calls=[0]
        def fake_http(ref):
            calls[0]+=1
            if calls[0]==1:raise RuntimeError('Synthetic HTTP 502')
            return self.smoke(ref)
        self.m.smoke=fake_http
        with self.assertRaises(RuntimeError):self.m.apply()
        self.assertEqual(self.m.read_journal()['phase'],'ORIGINAL_HTTP_VERIFIED')
        self.smoke(before)
    def test_modified_live_file_blocks_preparation(self):
        p=self.m.live('potrebpravo.ru')/'robots.txt'
        p.write_bytes(p.read_bytes()+b'foreign')
        with self.assertRaises(self.m.Stop):self.m.prepare()
        self.assertFalse(self.m.journal().exists())
    def test_tampered_staged_file_refuses_publication(self):
        self.m.prepare()
        (self.m.new('semya-yurist.ru')/'index.html').write_bytes(b'TAMPERED')
        with self.assertRaises(self.m.Stop):self.m.apply()
        self.assertFalse(self.m.old('potrebpravo.ru').exists())
    def test_second_publish_is_refused(self):
        self.m.prepare();self.m.apply()
        with self.assertRaises(self.m.Stop):self.m.apply()
    def test_rollback_is_repeatable(self):
        before,after=self.m.preflight()
        self.m.prepare();self.m.apply()
        self.m.recover(before,after)
        self.assertEqual(self.m.recover(before,after)['state'],'ROLLED_BACK_AND_WEB_VERIFIED')
    def test_foreign_write_blocks_destructive_recovery(self):
        before,after=self.m.preflight()
        self.m.prepare();self.m.apply()
        p=self.m.live('potrebpravo.ru')/'index.html'
        p.write_bytes(b'foreign-write-after-release')
        with self.assertRaises(self.m.Stop):self.m.recover(before,after)
        self.assertEqual(p.read_bytes(),b'foreign-write-after-release')

if __name__=='__main__':unittest.main(verbosity=2)
