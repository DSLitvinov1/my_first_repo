#!/usr/bin/env python3
"""Never invokes a real Timeweb path or live URL; exact 168-file backup fixture."""
import importlib.util, json, pathlib, shutil, sys, tarfile, tempfile, unittest

P=pathlib.Path(__file__).with_name('v19_timeweb_atomic_release.py')
STAGE=pathlib.Path('/home/cloudagent/projects/oleg-seo-review-20261116/.offline-stage-v15-primary-20261117')
BACKUP=pathlib.Path('/home/cloudagent/projects/oleg-seo-v19-seo-readiness-20261117/.private-seo-v19/oleg-v18-availability-pre-20261117T144230Z.tar.gz')

def load():
    spec=importlib.util.spec_from_file_location('v19_guard',P)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

class MigrationSmoke(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='oleg-v19-migration-test-')
        self.h=pathlib.Path(self.tmp.name)
        with tarfile.open(BACKUP) as archive:
            for item in archive.getmembers():
                if item.isdir():continue
                if not item.isfile():raise ValueError('unexpected archive type')
                rel=pathlib.PurePosixPath(item.name)
                if rel.is_absolute() or '..' in rel.parts or rel.parts[0] not in ('potrebpravo.ru','semya-yurist.ru'):
                    raise ValueError('unsafe archive')
                dst=self.h.joinpath(*rel.parts)
                dst.parent.mkdir(parents=True,exist_ok=True)
                with archive.extractfile(item) as src,dst.open('xb') as dest:
                    shutil.copyfileobj(src,dest)
        self.m=load()
        self.m.H=self.h
        self.m.RELEASES=self.h/'.oleg-seo-releases'
        self.m.R=self.m.RELEASES/self.m.IDENT
        self.m.RELEASES.mkdir(mode=0o700)
        self.m.R.mkdir(mode=0o700)
        (self.m.R/'candidate').mkdir()
        shutil.copyfile(STAGE/'unified-manifest.json',self.m.R/'candidate-manifest.json')
        report=json.loads((STAGE/'unified-manifest.json').read_text())
        for item in report['manifest']:
            rel=pathlib.Path(item['host'])/item['path']
            dest=self.m.R/'candidate'/item['host']/'public_html'/item['path']
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(STAGE/'unified-release'/item['host']/'public_html'/item['path'],dest)
        self.m.mark('STAGING')
        def offline_smoke(v):
            for host in self.m.HOSTS:
                actual=self.m.docroot(host)
                wanted=self.m.version(v,host)
                assert actual.is_dir()
                for rel in ('index.html','assets/legal-assistant-v4.js','robots.txt','sitemap.xml'):
                    assert self.m.digest(actual/rel)==self.m.digest(wanted/rel)
            return 8
        self.m.web_checks=offline_smoke
    def tearDown(self):self.tmp.cleanup()
    def test_full_staged_two_domains_switch_and_physical_rollback(self):
        a=self.m.assemble()
        self.assertEqual(a['reviewed_sha'],43)
        self.assertEqual(a['full_snapshot_files'],168)
        b=self.m.migrate()
        self.assertEqual(b['status'],'MIGRATED_OLD_VERIFIED')
        self.assertTrue(all(self.m.docroot(h).is_symlink() for h in self.m.HOSTS))
        c=self.m.switch()
        self.assertEqual(c['status'],'SEO_LIVE_VERIFIED')
        self.assertEqual(self.m.verify()['status'],'PRODUCTION_SEO_VERIFIED')
        self.assertEqual(self.m.pointer_version(),'v1')
        self.assertEqual(self.m.rollback()['status'],'ORIGINAL_PHYSICAL_RESTORED')
        self.assertTrue(all(self.m.docroot(h).is_dir() and not self.m.docroot(h).is_symlink() for h in self.m.HOSTS))
        self.assertFalse(any(self.m.legacy(h).exists() for h in self.m.HOSTS))
    def test_migration_smoke_failure_restores_physical(self):
        self.m.assemble()
        self.m.web_checks=lambda v: (_ for _ in ()).throw(RuntimeError('simulated network failure'))
        with self.assertRaises(RuntimeError):self.m.migrate()
        self.assertEqual(self.m.state()['phase'],'ORIGINAL_PHYSICAL_RESTORED')
        self.assertTrue(all(self.m.docroot(h).is_dir() and not self.m.docroot(h).is_symlink() for h in self.m.HOSTS))
    def test_switch_smoke_failure_restores_old_content(self):
        self.m.assemble(); self.m.migrate()
        prior=self.m.web_checks
        def failing(v):
            if v=='v1':raise RuntimeError('simulated new-site 502')
            return prior(v)
        self.m.web_checks=failing
        with self.assertRaises(RuntimeError):self.m.switch()
        self.assertEqual(self.m.pointer_version(),'v0')
        self.assertEqual(self.m.state()['phase'],'SWITCH_ROLLED_BACK_TO_V0')
        self.m.rollback()
    def test_unreviewed_live_file_drift_blocks_migration(self):
        self.m.assemble()
        with (self.m.docroot('potrebpravo.ru')/'robots.txt').open('ab') as f:f.write(b'\nexternal-change')
        with self.assertRaises(self.m.Guard):self.m.migrate()
        self.assertEqual(self.m.state()['phase'],'STAGED')
    def test_crash_after_one_directory_rename_can_recover(self):
        self.m.assemble()
        self.m.mark('MIGRATING')
        first='potrebpravo.ru'
        self.m.docroot(first).rename(self.m.legacy(first))
        self.m.rollback()
        self.assertEqual(self.m.state()['phase'],'ORIGINAL_PHYSICAL_RESTORED')
        self.assertTrue(all(self.m.docroot(h).is_dir() and not self.m.docroot(h).is_symlink() for h in self.m.HOSTS))
    def test_unapproved_repeated_stage_fails(self):
        self.m.assemble()
        with self.assertRaises(self.m.Guard):self.m.assemble()
    def test_unknown_change_in_candidate_is_blocked(self):
        file=self.m.R/'candidate'/'potrebpravo.ru'/'public_html'/'index.html'
        file.write_bytes(b'corruption')
        with self.assertRaises(self.m.Guard):self.m.assemble()
if __name__=='__main__':unittest.main(verbosity=2)
