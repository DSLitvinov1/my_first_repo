import hashlib, json, pathlib, tarfile, tempfile, unittest
from unittest.mock import patch
from v24_goals_timeweb_release import Release, Stop, SITES, STAGE, PRIOR, VERSION, STATUS, inventory, sha_file

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.H=pathlib.Path(self.temp.name)
        self.R=self.H/'.oleg-seo-ops/v24-goals'
        self.R.mkdir(parents=True)
        base={};new={};changed=[]
        for site,count,changes in [(SITES[0],87,26),(SITES[1],81,21)]:
            src=self.H/site/'public_html'
            cand=self.H/'test-artifact'/site/'public_html'
            src.mkdir(parents=True);cand.mkdir(parents=True)
            base[site]={};new[site]={}
            for i in range(count):
                rel=f'file{i:03d}.txt'
                if i==0:rel='index.html'
                if i==1:rel='assets/oleg-analytics-v1.js'
                old=('OLD_'+site+'_'+rel).encode()
                cur=old+(b'\nNEW_EVENT') if i<changes else old
                for folder,content in [(src,old),(cand,cur)]:
                    p=folder/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(content)
                base[site][rel]=hashlib.sha256(old).hexdigest()
                new[site][rel]=hashlib.sha256(cur).hexdigest()
                if i<changes:changed.append(site+'/'+rel)
        a=self.R/'v24-goals-candidate.tar.gz'
        with tarfile.open(a,'w:gz') as tf:
            for site in SITES:tf.add(self.H/'test-artifact'/site/'public_html',arcname=site+'/public_html')
        backupname='oleg-sites-auto-20261118T111259Z-1ac3a1be32.tar.gz'
        backup=self.H/'.oleg-safe-backups/oleg-managed-daily'/backupname
        backup.parent.mkdir(parents=True);backup.write_bytes(b'TEST_BACKUP_NO_PRIVATE_DATA')
        self.manifest={'status':STATUS,'version':VERSION,'sites':list(SITES),'baseline_sha256':base,'candidate_sha256':new,'changed':changed,'count':168,'archive_sha256':sha_file(a),'archive_filename':a.name,'backup_filename':backupname,'backup_sha256':sha_file(backup)}
        (self.R/'v24-goals-manifest.json').write_text(json.dumps(self.manifest))
    def tearDown(self):self.temp.cleanup()
    def make(self,fail=None):return Release(self.H,self.R,failure_site=fail)
    def fake_webcheck(self):return {x:{'http':'OFFLINE_TEST_PASS'} for x in SITES}
    def test_1_readonly_preflight(self):
        r=self.make();z=r.check();self.assertEqual(z['live_writes'],0)
        self.assertEqual(z['changes'],47)
        self.assertFalse((self.H/SITES[0]/STAGE).exists())
    def test_2_prepare_is_nonproduction(self):
        r=self.make();r.prepare()
        for s in SITES:
            self.assertEqual(inventory(r.live(s)),self.manifest['baseline_sha256'][s])
            self.assertEqual(inventory(r.ready(s)),self.manifest['candidate_sha256'][s])
        self.assertEqual(r.journal()['phase'],'READY')
    def test_3_successful_directory_exchange(self):
        r=self.make();r.prepare()
        with patch.object(Release,'webcheck',self.fake_webcheck):z=r.release()
        self.assertEqual(z['state'],'LIVE_VERIFIED')
        for s in SITES:
            self.assertEqual(inventory(r.live(s)),self.manifest['candidate_sha256'][s])
            self.assertEqual(inventory(r.prior(s)),self.manifest['baseline_sha256'][s])
    def test_4_approved_rollback(self):
        r=self.make();r.prepare()
        with patch.object(Release,'webcheck',self.fake_webcheck):r.release()
        self.assertEqual(r.rollback()['state'],'ROLLED_BACK')
        for s in SITES:self.assertEqual(inventory(r.live(s)),self.manifest['baseline_sha256'][s])
    def test_5_auto_rollback_after_first_site_failure(self):
        r=self.make(fail=SITES[0]);r.prepare()
        with self.assertRaisesRegex(Stop,'SIMULATED_FAILURE'):r.release()
        self.assertEqual(r.journal()['phase'],'ROLLED_BACK')
        for s in SITES:self.assertEqual(inventory(r.live(s)),self.manifest['baseline_sha256'][s])
    def test_6_auto_rollback_if_external_check_fails(self):
        r=self.make();r.prepare()
        with patch.object(Release,'webcheck',side_effect=Stop('HTTP_ERROR')):
            with self.assertRaisesRegex(Stop,'HTTP_ERROR'):r.release()
        self.assertEqual(r.journal()['phase'],'ROLLED_BACK')
        for s in SITES:self.assertEqual(inventory(r.live(s)),self.manifest['baseline_sha256'][s])
    def test_7_source_sha_drift_prevents_staging(self):
        r=self.make();(r.live(SITES[0])/'index.html').write_text('DRIFT')
        with self.assertRaisesRegex(Stop,'INVENTORY_MISMATCH'):r.prepare()
        self.assertFalse(r.ready(SITES[1]).exists())
    def test_8_archive_tamper_is_blocked(self):
        r=self.make();(self.R/'v24-goals-candidate.tar.gz').write_bytes(b'CORRUPTED')
        with self.assertRaisesRegex(Stop,'ARCHIVE_SHA_INVALID'):r.check()
    def test_9_backup_tamper_is_blocked(self):
        r=self.make();p=self.H/'.oleg-safe-backups/oleg-managed-daily'/self.manifest['backup_filename']
        p.write_bytes(b'TAMPERED')
        with self.assertRaisesRegex(Stop,'BACKUP_NOT_VALID'):r.check()
    def test_10_no_duplicate_release(self):
        r=self.make();r.prepare()
        with self.assertRaisesRegex(Stop,'RELEASE_ALREADY_INITIALIZED'):r.check()
        with patch.object(Release,'webcheck',self.fake_webcheck):r.release()
        with self.assertRaisesRegex(Stop,'NOT_STAGED_FOR_RELEASE'):r.release()
    def test_11_symlink_in_live_blocks(self):
        r=self.make();p=r.live(SITES[0])/'escape.link';p.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(Stop,'UNSAFE_FILE'):r.check()
    def test_12_crash_recovery_without_replacing_foreign_data(self):
        r=self.make();r.prepare();r.live(SITES[0]).rename(r.prior(SITES[0]));r.mark('SWAPPING')
        self.assertEqual(r.recover()['state'],'ROLLED_BACK')
        for s in SITES:self.assertEqual(inventory(r.live(s)),self.manifest['baseline_sha256'][s])

if __name__=='__main__':unittest.main()