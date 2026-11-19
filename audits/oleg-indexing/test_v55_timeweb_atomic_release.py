#!/usr/bin/env python3
"""Offline failure-injection regression for guarded V55 two-domain deployment."""
from pathlib import Path
import hashlib, json, shutil, tempfile, unittest
from unittest.mock import patch
from v55_timeweb_atomic_release import Release, Stop, inv, SITES, READY, PRIOR
BASE=Path(__file__).resolve().parents[2]
SNAPSHOT=BASE/'.private-v25-offline'/'snapshot'
ARCHIVE=BASE/'.private-v54-offline'/'v54-release-a-full-168-v25-to-v53-20261119.tar.gz'
MANIFEST=BASE/'.private-v55-offline'/'v55-release-manifest.json'
class GuardedReleaseTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(prefix='oleg-v55-release-test-')
  self.home=Path(self.t.name)
  self.ops=self.home/'.oleg-seo-ops'/'v55-release-a'
  self.ops.mkdir(parents=True)
  shutil.copy2(ARCHIVE,self.ops/ARCHIVE.name)
  shutil.copy2(MANIFEST,self.ops/'v55-release-manifest.json')
  self.meta=json.loads(MANIFEST.read_text())
  for site in SITES:shutil.copytree(SNAPSHOT/site/'public_html',self.home/site/'public_html')
 def tearDown(self):self.t.cleanup()
 def manager(self,fail_after=None):return Release(self.home,self.ops,test_mode=True,fail_after=fail_after)
 def verify_base(self):
  for site in SITES:self.assertEqual(inv(self.home/site/'public_html'),self.meta['expected'][site]['baseline'])
 def verify_new(self):
  for site in SITES:self.assertEqual(inv(self.home/site/'public_html'),self.meta['expected'][site]['target'])
 def fake_http(self):return {s:'MOCKED_HTTPS_NOT_A_LIVE_TEST' for s in SITES}
 def test_01_preflight_readonly(self):
  p=self.manager();self.assertEqual(p.check()['state'],'PREFLIGHT_PASS');self.verify_base()
  self.assertFalse((self.home/SITES[0]/READY).exists())
 def test_02_prepare_creates_verified_backup_no_live_mutation(self):
  p=self.manager();z=p.prepare();self.assertEqual(z['state'],'READY')
  self.assertTrue(Path(p.journal()['backup']['path']).is_file())
  p.backup_checked();self.verify_base()
  for site in SITES:self.assertEqual(inv(p.ready(site)),self.meta['expected'][site]['target'])
 def test_03_atomic_deploy_with_mocked_http(self):
  p=self.manager();p.prepare()
  with patch.object(Release,'httpverify',self.fake_http):
   self.assertEqual(p.deploy()['state'],'LIVE_VERIFIED')
  self.verify_new()
  for site in SITES:self.assertEqual(inv(p.prior(site)),self.meta['expected'][site]['baseline'])
 def test_04_manual_rollback(self):
  p=self.manager();p.prepare()
  with patch.object(Release,'httpverify',self.fake_http):p.deploy()
  self.assertEqual(p.rollback()['state'],'ROLLED_BACK');self.verify_base()
 def test_05_auto_rollback_after_first_site_failure(self):
  p=self.manager(fail_after=SITES[0]);p.prepare()
  with self.assertRaisesRegex(Stop,'TEST_FAILURE_AFTER'):p.deploy()
  self.assertEqual(p.journal()['phase'],'ROLLED_BACK');self.verify_base()
 def test_06_auto_rollback_after_network_http_failure(self):
  p=self.manager();p.prepare()
  with patch.object(Release,'httpverify',side_effect=Stop('HTTPS_BROKEN')):
   with self.assertRaisesRegex(Stop,'HTTPS_BROKEN'):p.deploy()
  self.verify_base()
 def test_07_live_drift_rejected_before_stage(self):
  p=self.manager();(p.live(SITES[0])/'index.html').write_text('A THIRD PARTY MODIFIED THIS FILE')
  with self.assertRaisesRegex(Stop,'LIVE_SHA_MISMATCH'):p.check()
  self.assertFalse(p.ready(SITES[0]).exists())
 def test_08_bundle_tamper_rejected(self):
  p=self.manager();(self.ops/ARCHIVE.name).write_bytes(b'not real archive')
  with self.assertRaisesRegex(Stop,'ARCHIVE_SHA_MISMATCH'):p.check()
 def test_09_backup_tamper_rejected_before_deploy(self):
  p=self.manager();p.prepare()
  Path(p.journal()['backup']['path']).write_bytes(b'backup changed')
  with self.assertRaisesRegex(Stop,'BACKUP_SHA_INVALID'):p.deploy()
  self.verify_base()
 def test_10_no_redeployment_without_state_reset(self):
  p=self.manager();p.prepare()
  with self.assertRaisesRegex(Stop,'RELEASE_ALREADY_STARTED'):p.check()
  with patch.object(Release,'httpverify',self.fake_http):p.deploy()
  with self.assertRaisesRegex(Stop,'DEPLOY_NOT_READY'):p.deploy()
 def test_11_recovery_from_crash_between_moves(self):
  p=self.manager();p.prepare();p.mark('SWAPPING')
  p.live(SITES[0]).rename(p.prior(SITES[0]))
  self.assertEqual(p.recover()['state'],'ROLLED_BACK');self.verify_base()
 def test_12_symlink_refused_during_preflight(self):
  p=self.manager();(p.live(SITES[0])/'foreign.link').symlink_to('/etc/passwd')
  with self.assertRaisesRegex(Stop,'BAD_FILE'):p.check()
 def test_13_unauthorized_home_rejected(self):
  with self.assertRaisesRegex(Stop,'WRONG_PRODUCTION_PATH'):
   Release(self.home,self.ops,test_mode=False)
if __name__=='__main__':unittest.main(verbosity=2)