"""No-customer-data, self-contained regression of the V18 four-file release guard."""
import hashlib,json,pathlib,shutil,subprocess,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
PRODUCTION_DEPLOY=ROOT/'deploy_interim_safely.py'
FILES={
 'potrebpravo.ru/index.html':b'consumer-original-html\n',
 'semya-yurist.ru/index.html':b'family-original-html\n',
 'potrebpravo.ru/assets/legal-assistant-v4.js':b'shared-assistant-original-js\n',
 'semya-yurist.ru/assets/legal-assistant-v4.js':b'shared-assistant-original-js\n',
}
ORIGINAL_SHA={
 'potrebpravo.ru/index.html':'7138aad960cb41c169b3417046f2c9d673110ae39e82be5033f48eb3eb5b0704',
 'semya-yurist.ru/index.html':'f7b0b6a897aefe7bf09b06bc550691709988a4cfee1641e7caec48f47a805eaa',
 'potrebpravo.ru/assets/legal-assistant-v4.js':'3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a',
 'semya-yurist.ru/assets/legal-assistant-v4.js':'3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a',
}
def sha(data):return hashlib.sha256(data).hexdigest()
class TestSafeRelease(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='oleg-v18-release-test.')
        self.root=pathlib.Path(self.tmp.name)
        (self.root/'.v18-test-marker').write_text('test-only')
        self.stage=self.root/'.stage'
        self.stage.mkdir(mode=0o700)
        code=PRODUCTION_DEPLOY.read_text()
        self.rows=[]
        for rel,data in FILES.items():
            old=sha(data)
            code=code.replace(ORIGINAL_SHA[rel],old)
            target=self.root/rel.split('/')[0]/'public_html'/rel.split('/',1)[1]
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(data)
            new=self.stage/'new'/rel
            new.parent.mkdir(parents=True,exist_ok=True)
            updated=b'v18-availability-'+rel.encode()+b'\n'
            new.write_bytes(updated)
            self.rows.append({'relative_file':rel,'previous_sha256':old,'new_sha256':sha(updated),'bytes':len(updated)})
        self.deploy=self.root/'sandbox_copy_of_release_guard.py'
        self.deploy.write_text(code)
        (self.stage/'manifest.json').write_text(json.dumps({'state':'INTERIM_AVAILABILITY_ONLY_NOT_DEPLOYED','files':self.rows}))
    def tearDown(self):self.tmp.cleanup()
    def runphase(self,action,success=True):
        p=subprocess.run([sys.executable,str(self.deploy),'--root',str(self.root),'--stage',str(self.stage),'--action',action],capture_output=True,text=True)
        self.assertEqual(p.returncode==0,success,action+':'+p.stderr[:180])
    def current(self,kind):
        for row in self.rows:
            rel=row['relative_file']
            path=self.root/rel.split('/')[0]/'public_html'/rel.split('/',1)[1]
            self.assertEqual(sha(path.read_bytes()),row[kind])
    def test_commit_and_rollback(self):
        self.runphase('preflight');self.runphase('apply');self.current('new_sha256')
        self.runphase('finalize');self.runphase('rollback');self.current('previous_sha256')
    def test_crash_recovery(self):
        self.runphase('apply')
        (self.stage/'journal.json').write_text(json.dumps({'state':'applying','done':['potrebpravo.ru/index.html']}))
        self.runphase('recover');self.current('previous_sha256')
    def test_source_drift_blocks(self):
        target=self.root/'potrebpravo.ru/public_html/index.html'
        target.write_bytes(b'updated-by-third-party')
        self.runphase('preflight',False)
        self.assertEqual(target.read_bytes(),b'updated-by-third-party')
    def test_stage_drift_blocks(self):
        new=self.stage/'new/semya-yurist.ru/index.html'
        new.write_bytes(b'corrupted-stage')
        self.runphase('preflight',False);self.current('previous_sha256')
    def test_second_apply_refused(self):
        self.runphase('apply');self.runphase('apply',False);self.current('new_sha256')
    def test_rollback_refuses_external_modifications(self):
        self.runphase('apply')
        t=self.root/'semya-yurist.ru/public_html/index.html'
        t.write_bytes(b'foreign-concurrent-write')
        self.runphase('rollback',False)
        self.assertEqual(t.read_bytes(),b'foreign-concurrent-write')
if __name__=='__main__':unittest.main(verbosity=2)
