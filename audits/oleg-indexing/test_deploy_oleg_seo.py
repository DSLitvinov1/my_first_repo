import tempfile
import unittest
from pathlib import Path
from copy import deepcopy

from deploy_oleg_seo import build_release
from metadata_guard import apply_edits

HOSTS=('potrebpravo.ru','semya-yurist.ru')


class BatchReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.parent=Path(self.tmp.name)
        self.meta={'status':'REVIEW_ONLY_NOT_DEPLOYED',
                   'sites':[{'host':h,'changes':[]} for h in HOSTS]}
        self.links={'status':'REVIEW_ONLY_NOT_DEPLOYED','changes':[]}
        self.initial={}
        for i in range(20):
            host=HOSTS[0] if i<12 else HOSTS[1]
            is_case=(i<9 or 12<=i<16)
            rel=f'practice/cases/case-{i}.html' if is_case else f'services/service-{i}.html'
            oldtitle=f'Судебная страница {i}'
            olddesc=f'Описание страницы {i}'
            newtitle=f'Новый заголовок {i}'
            newdesc=f'Новое описание {i}'
            source=(f'<!doctype html><html><head><title>{oldtitle}</title>'
                   f'<meta name="description" content="{olddesc}"></head>'
                   f'<body><main><article class="article"><h2>Дело</h2>'
                   f'<p>Описание без выдуманных фактов.</p></article>'
                   f'</main></body></html>')
            file=self.parent/host/'public_html'/rel
            file.parent.mkdir(parents=True,exist_ok=True)
            file.write_text(source,encoding='utf-8')
            self.initial[file]=source
            self.meta['sites'][0 if host==HOSTS[0] else 1]['changes'].append({
                'path':rel,
                'expected':{'title':oldtitle,'description':olddesc},
                'proposed':{'title':newtitle,'description':newdesc}
            })
            if is_case:
                self.links['changes'].append({
                    'host':host,'path':rel,'url':'https://'+host+'/'+rel,
                    'expectedTitle':oldtitle,
                    'related':[
                        {'href':'/services/other-service.html',
                         'label':'Юридическая помощь по похожим вопросам'},
                        {'href':'/practice/index.html',
                         'label':'Примеры судебной практики'}
                    ]
                })
    def tearDown(self):
        self.tmp.cleanup()
    def test_combined_release_dryrun_and_backup(self):
        changes,overlap=build_release(self.meta,self.links,self.parent)
        self.assertEqual(overlap,13)
        self.assertEqual(len(changes),20)
        for file,info in changes.items():
            self.assertEqual(file.read_text(encoding='utf-8'),self.initial[file])
            self.assertIn('Новый заголовок',info['new'].decode())
            if '/cases/' in str(file):
                self.assertIn('article-related',info['new'].decode())
        backup,count=apply_edits(changes,self.parent)
        self.assertEqual(count,20)
        for file,info in changes.items():
            new=file.read_bytes()
            self.assertEqual(new,info['new'])
            self.assertEqual(
                (backup/info['domain']/info['path']).read_text(encoding='utf-8'),
                self.initial[file]
            )
    def test_concurrent_write_before_apply_refuses_all(self):
        changes,_=build_release(self.meta,self.links,self.parent)
        target=next(iter(changes.keys()))
        target.write_text('Edited by another administrator',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'source changed since preflight'):
            apply_edits(changes,self.parent)
        self.assertEqual(target.read_text(encoding='utf-8'),'Edited by another administrator')
        for path in list(changes.keys())[1:]:
            self.assertEqual(path.read_text(encoding='utf-8'),self.initial[path])
        self.assertEqual(list(self.parent.glob('.oleg-seo-metadata-backup-*')),[])
    def test_mismatch_domain_list_rejected(self):
        bad=deepcopy(self.meta)
        bad['sites'][1]['host']='some-other-site.ru'
        with self.assertRaisesRegex(ValueError,'allowlist'):
            build_release(bad,self.links,self.parent)
    def test_reject_missing_or_extra_change(self):
        bad=deepcopy(self.meta)
        bad['sites'][0]['changes'].pop()
        with self.assertRaisesRegex(ValueError,'exactly 20'):
            build_release(bad,self.links,self.parent)


if __name__=='__main__':
    unittest.main()
