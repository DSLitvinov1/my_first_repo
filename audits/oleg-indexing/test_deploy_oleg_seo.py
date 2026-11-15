import tempfile
import unittest
from pathlib import Path
from copy import deepcopy

from deploy_oleg_seo import build_release, build_full_release
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
    def setup_site_assistant_fixture(self):
        from lead_assistant_guard import SCRIPT
        for host,count in [('potrebpravo.ru',23),('semya-yurist.ru',18)]:
            site_root=self.parent/host/'public_html'
            asset=site_root/'assets'/'legal-assistant-v4.js'
            asset.parent.mkdir(parents=True,exist_ok=True)
            from bitrix_fallback_guard import FROM
            js='const forms={consumer:"crm_form_fhi3n",family:"crm_form_ep5fd"};document.getElementById("legal-help-toggle");const id="legal-help-form-step";\n'
            js+='\n'.join(before for before,_ in FROM)
            asset.write_text(js,encoding='utf-8')
            self.initial[asset]=js
            existing=[str(p.relative_to(site_root)) for p in self.initial if p.is_relative_to(site_root) and p.suffix=='.html']
            extras=['index.html']
            n=0
            while len(set(existing+extras))<count:
                rel=f'services/extra-{n}.html'
                extras.append(rel)
                n+=1
            pages=list(dict.fromkeys(existing+extras))
            self.assertEqual(len(pages),count)
            for rel in extras:
                path=site_root/rel
                if path not in self.initial:
                    path.parent.mkdir(parents=True,exist_ok=True)
                    code='<html><head><title>Страница</title></head><body><main>Информация</main></body></html>'
                    if rel=='index.html':
                        code=code.replace('</body>',SCRIPT+'</body>')
                    path.write_text(code,encoding='utf-8')
                    self.initial[path]=code
            urls=['https://'+host+('/' if rel=='index.html' else '/'+rel) for rel in pages]
            (site_root/'sitemap.xml').write_text('<urlset>'+''.join('<url><loc>'+url+'</loc></url>' for url in urls)+'</urlset>',encoding='utf-8')

    def test_full_seo_and_bitrix_release_without_overwriting_sources(self):
        self.setup_site_assistant_fixture()
        changes,overlap,missing=build_full_release(self.meta,self.links,self.parent)
        self.assertEqual(len(changes),43)
        self.assertEqual(overlap,13)
        self.assertEqual(missing,39)
        self.assertEqual(sum(x['new']!=x['old'] for x in changes.values()),41)
        for path,old in self.initial.items():
            self.assertEqual(path.read_text(encoding='utf-8'),old)
        backup,changed=apply_edits(changes,self.parent)
        self.assertEqual(changed,41)
        for path,info in changes.items():
            new=path.read_text(encoding='utf-8')
            self.assertEqual(new,info['new'].decode('utf-8'))
            if path.suffix=='.js':
                self.assertIn('formStep.insertBefore(fallback, frame);',new)
            else:
                self.assertIn('/assets/legal-assistant-v4.js',new)
            self.assertEqual((backup/info['domain']/info['path']).read_text(encoding='utf-8'),self.initial[path])
            if path.name.startswith('case-'):
                self.assertIn('article-related',new)
                self.assertIn('Новый заголовок',new)

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
