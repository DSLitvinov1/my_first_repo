import tempfile
import unittest
from pathlib import Path

from case_links_guard import transform, prepare, make_section
from metadata_guard import apply_edits

DOC = '''<!doctype html><html lang="ru"><head>
<title>Спор о недостатках жилья</title><link rel="canonical" href="https://potrebpravo.ru/practice/cases/developer-one.html">
<meta name="description" content="Судебная практика по недостаткам жилья"></head>
<body><header><h1>Спор о недостатках жилья</h1></header><main class="case">
<article class="article"><h2>Предмет разбирательства</h2><p>Проверка документов.</p></article>
</main><footer>Контакты</footer></body></html>'''
ITEM = {
 'host':'potrebpravo.ru','path':'practice/cases/developer-one.html',
 'url':'https://potrebpravo.ru/practice/cases/developer-one.html',
 'expectedTitle':'Спор о недостатках жилья',
 'related':[
  {'href':'/services/neustoyka-zastroishchika.html','label':'Споры с застройщиком'},
  {'href':'/services/nekachestvennye-uslugi.html','label':'Качество работ и услуг'}
 ]
}

class GuardTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.parent=Path(self.tmp.name)
  self.root=self.parent/'potrebpravo.ru'/'public_html'/'practice'/'cases'
  self.root.mkdir(parents=True)
  (self.root/'developer-one.html').write_text(DOC,encoding='utf-8')
 def tearDown(self):
  self.tmp.cleanup()
 def plan(self,item=None):
  return {'status':'REVIEW_ONLY_NOT_DEPLOYED','changes':[item or ITEM]}
 def test_dry_run_preserves_html_and_apply_is_idempotent(self):
  edits=prepare(self.plan(),self.parent)
  before=(self.root/'developer-one.html').read_text(encoding='utf-8')
  self.assertEqual(before,DOC)
  self.assertIn('<nav class="article-related"',edits[self.root/'developer-one.html']['new'].decode())
  self.assertIn('href="/services/neustoyka-zastroishchika.html"',edits[self.root/'developer-one.html']['new'].decode())
  backup,count=apply_edits(edits,self.parent)
  self.assertEqual(count,1)
  final=(self.root/'developer-one.html').read_text(encoding='utf-8')
  self.assertIn('Споры с застройщиком',final)
  self.assertEqual((backup/'potrebpravo.ru'/'practice'/'cases'/'developer-one.html').read_text(encoding='utf-8'),DOC)
  self.assertEqual(prepare(self.plan(),self.parent)[self.root/'developer-one.html']['new'],final.encode())
 def test_title_drift_blocks(self):
  other={**ITEM,'expectedTitle':'Кто-то поменял заголовок'}
  with self.assertRaisesRegex(ValueError,'changed'):
   transform(DOC,other)
 def test_duplicate_existing_link_blocks(self):
  s=DOC.replace('</article>','<a href="/services/neustoyka-zastroishchika.html">Есть ссылка</a></article>')
  with self.assertRaisesRegex(ValueError,'already present'):
   transform(s,ITEM)
 def test_missing_main_or_article_blocks(self):
  with self.assertRaisesRegex(ValueError,'main container'):
   transform(DOC.replace('<main','<section').replace('</main>','</section>'),ITEM)
  with self.assertRaisesRegex(ValueError,'one <article'):
   transform(DOC.replace('class="article"','class="wrong"'),ITEM)
 def test_unsafe_link_rejected(self):
  for href in ['//outside.ru/', 'https://bad.tld/page', '/services/../file.html', '/services/path?token=1']:
   wrong={**ITEM,'related':[{'href':href,'label':'Читать'}]}
   with self.assertRaises(ValueError):
    make_section(wrong)
 def test_wrong_url_rejected(self):
  wrong={**ITEM,'url':'https://semya-yurist.ru/practice/cases/developer-one.html'}
  with self.assertRaisesRegex(ValueError,'exact case file'):
   transform(DOC,wrong)
 def test_disallowed_case_path_and_host_rejected(self):
  for value in ['../secrets.html', '/etc/passwd', 'services/strange.html']:
   wrong={**ITEM,'path':value}
   with self.assertRaises(ValueError):
    transform(DOC,wrong)
  with self.assertRaisesRegex(ValueError,'Invalid host'):
   transform(DOC,{**ITEM,'host':'other.net'})
 def test_source_guard_prevents_symlink(self):
  target=self.root/'developer-one.html'
  target.unlink()
  target.symlink_to(self.parent/'does-not-exist')
  with self.assertRaisesRegex(ValueError,'Unsafe'):
   prepare(self.plan(),self.parent)


if __name__=='__main__':
 unittest.main()
