#!/usr/bin/env python3
"""V53 release A: independent non-legal site fixes from V25; no unpublished URLs."""
from pathlib import Path
from xml.etree import ElementTree as ET
import re,hashlib,shutil,tarfile,json
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'.private-v25-offline'/'snapshot'
SOURCE=ROOT/'.private-v52-offline'/'candidate'
DEST=ROOT/'.private-v53-offline'/'release-a'
OUT=ROOT/'.private-v53-offline'
SERVICES={
'potrebpravo.ru':['vozvrat-deneg.html','pretenziya-prodavcu.html','nekachestvennye-uslugi.html','neustoyka-zastroishchika.html','strahovye-spory.html','vozvrat-avtomobilya.html'],
'semya-yurist.ru':['razvod.html','alimenty.html','razdel-imushchestva.html','brachnyi-dogovor.html','ipotechnaya-kvartira.html','spory-o-detyakh.html']
}
EXCLUDED={'potrebpravo.ru':('otkaz-ot-uslug.html','<a href="../services/otkaz-ot-uslug.html">Отказ от услуг</a>'),
'semya-yurist.ru':('razdel-dolgov.html','<a href="../services/razdel-dolgov.html">Раздел долгов супругов</a>')}
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def generate():
 if DEST.exists():raise FileExistsError('Release A already exists: refuse silent overwrite')
 OUT.mkdir(parents=True,exist_ok=True)
 for host in SERVICES:shutil.copytree(BASE/host/'public_html',DEST/host/'public_html')
 for host,names in SERVICES.items():
  base=DEST/host/'public_html'
  v52=SOURCE/host/'public_html'
  for js in ['oleg-analytics-v1.js','legal-assistant-v4.js']:
   shutil.copy2(v52/'assets'/js,base/'assets'/js)
  versions={'oleg-analytics-v1.js':digest(base/'assets/oleg-analytics-v1.js')[:8],
            'legal-assistant-v4.js':digest(base/'assets/legal-assistant-v4.js')[:8]}
  exclusion,element=EXCLUDED[host]
  for name in names:
   src=v52/'services'/name;target=base/'services'/name
   s=src.read_text();count=s.count(element)
   if name==('nekachestvennye-uslugi.html' if host=='potrebpravo.ru' else 'razdel-imushchestva.html'):
    if count!=1:raise ValueError('Expected one new-page link in source '+host+name)
    s=s.replace(element,'')
   elif count:raise ValueError('Unexpected new-page link '+host+name)
   if 'oleg-direct-crm-link' not in s:raise ValueError('CTA missing '+host+name)
   target.write_text(s)
  num={'oleg-analytics-v1.js':0,'legal-assistant-v4.js':0}
  for f in base.rglob('*.html'):
   s=f.read_text()
   for js,v in versions.items():
    # A stable regex for a URL cache version, no HTML parsing transformation.
    pattern=r'(/assets/'+re.escape(js)+r'\?v=)[a-f0-9]{8}'
    s,n=re.subn(pattern,lambda m:m.group(1)+v,s);num[js]+=n
   f.write_text(s)
  if num['oleg-analytics-v1.js']<17 or num['legal-assistant-v4.js']<17:raise AssertionError('Cache version missed: '+host+str(num))
  x=base/'sitemap.xml';raw=x.read_text()
  for name in names:
   url='https://'+host+'/services/'+name
   pat=r'(<loc>'+re.escape(url)+r'</loc><lastmod>)\d{4}-\d{2}-\d{2}(</lastmod>)'
   replacement=r'\\g<1>2026-11-19\\g<2>'
   # Use lambda to keep regex group references literally out of replacement.
   raw,n=re.subn(pat,lambda m:m.group(1)+'2026-11-19'+m.group(2),raw)
   if n!=1:raise ValueError('Sitemap timestamp target mismatch '+url)
  ET.fromstring(raw)
  x.write_text(raw)
  print('SITE',host,'services',len(names),'cache_refs',num,'Sitemap_urls',len(ET.fromstring(raw).findall('.//{*}loc')))
 # Validate source version exactly equals certified V25; fail before building archives.
 v25=json.loads((ROOT/'.private-v25-offline/v25-utm-manifest.json').read_text())
 changes=[]
 for host in SERVICES:
  baseline=v25['candidate_sha256'][host];source={str(p.relative_to(BASE/host/'public_html')):digest(p) for p in (BASE/host/'public_html').rglob('*') if p.is_file()}
  if baseline!=source:raise RuntimeError('V25 source mismatch '+host)
  target={str(p.relative_to(DEST/host/'public_html')):digest(p) for p in (DEST/host/'public_html').rglob('*') if p.is_file()}
  if set(source)!=set(target):raise RuntimeError('Release A changed file count '+host)
  for rel,sha in target.items():
   if sha!=source[rel]:changes.append({'site':host,'file':rel,'baseline':source[rel],'sha256':sha})
  for file in (DEST/host/'public_html').rglob('*.html'):
   s=file.read_text()
   if EXCLUDED[host][0] in s:raise AssertionError('Unpublished page link '+str(file))
   if 'Электронный приём заявок появится' in s or 'Онлайн-заявки на сайте пока отключены' in s or 'неработающие формы' in s:raise AssertionError('Legacy CTA '+str(file))
 assert len(changes)>35
 archive=OUT/'v53-release-a-v25-safe-delta-20261119.tar.gz'
 with tarfile.open(archive,'w:gz') as t:
  for item in sorted(changes,key=lambda x:(x['site'],x['file'])):
   rel=Path(item['site'])/'public_html'/item['file'];t.add(DEST/rel,arcname=str(rel))
 with tarfile.open(archive,'r:gz') as t:
  names=t.getnames()
  assert len(names)==len(changes) and all(not n.startswith('/') and '..' not in Path(n).parts for n in names)
  for item in changes:
   key=str(Path(item['site'])/'public_html'/item['file'])
   assert hashlib.sha256(t.extractfile(key).read()).hexdigest()==item['sha256']
 manifest={'status':'OFFLINE_SAFE_RELEASE_A_NOT_PUBLISHED','v25_files':168,'staged_files':168,
           'two_new_legal_pages_excluded':True,'changes':changes,'archive':{'file':archive.name,'sha256':digest(archive),'bytes':archive.stat().st_size},'count':len(changes)}
 (OUT/'v53-release-a-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
 print('V53_RELEASE_A_VERIFIED',len(changes),'ARCHIVE',archive.stat().st_size,'SHA256',digest(archive))
if __name__=='__main__':generate()