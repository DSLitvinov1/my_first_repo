#!/usr/bin/env python3
"""Offline-only V54 full-directory payload for preflighted Timeweb atomic release.

Never touches the live server or extracts into production.
"""
import hashlib, json, tarfile
from pathlib import Path
from xml.etree import ElementTree
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'.private-v25-offline'/'snapshot'
STAGE=ROOT/'.private-v53-offline'/'release-a'
OUT=ROOT/'.private-v54-offline'
EXPECTED=ROOT/'.private-v25-offline'/'v25-utm-manifest.json'
DELTA=ROOT/'.private-v53-offline'/'v53-release-a-manifest.json'
HOSTS=('potrebpravo.ru','semya-yurist.ru')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory(root):
 result={}
 for p in root.rglob('*'):
  if p.is_symlink():raise RuntimeError('Symlink forbidden: '+str(p))
  if p.is_file():
   rel=p.relative_to(root).as_posix()
   if '..' in Path(rel).parts:raise RuntimeError('Traversal')
   result[rel]=sha(p)
 return result
def run():
 if not (EXPECTED.is_file() and DELTA.is_file()):raise RuntimeError('Missing trusted manifests')
 v25=json.loads(EXPECTED.read_text())
 release=json.loads(DELTA.read_text())
 assert v25['count']==168
 assert release['status']=='OFFLINE_SAFE_RELEASE_A_NOT_PUBLISHED'
 rows=[];counts={};changes=[]
 for host in HOSTS:
  origin=BASE/host/'public_html'
  target=STAGE/host/'public_html'
  assert origin.is_dir() and target.is_dir()
  baseline=inventory(origin)
  current=inventory(target)
  if baseline!=v25['candidate_sha256'][host]:raise RuntimeError('V25 baseline drift: '+host)
  if baseline.keys()!=current.keys():raise RuntimeError('Unexpected files added/removed: '+host)
  count=0
  for rel,new_hash in sorted(current.items()):
   p=target/rel
   if not p.is_file():raise RuntimeError('Non-file payload')
   if rel.endswith('.html') and any(
       name in p.read_text() for name in ('otkaz-ot-uslug.html','razdel-dolgov.html')
   ):raise RuntimeError('Unpublished legal article leaked')
   rows.append({'site':host,'file':rel,'sha256':new_hash})
   if baseline[rel]!=new_hash:
    changes.append({'site':host,'file':rel,'old':baseline[rel],'new':new_hash})
    count+=1
  xml=ElementTree.fromstring((target/'sitemap.xml').read_bytes())
  sitemap_urls=[x.text for x in xml.findall('.//{*}loc')]
  expected=23 if host=='potrebpravo.ru' else 18
  if len(sitemap_urls)!=expected or len(set(sitemap_urls))!=expected:
   raise RuntimeError('Wrong XML sitemap: '+host)
  counts[host]={'baseline':len(baseline),'candidate':len(current),'changes':count,'sitemap':len(sitemap_urls)}
 if len(rows)!=168 or len(changes)!=release['count']:raise RuntimeError('Unexpected file delta')
 manifest_deltas={(x['site'],x['file'],x['sha256']) for x in release['changes']}
 if manifest_deltas!={(x['site'],x['file'],x['new']) for x in changes}:
  raise RuntimeError('V53 staged delta mismatch')
 OUT.mkdir(exist_ok=True)
 dest=OUT/'v54-release-a-full-168-v25-to-v53-20261119.tar.gz'
 if dest.exists():raise FileExistsError('Refuse to overwrite immutable archive')
 with tarfile.open(dest,'w:gz') as tf:
  for r in rows:
   name=str(Path(r['site'])/'public_html'/r['file'])
   tf.add(STAGE/name,arcname=name,recursive=False)
 with tarfile.open(dest,'r:gz') as tf:
  members=tf.getmembers()
  if len(members)!=168 or any(not x.isfile() or x.name.startswith('/') or '..' in Path(x.name).parts for x in members):
   raise RuntimeError('Unsafe or incomplete archive')
  for r in rows:
   key=str(Path(r['site'])/'public_html'/r['file'])
   value=tf.extractfile(key)
   if value is None or hashlib.sha256(value.read()).hexdigest()!=r['sha256']:
    raise RuntimeError('Archive SHA mismatch '+key)
 result={'status':'OFFLINE_PREPARED_NO_TIMEWEB_WRITE','produced':'2026-11-19','target':'V53 Release A',
         'baseline':'V25','entries':len(rows),'modified':len(changes),
         'sites':counts,'archive':{'name':dest.name,'bytes':dest.stat().st_size,'sha256':sha(dest)},
         'requires_before_release':['authorized Timeweb login','read-only live SHA verification',
                                   'new off-server and on-server backup','rollback validation',
                                   'atomic site switch and post-release checks']}
 (OUT/'v54-full-release-manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
 print('V54_FULL_RELEASE_PREPARED',json.dumps({k:result[k] for k in ['status','entries','modified','sites','archive']},ensure_ascii=False))
if __name__=='__main__':run()