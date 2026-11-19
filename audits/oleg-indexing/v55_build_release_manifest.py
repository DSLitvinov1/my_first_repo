#!/usr/bin/env python3
"""Prepare a strict immutable V55 Timeweb release manifest from verified V25 and V53 data.

No connection, no production changes; reuses existing full 168-file V54 archive.
"""
from pathlib import Path
import hashlib, json
from xml.etree import ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/'.private-v25-offline'/'v25-utm-manifest.json'
V54=ROOT/'.private-v54-offline'
STAGE=ROOT/'.private-v53-offline'/'release-a'
OUT=ROOT/'.private-v55-offline'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run():
 source=json.loads(SRC.read_text())
 archive_meta=json.loads((V54/'v54-full-release-manifest.json').read_text())
 assert source['count']==168 and archive_meta['entries']==168 and archive_meta['modified']==53
 archive=V54/archive_meta['archive']['name']
 if sha(archive)!=archive_meta['archive']['sha256']:raise RuntimeError('Archive SHA drift')
 expected={}
 for site in ('potrebpravo.ru','semya-yurist.ru'):
  root=STAGE/site/'public_html'
  target={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}
  base=source['candidate_sha256'][site]
  if set(target)!=set(base):raise RuntimeError('Files changed in candidate '+site)
  for u in ET.parse(root/'sitemap.xml').findall('.//{*}loc'):
   assert u.text.startswith('https://'+site+'/')
  expected[site]={'baseline':base,'target':target}
 expected_changes=sum(a!=expected[site]['target'][rel] for site in expected for rel,a in expected[site]['baseline'].items())
 if expected_changes!=53:raise RuntimeError('Wrong diff count')
 out={'version':'v55-release-a-20261119','status':'PREPARED_OFFLINE_NOT_DEPLOYED','host_home':'/home/c/cl664853','sites':list(expected),'expected':expected,'count':168,'changed_count':53,'archive_name':archive.name,'archive_sha256':sha(archive),'sitemap':{'potrebpravo.ru':23,'semya-yurist.ru':18}}
 OUT.mkdir(exist_ok=True)
 filename=OUT/'v55-release-manifest.json'
 if filename.exists():raise FileExistsError('Refuse overwrite of approved candidate')
 filename.write_text(json.dumps(out,ensure_ascii=False,indent=2))
 print('V55_TRUSTED_MANIFEST',filename,'BASE',out['count'],'CHANGED',out['changed_count'],'ARCHIVE_SHA',out['archive_sha256'])
if __name__=='__main__':run()