#!/usr/bin/env python3
"""Build reproducible, SHA-guarded V52 cumulative delta from proven V25. Never deploy."""
from pathlib import Path
from urllib.parse import urljoin,urlsplit,urldefrag
from html.parser import HTMLParser
from xml.etree import ElementTree as ET
import hashlib,json,tarfile,re
ROOT=Path(__file__).resolve().parents[2]
V25=ROOT/'.private-v25-offline'/'snapshot'
V52=ROOT/'.private-v52-offline'/'candidate'
OUT=ROOT/'.private-v52-offline'
OLD=json.loads((ROOT/'.private-v25-offline'/'v25-utm-manifest.json').read_text())
HOSTS=['potrebpravo.ru','semya-yurist.ru']
def sha(b):return hashlib.sha256(b).hexdigest()
class SEO(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True);self.title=[];self.h1=[];self.canonical=[];self.desc=[];self.links=[];self.schema=[];self.stack=[];self.buf='';self.capture=None
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag=='title':self.capture='title';self.buf=''
  if tag=='h1':self.capture='h1';self.buf=''
  if tag=='link' and 'canonical' in a.get('rel',''):self.canonical.append(a.get('href',''))
  if tag=='meta' and a.get('name','').lower()=='description':self.desc.append(a.get('content',''))
  if tag=='a':self.links.append(a.get('href',''))
  if tag=='script' and a.get('type')=='application/ld+json':self.capture='ld';self.buf=''
 def handle_data(self,data):
  if self.capture:self.buf+=data
 def handle_endtag(self,tag):
  if tag==self.capture:
   (self.title if tag=='title' else self.h1 if tag=='h1' else self.schema).append(self.buf.strip())
   self.capture=None;self.buf=''
def run():
 results=[];changed=[];errors=[]
 for host in HOSTS:
  base=V25/host/'public_html'
  latest=V52/host/'public_html'
  originals={str(p.relative_to(base)):sha(p.read_bytes()) for p in base.rglob('*') if p.is_file()}
  expected=OLD['candidate_sha256'][host]
  if originals!=expected:raise RuntimeError('V25 snapshot SHA drift '+host)
  candidate={str(p.relative_to(latest)):sha(p.read_bytes()) for p in latest.rglob('*') if p.is_file()}
  if set(originals)-set(candidate):raise RuntimeError('Files removed from V52 '+host)
  sitemap=ET.fromstring((latest/'sitemap.xml').read_bytes())
  urls=[x.text for x in sitemap.findall('.//{*}loc')]
  if len(set(urls))!=len(urls):raise RuntimeError('Duplicate sitemap '+host)
  for url in urls:
   if not url.startswith('https://'+host+'/'):raise RuntimeError('Foreign URL '+url)
   rel=urlsplit(url).path.lstrip('/') or 'index.html';p=latest/rel
   if not p.is_file():errors.append('URL has no file '+url);continue
   s=p.read_text();h=SEO();h.feed(s)
   if not h.title or len(h.h1)!=1 or h.canonical!=[url] or len(h.desc)!=1:errors.append('SEO tags '+url)
   for block in h.schema:
    try:json.loads(block)
    except Exception:errors.append('Invalid schema '+url)
   for href in h.links:
    if not href or href.startswith(('mailto:','tel:','#','javascript:')):continue
    target=urldefrag(urljoin(url,href))[0]
    q=urlsplit(target)
    if q.netloc!=host:continue
    rel=(q.path.lstrip('/') or 'index.html')
    if rel and not (latest/rel).exists() and not (latest/rel/'index.html').exists():errors.append('Broken internal link '+url+' -> '+rel)
   if '/services/' in url:
    good='crm_form_fhi3n' if host=='potrebpravo.ru' else 'crm_form_ep5fd'
    if good not in s:errors.append('Missing own form '+url)
    if ('crm_form_ep5fd' if good=='crm_form_fhi3n' else 'crm_form_fhi3n') in s:errors.append('Foreign form '+url)
  changed_now=[{'site':host,'file':f,'prior_sha':originals.get(f),'sha':digest} for f,digest in candidate.items() if originals.get(f)!=digest]
  changed.extend(changed_now)
  results.append({'site':host,'base_files':len(originals),'candidate_files':len(candidate),'updated_or_new':len(changed_now),'sitemap_urls':len(urls)})
 if errors:raise RuntimeError('V52 validation failed: '+str(errors[:12]))
 total=sum(x['sitemap_urls'] for x in results)
 if total!=43 or len(changed)<50:raise RuntimeError('Unexpected totals: '+str((total,len(changed))))
 archive=OUT/'v52-cumulative-v25-delta-20261119.tar.gz'
 with tarfile.open(archive,'w:gz') as ar:
  for x in sorted(changed,key=lambda x:(x['site'],x['file'])):
   arc=Path(x['site'])/'public_html'/x['file']
   file=V52/arc
   if file.is_symlink() or not file.is_file():raise RuntimeError('Unsafe archive source '+str(file))
   ar.add(file,arcname=str(arc))
 with tarfile.open(archive,'r:gz') as ar:
  members=ar.getmembers()
  if len(members)!=len(changed) or any(not x.isfile() or x.name.startswith('/') or '..' in Path(x.name).parts for x in members):raise RuntimeError('Unsafe archive member')
  for x in changed:
   arc=str(Path(x['site'])/'public_html'/x['file'])
   member=ar.extractfile(arc)
   if not member or sha(member.read())!=x['sha']:raise RuntimeError('Archive content changed '+arc)
 manifest={'status':'STAGED_V52_ONLY_NOT_PUBLISHED','source_version':'v25-utm-20261118','target_version':'v52-internal-attribution-20261119','baseline_files':168,'candidate_files':170,'sitemap_urls':total,'files_changed':len(changed),'sites':results,'files':changed,
 'archive':{'name':archive.name,'bytes':archive.stat().st_size,'sha256':sha(archive.read_bytes())}}
 (OUT/'v52-cumulative-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
 print('V52_CUMULATIVE_ARCHIVE_OK',json.dumps({k:manifest[k] for k in ('status','baseline_files','candidate_files','sitemap_urls','files_changed','sites','archive')},ensure_ascii=False))
if __name__=='__main__':run()