#!/usr/bin/env python3
"""Strict offline V51 acceptance: V25 provenance, 43 URLs, 14 real form CTAs, zero broken links."""
import hashlib,json,re,sys
from pathlib import Path
from urllib.parse import urljoin,urlparse,urldefrag
from xml.etree import ElementTree as ET
sys.path.insert(0,str(Path(__file__).parent))
from v51_live_seo_inventory_20261119 import Page
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'.private-v25-offline'/'snapshot'
CANDIDATE=ROOT/'.private-v51-offline'/'candidate'
V25=json.loads((ROOT/'.private-v25-offline/v25-utm-manifest.json').read_text())
FORM={'potrebpravo.ru':'crm_form_fhi3n','semya-yurist.ru':'crm_form_ep5fd'}
NEW={'potrebpravo.ru':'/services/otkaz-ot-uslug.html','semya-yurist.ru':'/services/razdel-dolgov.html'}
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def local_path(root,url):
 p=urlparse(url).path
 if p=='/':p='/index.html'
 elif p.endswith('/'):p+='index.html'
 return root/p.lstrip('/')
def run():
 errors=[];result={'mode':'OFFLINE ONLY — NOT DEPLOYED','sites':{},'checked':0,'errors':errors,'changed':[]}
 for host,files in V25['candidate_sha256'].items():
  base=BASE/host/'public_html';dst=CANDIDATE/host/'public_html'
  for rel,sha in files.items():
   path=base/rel
   if not path.is_file() or digest(path)!=sha:errors.append('V25 SOURCE DRIFT '+host+'/'+rel)
  original={str(x.relative_to(base)):digest(x) for x in base.rglob('*') if x.is_file()}
  changed=[rel for rel,sha in original.items() if digest(dst/rel)!=sha]
  new=[str(x.relative_to(dst)) for x in dst.rglob('*') if x.is_file() and str(x.relative_to(dst)) not in original]
  if len(changed)!=8 or len(new)!=1:errors.append('UNEXPECTED FILE MODIFICATIONS '+host+' '+str(len(changed))+'/'+str(len(new)))
  for rel in changed+new:result['changed'].append({'site':host,'file':rel,'sha256':digest(dst/rel),'baseline_sha256':original.get(rel)})
  xml=ET.fromstring((dst/'sitemap.xml').read_bytes())
  urls=[node.text for node in xml.findall('.//{*}loc') if node.text]
  if len(urls)!=len(set(urls)):errors.append('DUPLICATE SITEMAP URL '+host)
  if 'https://'+host+NEW[host] not in urls:errors.append('NEW PAGE NOT IN SITEMAP '+host)
  expected=24 if host=='potrebpravo.ru' else 19
  if len(urls)!=expected:errors.append('WRONG SITEMAP SIZE '+host+' '+str(len(urls)))
  page_rows=[];titles={};descs={}
  for url in urls:
   result['checked']+=1
   f=local_path(dst,url)
   if not f.is_file():errors.append('MISSING TARGET '+url);continue
   s=f.read_text(); p=Page();p.feed(s)
   row={'url':url,'words':len(re.findall(r'[а-яА-ЯёЁa-zA-Z0-9]{2,}',' '.join(p.maintext))),'headlines':len(p.h1),'jsonld':len(p.jsonld)}
   page_rows.append(row)
   for predicate,issue in [(p.canonical!=url,'CANONICAL'),(not p.title,'TITLE'),(not p.desc,'DESCRIPTION'),(len(p.h1)!=1,'H1'),('noindex' in p.robots.lower(),'NOINDEX'),(len(p.jsonld)==0,'SCHEMA')]:
    if predicate:errors.append(issue+' '+url)
   if p.title in titles:errors.append('DUPLICATE TITLE '+url+' + '+titles[p.title])
   if p.desc in descs:errors.append('DUPLICATE DESCRIPTION '+url+' + '+descs[p.desc])
   titles[p.title]=url;descs[p.desc]=url
   for script in p.jsonld:
    try:json.loads(script)
    except Exception as e:errors.append('BAD JSONLD '+url+' '+str(e))
   for a in p.links:
    href=a.get('href','')
    if not href or href.startswith(('#','tel:','mailto:','javascript:')):continue
    full=urldefrag(urljoin(url,href))[0].split('?')[0]
    parsed=urlparse(full)
    if parsed.scheme in ('http','https') and parsed.netloc==host:
     loc=local_path(dst,full)
     if not loc.exists():errors.append('BROKEN INTERNAL LINK '+url+' -> '+full)
   if url.endswith(NEW[host]):
    if row['words']<450:errors.append('NEW PAGE THIN CONTENT '+url+' '+str(row['words']))
   if '/services/' in url:
    cta=[x for x in p.links if FORM[host] in x.get('href','')]
    if len(cta)!=1:errors.append('MISSING OR DUPLICATE CORRECT CRM CTA '+url)
    wrong='crm_form_ep5fd' if FORM[host]=='crm_form_fhi3n' else 'crm_form_fhi3n'
    if wrong in s:errors.append('WRONG SITE FORM '+url)
  result['sites'][host]={'sitemap_urls':len(urls),'pages_audited':len(page_rows),'modified_existing':len(changed),'new_files':new,'new_page_words':next((x['words'] for x in page_rows if x['url'].endswith(NEW[host])),None)}
 result['valid']=len(errors)==0
 out=ROOT/'.private-v51-offline/v51-final-structural-acceptance.json'
 out.write_text(json.dumps(result,ensure_ascii=False,indent=2))
 print('V51_STRUCTURAL_ACCEPTANCE',json.dumps({'valid':result['valid'],'sitemap_total':result['checked'],'files_modified':len(result['changed']),'errors':errors[:35]},ensure_ascii=False))
 if errors:raise SystemExit(2)
if __name__=='__main__':run()