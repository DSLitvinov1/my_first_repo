#!/usr/bin/env python3
"""Read-only, rate-limited public SEO inventory for two Oleg Legal sites."""
from html.parser import HTMLParser
from urllib.parse import urljoin,urlparse,urldefrag
from xml.etree import ElementTree as ET
from collections import defaultdict,Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime, timezone
import requests,json,os,re,hashlib
HOSTS=('potrebpravo.ru','semya-yurist.ru')
BASE=os.path.dirname(__file__)
OUT=os.path.join(BASE,'../../.private-v25-offline')
os.makedirs(OUT,exist_ok=True)
class Page(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True)
  self.title='';self.desc='';self.canonical='';self.robots='';self.h1=[];self.h2=[];self.links=[];self.images=[];self.jsonld=[];self.lang='';self.headings=[];self._stack=[];self._capture=None;self._text='';self._ld='';self.maintext=[];self.anchors=0;self.meta={};self.form_count=0
 def handle_starttag(self,tag,attrs):
  d=dict(attrs)
  if tag=='html':self.lang=d.get('lang','')
  if tag=='title':self._capture='title';self._text=''
  if tag in ('h1','h2','h3'):self._capture=tag;self._text=''
  if tag=='script' and d.get('type','').lower()=='application/ld+json':self._capture='ld';self._ld=''
  if tag=='meta':
   name=(d.get('name') or d.get('property') or '').lower()
   self.meta[name]=d.get('content','')
   if name=='description':self.desc=d.get('content','')
   if name in ('robots','googlebot','yandex'):self.robots+=name+': '+d.get('content','')+' '
  if tag=='link' and 'canonical' in d.get('rel','').lower():self.canonical=d.get('href','')
  if tag=='a':
   self.anchors+=1
   self.links.append({'href':d.get('href',''),'text':''})
  if tag=='img':self.images.append({'src':d.get('src',''),'alt':d.get('alt'),'width':d.get('width'),'height':d.get('height'),'loading':d.get('loading')})
  if tag=='form':self.form_count+=1
 def handle_data(self,v):
  if self._capture=='ld':self._ld+=v
  elif self._capture:self._text+=v
  elif v.strip():self.maintext.append(v.strip())
 def handle_endtag(self,tag):
  if self._capture==tag:
   text=re.sub(r'\s+',' ',self._text).strip()
   if tag=='title':self.title=text
   if tag=='h1':self.h1.append(text)
   if tag=='h2':self.h2.append(text)
   self._capture=None
  elif tag=='script' and self._capture=='ld':
   self.jsonld.append(self._ld);self._capture=None
def get(url):
 try:
  r=requests.get(url,timeout=22,headers={'User-Agent':'OlegLegalAuthorizedSiteQA/1.0'},allow_redirects=True)
  return r,None
 except Exception as e:return None,str(e)
def check(host,url):
 r,err=get(url);o={'host':host,'url':url,'error':err}
 if r is None:return o
 o.update({'status':r.status_code,'final':r.url,'bytes':len(r.content),'redirects':len(r.history),'ctype':r.headers.get('Content-Type',''),'xrobots':r.headers.get('X-Robots-Tag',''),'server':r.headers.get('server',''),'security_headers':{k:r.headers.get(k,'') for k in ('Content-Security-Policy','Strict-Transport-Security','X-Content-Type-Options')}})
 if r.status_code!=200 or 'text/html' not in o['ctype']:return o
 p=Page();p.feed(r.text);o.update({'title':p.title,'title_len':len(p.title),'description':p.desc,'desc_len':len(p.desc),'canonical':p.canonical,'h1':p.h1,'h2_count':len(p.h2),'lang':p.lang,'robots':p.robots,'links':p.links,'images':p.images,'meta':p.meta,'forms':p.form_count,'words':len(re.findall(r'[а-яА-ЯёЁa-zA-Z0-9]{2,}', ' '.join(p.maintext))),'jsonld_count':len(p.jsonld)})
 o['jsonld_types']=[];o['jsonld_errors']=[]
 for s in p.jsonld:
  try:
   obj=json.loads(s)
   objects=obj.get('@graph',[]) if isinstance(obj,dict) and '@graph' in obj else [obj]
   for item in objects:
    if isinstance(item,dict):o['jsonld_types'].append(item.get('@type',''))
  except Exception as e:o['jsonld_errors'].append(str(e))
 o['issues']=[]
 for cond,msg in [(not p.title,'NO_TITLE'),(len(p.title)>75,'LONG_TITLE'),(len(p.desc)==0,'NO_DESCRIPTION'),(len(p.desc)>190,'LONG_DESCRIPTION'),(len(p.h1)!=1,'H1_NOT_SINGLE'),(p.canonical!=url,'CANONICAL_MISMATCH'),(not p.lang,'LANG_MISSING'),('noindex' in p.robots.lower(),'NOINDEX'),('noindex' in o['xrobots'].lower(),'X_ROBOTS_NOINDEX'),(len(p.images)>0 and any(x['alt'] is None for x in p.images),'IMG_ALT_ATTR_MISSING'),(len(p.jsonld)>0 and len(o['jsonld_errors'])>0,'BAD_JSONLD'),(o['words']<160,'SHORT_MAIN_TEXT')]:
  if cond:o['issues'].append(msg)
 return o
def run():
 siteurls={}
 for host in HOSTS:
  r,err=get('https://'+host+'/sitemap.xml')
  if err or r.status_code!=200:raise RuntimeError('Cannot fetch sitemap '+host+str(err))
  root=ET.fromstring(r.content)
  urls=[el.text.strip() for el in root.findall('.//{*}loc') if el.text and el.text.strip().startswith('https://'+host+'/')]
  siteurls[host]=list(dict.fromkeys(urls))
 items=[]
 with ThreadPoolExecutor(max_workers=4) as ex:
  fut={ex.submit(check,h,u):(h,u) for h,urls in siteurls.items() for u in urls}
  for f in as_completed(fut):
   try:items.append(f.result())
   except Exception as e:items.append({'url':fut[f][1],'error':str(e)})
 items.sort(key=lambda x:(x.get('host',''),x.get('url','')))
 titles=defaultdict(list);descs=defaultdict(list);sitecounts={}
 for x in items:
  if 'title' in x:titles[(x['host'],x['title'])].append(x['url']);descs[(x['host'],x['description'])].append(x['url'])
 for host in HOSTS:
  rows=[x for x in items if x.get('host')==host]
  discovered=set();indexed=set(siteurls[host]);malformed=[];potential=[]
  for x in rows:
   for a in x.get('links',[]):
    href=a['href']
    if not href or href.startswith(('#','tel:','mailto:','javascript:')):continue
    full=urldefrag(urljoin(x['url'],href))[0].split('?')[0]
    if urlparse(full).netloc==host:
     discovered.add(full)
     if full not in indexed and not re.search(r'\.(css|js|png|jpg|jpeg|svg|webp|gif|ico|pdf|xml|php)$',full,re.I):
      potential.append((x['url'],full))
  sitecounts[host]={'pages':len(rows),'status200':sum(x.get('status')==200 for x in rows),'errors':[{ 'url':x['url'],'issues':x.get('issues',[]),'error':x.get('error')} for x in rows if x.get('issues') or x.get('error') or x.get('status')!=200],
  'duplicate_titles':[{'title':k[1],'urls':v} for k,v in titles.items() if k[0]==host and len(v)>1],
  'duplicate_descriptions':[{'description':k[1][:80],'urls':v} for k,v in descs.items() if k[0]==host and len(v)>1],
  'internal_targets':len(discovered),'candidate_non_sitemap':list(dict.fromkeys(potential))[:90],
  'total_images':sum(len(x.get('images',[])) for x in rows),
  'images_missing_alt_attr':sum(sum(y['alt'] is None for y in x.get('images',[])) for x in rows),
  'schema_types':dict(Counter(str(t) for x in rows for t in x.get('jsonld_types',[])))}
 report={'checked_utc':datetime.now(timezone.utc).isoformat(),'summary':sitecounts,'pages':items}
 path=os.path.join(OUT,'v51_live_seo_inventory_20261119.json')
 with open(path,'w') as f:json.dump(report,f,ensure_ascii=False,indent=2)
 for host,x in sitecounts.items():
  print('SITE',host,'pages',x['pages'],'200',x['status200'],'issues_pages',len(x['errors']),'duplicates',len(x['duplicate_titles']),'non_sitemap',len(x['candidate_non_sitemap']),'missing_alt',x['images_missing_alt_attr'])
  print('ERRORS',json.dumps(x['errors'][:30],ensure_ascii=False))
  print('NOT_IN_SITEMAP',json.dumps(x['candidate_non_sitemap'][:24],ensure_ascii=False))
  print('SCHEMA',x['schema_types'])
 print('REPORT',path)
if __name__=='__main__':run()