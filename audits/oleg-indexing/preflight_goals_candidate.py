#!/usr/bin/env python3
import concurrent.futures,hashlib,json,tarfile,requests
from pathlib import Path
WORK=Path('/home/cloudagent/projects/oleg-seo-v24-analytics-intake-20261118')
ARCH=Path('/home/cloudagent/projects/oleg-seo-v23-analytics-watch-20261117/.private-v23-timeweb/approved-live-site-snapshot.tar.gz')
CAND=WORK/'.private-v24-offline/snapshot'
result={'expected_files':0,'candidate_changed':0,'candidate_unchanged':0,'changed_by_domain':{},'public_original_hash_matches':0,'public_failed':[],'public_mismatch':[]}
prior={}
with tarfile.open(ARCH,'r:gz') as tf:
 for m in tf.getmembers():
  b=tf.extractfile(m).read();prior[m.name]=hashlib.sha256(b).hexdigest()
  p=CAND/m.name
  if not p.is_file():raise RuntimeError('CANDIDATE_FILE_MISSING '+m.name)
  cur=hashlib.sha256(p.read_bytes()).hexdigest();changed=cur!=prior[m.name]
  result['candidate_changed']+=bool(changed);result['candidate_unchanged']+=not changed
  if changed:
   host=m.name.split('/')[0];result['changed_by_domain'][host]=result['changed_by_domain'].get(host,0)+1
result['expected_files']=len(prior)
def probe(name):
 url='https://'+name.replace('/public_html','',1)
 try:
  r=requests.get(url,timeout=13,headers={'User-Agent':'OlegLegalReadOnlyReleasePreflight/2026-11-18'})
  if r.status_code!=200:return name,'http_'+str(r.status_code)
  return name,hashlib.sha256(r.content).hexdigest()
 except Exception as e:return name,type(e).__name__
changed=[name for name,sha in prior.items() if hashlib.sha256((CAND/name).read_bytes()).hexdigest()!=sha]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
 for name,h in ex.map(probe,changed):
  if h==prior[name]:result['public_original_hash_matches']+=1
  elif not (len(h)==64 and all(c in '0123456789abcdef' for c in h)):result['public_failed'].append({'path':name,'status':h})
  else:result['public_mismatch'].append(name)
p=WORK/'.private-v24-offline/live-baseline-vs-candidate.json'
p.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(result,ensure_ascii=False,indent=2))