#!/usr/bin/env python3
"""V55 safe Timeweb two-domain release with fresh verified backup and rollback.

Deploy only after a verified authorized server session. Offline unit tests use
an explicitly provided temporary --home. No secrets, REST keys, or payments.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, tarfile, tempfile, time
import urllib.request
from datetime import datetime, timezone
SITES=('potrebpravo.ru','semya-yurist.ru')
READY='public_html.v55-a-ready'
PRIOR='public_html.v55-a-prior'
WITHDRAWN='public_html.v55-a-withdrawn'
VERSION='v55-release-a-20261119'
class Stop(RuntimeError):pass
def need(ok,msg):
 if not ok:raise Stop(msg)
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
 return h.hexdigest()
def inv(root):
 need(root.is_dir() and not root.is_symlink(),'INVALID_DIR '+str(root))
 out={}
 for folder, dirs, files in os.walk(root,followlinks=False):
  for name in dirs:need(not (pathlib.Path(folder)/name).is_symlink(),'SYMLINK_DIR')
  for name in files:
   f=pathlib.Path(folder)/name
   need(f.is_file() and not f.is_symlink(),'BAD_FILE '+str(f))
   out[f.relative_to(root).as_posix()]=digest(f)
 return out
class Release:
 def __init__(self,home,ops,*,test_mode=False,fail_after=None):
  self.home=pathlib.Path(home)
  self.ops=pathlib.Path(ops)
  self.fail_after=fail_after
  need(self.home.is_dir() and self.home.resolve()==self.home,'UNEXPECTED_HOME')
  if not test_mode:need(str(self.home)=='/home/c/cl664853' and str(self.ops)==str(self.home/'.oleg-seo-ops/v55-release-a'),'WRONG_PRODUCTION_PATH')
  need(self.ops.is_dir() and not self.ops.is_symlink(),'OPS_MISSING')
  self.meta=json.loads((self.ops/'v55-release-manifest.json').read_text())
  need(self.meta.get('version')==VERSION and self.meta.get('status')=='PREPARED_OFFLINE_NOT_DEPLOYED','INVALID_MANIFEST')
  need(self.meta.get('sites')==list(SITES) and self.meta.get('count')==168 and self.meta.get('changed_count')==53,'INVALID_COUNTS')
  self.base={h:self.meta['expected'][h]['baseline'] for h in SITES}
  self.new={h:self.meta['expected'][h]['target'] for h in SITES}
  need(sum(len(self.new[h]) for h in SITES)==168,'INVALID_FILE_COUNT')
  for h in SITES:need(self.base[h].keys()==self.new[h].keys(),'MISMATCH_FILE_LIST '+h)
  need(self.meta['archive_name']=='v54-release-a-full-168-v25-to-v53-20261119.tar.gz','WRONG_ARCHIVE_NAME')
 def live(self,h):return self.home/h/'public_html'
 def ready(self,h):return self.home/h/READY
 def prior(self,h):return self.home/h/PRIOR
 def withdrawn(self,h):return self.home/h/WITHDRAWN
 def journal(self):
  p=self.ops/'release-state.json'
  return json.loads(p.read_text()) if p.exists() else {}
 def mark(self,phase,**details):
  out=self.ops/'release-state.json';tmp=self.ops/'release-state.json.tmp'
  need(not tmp.exists(),'JOURNAL_TMP_EXISTS')
  entry={**self.journal(),'version':VERSION,'phase':phase,**details}
  with tmp.open('x') as f:
   json.dump(entry,f,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
  os.replace(tmp,out)
 def archive(self):
  f=self.ops/self.meta['archive_name']
  need(f.is_file() and not f.is_symlink() and digest(f)==self.meta['archive_sha256'],'ARCHIVE_SHA_MISMATCH')
  return f
 def archive_verify(self,archive,expected):
  with tarfile.open(archive,'r:gz') as tf:
   files=[m for m in tf.getmembers() if m.isfile()]
   need(len(files)==168 and len(tf.getmembers())==168,'ARCHIVE_FILE_COUNT')
   seen=set()
   for m in files:
    p=pathlib.PurePosixPath(m.name)
    need(not p.is_absolute() and '..' not in p.parts and len(p.parts)>=3 and p.parts[0] in SITES and p.parts[1]=='public_html','BAD_ARCHIVE_PATH '+m.name)
    name='/'.join(p.parts[2:])
    need(name in expected[p.parts[0]] and (p.parts[0],name) not in seen,'UNEXPECTED_ARCHIVE_ENTRY '+m.name)
    need(hashlib.sha256(tf.extractfile(m).read()).hexdigest()==expected[p.parts[0]][name],'ARCHIVE_CONTENT_SHA '+m.name)
    seen.add((p.parts[0],name))
   need(len(seen)==168,'ARCHIVE_INCOMPLETE')
 def verify(self,where,expected):
  for h in SITES:need(inv(where(h))==expected[h],'LIVE_SHA_MISMATCH '+h)
 def check(self):
  need(not self.journal(),'RELEASE_ALREADY_STARTED')
  need(all(not x.exists() for h in SITES for x in (self.ready(h),self.prior(h),self.withdrawn(h))),'CONFLICTING_RELEASE_DIR')
  self.verify(self.live,self.base)
  self.archive_verify(self.archive(),self.new)
  return {'state':'PREFLIGHT_PASS','live':168,'changed':53,'live_writes':0}
 def backup(self):
  root=self.home/'.oleg-safe-backups'/'oleg-managed-daily'
  root.mkdir(parents=True,exist_ok=True,mode=0o700)
  name='v55-oleg-live-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.tar.gz'
  dest=root/name
  need(not dest.exists(),'BACKUP_COLLISION')
  with dest.open('xb') as file:
   with tarfile.open(fileobj=file,mode='w:gz') as tf:
    for h in SITES:
     for rel in sorted(self.base[h]):
      tf.add(self.live(h)/rel,arcname=str(pathlib.PurePosixPath(h)/'public_html'/rel),recursive=False)
  os.chmod(dest,0o600)
  self.archive_verify(dest,self.base)
  return {'path':str(dest),'sha256':digest(dest)}
 def backup_checked(self):
  j=self.journal()
  need('backup' in j and 'sha256' in j['backup'],'NO_BACKUP')
  f=pathlib.Path(j['backup']['path'])
  need(f.is_file() and f.resolve().is_relative_to((self.home/'.oleg-safe-backups'/'oleg-managed-daily').resolve()),'INVALID_BACKUP_PATH')
  need(digest(f)==j['backup']['sha256'],'BACKUP_SHA_INVALID')
  self.archive_verify(f,self.base)
 def prepare(self):
  self.check()
  b=self.backup()
  self.verify(self.live,self.base)
  unpack=self.ops/'unpacked'
  need(not unpack.exists(),'UNPACK_ALREADY_EXISTS')
  unpack.mkdir(mode=0o700)
  try:
   with tarfile.open(self.archive(),'r:gz') as tf:
    for item in tf.getmembers():
     p=pathlib.PurePosixPath(item.name)
     need(item.isfile() and not p.is_absolute() and '..' not in p.parts,'INVALID_ENTRY')
     target=unpack/item.name
     need(target.resolve().is_relative_to(unpack.resolve()),'TARGET_OUTSIDE_STAGING')
     target.parent.mkdir(parents=True,exist_ok=True)
     with tf.extractfile(item) as inp, target.open('xb') as out:shutil.copyfileobj(inp,out)
     target.chmod(item.mode & 0o777)
   self.verify(lambda h:unpack/h/'public_html',self.new)
   for h in SITES:shutil.copytree(unpack/h/'public_html',self.ready(h))
   self.verify(self.ready,self.new)
  except:
   for h in SITES:
    if self.ready(h).exists():shutil.rmtree(self.ready(h))
   raise
  self.mark('READY',backup=b)
  return {'state':'READY','backup_sha256':b['sha256'],'ready_files':168,'live_writes':0}
 def httpverify(self):
  result={}
  for h in SITES:
   page='https://'+h+'/index.html?oleg-v55='+digest(self.live(h)/'index.html')[:10]
   req=urllib.request.Request(page,headers={'Cache-Control':'no-cache','User-Agent':'OlegV55ReleaseValidation/1.0'})
   with urllib.request.urlopen(req,timeout=15) as resp:
    need(resp.status==200,'HTTP_NON200 '+h)
    data=resp.read(1_000_000)
   need(hashlib.sha256(data).hexdigest()==self.new[h]['index.html'],'PUBLIC_HASH_MISMATCH '+h)
   result[h]='PUBLIC_HTTPS_SHA_PASS'
  return result
 def rollback_partial(self):
  self.backup_checked()
  restored=[]
  for h in reversed(SITES):
   prior=self.prior(h);live=self.live(h);withdrawn=self.withdrawn(h)
   if prior.exists():
    need(inv(prior)==self.base[h],'ROLLBACK_PRIOR_DRIFT '+h)
    if live.exists():
     need(inv(live)==self.new[h],'ROLLBACK_LIVE_DRIFT '+h)
     need(not withdrawn.exists(),'WITHDRAWN_CONFLICT '+h)
     live.rename(withdrawn)
    prior.rename(live)
    need(inv(live)==self.base[h],'ROLLBACK_RESTORED_MISMATCH '+h)
    restored.append(h)
   else:need(live.exists() and inv(live)==self.base[h],'ROLLBACK_UNEXPECTED_SITE '+h)
  self.mark('ROLLED_BACK',restored=restored)
  return {'state':'ROLLED_BACK','sites':restored}
 def deploy(self):
  need(self.journal().get('phase')=='READY','DEPLOY_NOT_READY')
  self.backup_checked();self.verify(self.live,self.base);self.verify(self.ready,self.new)
  need(all(not self.prior(h).exists() for h in SITES),'PRIOR_CONFLICT')
  self.mark('SWAPPING')
  try:
   for h in SITES:
    self.live(h).rename(self.prior(h))
    self.ready(h).rename(self.live(h))
    self.mark('SWAPPED',last_site=h)
    if self.fail_after==h:raise Stop('TEST_FAILURE_AFTER_'+h)
   self.verify(self.live,self.new)
   result=self.httpverify()
   self.mark('LIVE_VERIFIED',http=result)
   return {'state':'LIVE_VERIFIED','http':result}
  except:
   self.rollback_partial()
   raise
 def recover(self):
  need(self.journal().get('phase') in ('SWAPPING','SWAPPED'),'RECOVERY_NOT_REQUIRED')
  return self.rollback_partial()
 def rollback(self):
  need(self.journal().get('phase')=='LIVE_VERIFIED','NOT_VERIFIED_FOR_ROLLBACK')
  self.verify(self.live,self.new)
  return self.rollback_partial()
def main():
 p=argparse.ArgumentParser()
 p.add_argument('mode',choices=['check','prepare','deploy','recover','rollback','status'])
 p.add_argument('--home',default='/home/c/cl664853')
 p.add_argument('--test-mode',action='store_true',help='Only for isolated mock test environments')
 a=p.parse_args()
 home=pathlib.Path(a.home)
 if a.test_mode:
  need(str(home)!='/' and str(home)!='/home/c/cl664853','INVALID_TEST_HOME')
 ops=home/'.oleg-seo-ops/v55-release-a'
 r=Release(home,ops,test_mode=a.test_mode)
 result=r.journal() if a.mode=='status' else getattr(r,a.mode)()
 print(json.dumps(result,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()