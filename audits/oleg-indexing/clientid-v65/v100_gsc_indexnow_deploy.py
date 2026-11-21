#!/usr/bin/env python3
"""Oleg Legal GSC ownership + IndexNow key installation. Requires exact V68 live hashes.
Usage: --consumer-gsc ... --family-gsc ... --consumer-indexnow ... --family-indexnow ... [--apply]
DRY RUN is the default; no data other than GSC meta and public IndexNow keys is changed.
"""
from __future__ import annotations
import argparse,datetime,getpass,hashlib,json,os,re,stat,sys
from pathlib import Path

ROOT=Path('/home/c/cl664853')
ORIGINAL_HASHES={
 'potrebpravo.ru':'0f88baf242dc9060603cbe3d5c1e6f6f0da242f2debcc1da8e0302ba5fd2d74d',
 'semya-yurist.ru':'1590cfdcd9bbf56c52c1cbf7ef289ce6a974984c79364041ccebb885357f76b1'
}
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def need(ok:bool,msg:str):
 if not ok:raise RuntimeError(msg)
def atomic(path:Path,data:bytes,mode:int):
 temp=path.parent/('.oleg-indexing-verification-'+path.name)
 need(not temp.exists() and not temp.is_symlink(),'COLLISION_TEMP')
 fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:
  f.write(data);f.flush();os.fsync(f.fileno())
 os.chmod(temp,mode);os.replace(temp,path)
def main():
 p=argparse.ArgumentParser()
 p.add_argument('--consumer-gsc',required=True)
 p.add_argument('--family-gsc',required=True)
 p.add_argument('--consumer-indexnow',required=True)
 p.add_argument('--family-indexnow',required=True)
 p.add_argument('--apply',action='store_true')
 a=p.parse_args()
 need(getpass.getuser()=='cl664853','WRONG_HOSTING_ACCOUNT')
 assert ROOT.is_dir() and not ROOT.is_symlink()
 records={}
 for host,token,key in [('potrebpravo.ru',a.consumer_gsc,a.consumer_indexnow),
                         ('semya-yurist.ru',a.family_gsc,a.family_indexnow)]:
  need(bool(re.fullmatch(r'[A-Za-z0-9_-]{24,80}',token)),'INVALID_GSC_TOKEN')
  need(bool(re.fullmatch(r'[a-f0-9]{32}',key)),'INVALID_INDEXNOW_KEY')
  folder=ROOT/host/'public_html'
  need(folder.is_dir() and not folder.is_symlink(),'UNEXPECTED_ROOT_'+host)
  page=folder/'index.html';old=page.read_bytes()
  need(sha(old)==ORIGINAL_HASHES[host],'LIVE_HTML_SOURCE_DRIFT_'+host)
  meta=f'<meta name="google-site-verification" content="{token}" />'.encode('ascii')
  need(meta not in old,'TAG_ALREADY_APPLIED_'+host)
  need(old.count(b'</head>')==1,'UNEXPECTED_HEAD_'+host)
  patched=old.replace(b'</head>',meta+b'\n</head>',1)
  need(len(patched)-len(old)<160,'SUSPECT_PATCH')
  keyfile=folder/(key+'.txt')
  need(not keyfile.exists() and not keyfile.is_symlink(),'KEY_COLLISION_'+host)
  records[host]={'page':page,'old':old,'new':patched,'mode':stat.S_IMODE(page.stat().st_mode),
                 'keyfile':keyfile,'keycontent':key.encode('ascii')}
 if not a.apply:
  print(json.dumps({'status':'DRY_RUN_OK_NO_WRITES','targets':list(records),
                    'indexnow_new_files':2,'homepage_meta_patches':2},ensure_ascii=False))
  return
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 stage=ROOT/'.oleg-seo-ops'/'v100-gsc-indexnow'/stamp
 need(not stage.exists(),'STAGE_EXISTS')
 stage.mkdir(mode=0o700,parents=True)
 backups={}
 for host,r in records.items():
  backup=stage/(host+'-index.before.html')
  fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(r['old']);f.flush();os.fsync(f.fileno())
  backups[host]=str(backup)
 done=[]
 try:
  for host,r in records.items():
   # Write a new public proof key, then switch homepage to exact Google verification meta.
   fd=os.open(r['keyfile'],os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644)
   with os.fdopen(fd,'wb') as f:f.write(r['keycontent']);f.flush();os.fsync(f.fileno())
   done.append(('key',host))
   atomic(r['page'],r['new'],r['mode']);done.append(('html',host))
   need(sha(r['page'].read_bytes())==sha(r['new']),'VERIFY_NEW_HASH_'+host)
  report={'status':'LIVE_WRITTEN_NEEDS_GOOGLE_INDEXNOW_CONFIRMATION','time_utc':stamp,
          'backup_paths':backups,
          'files':[{ 'host':host,'homepage_sha_before':sha(r['old']),'homepage_sha_after':sha(r['new']),
                     'indexnow_file':r['keyfile'].name} for host,r in records.items()]}
  manifest=stage/'manifest.json';fd=os.open(manifest,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'w') as f:json.dump(report,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
  print(json.dumps({'status':report['status'],'backups':str(stage),'changed_homepages':2,'created_indexnow_keys':2},ensure_ascii=False))
 except BaseException:
  for kind,host in reversed(done):
   r=records[host]
   if kind=='html' and r['page'].exists() and sha(r['page'].read_bytes())==sha(r['new']):
    atomic(r['page'],r['old'],r['mode'])
   if kind=='key' and r['keyfile'].exists() and r['keyfile'].read_bytes()==r['keycontent']:
    r['keyfile'].unlink()
  raise
if __name__=='__main__':
 try:main()
 except Exception as e:print('RELEASE_REFUSED:'+str(e)[:160],file=sys.stderr);sys.exit(2)
