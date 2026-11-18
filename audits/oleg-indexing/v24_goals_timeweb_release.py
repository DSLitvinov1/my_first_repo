#!/usr/bin/env python3
"""Guarded V24 full-directory Timeweb release; no per-file production writes."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, shutil, stat, tarfile, urllib.request

SITES=('potrebpravo.ru','semya-yurist.ru')
STAGE='public_html.v24-goals-ready'
PRIOR='public_html.v24-goals-prior'
WITHDRAWN='public_html.v24-goals-withdrawn'
VERSION='v24-goals-20261118'
STATUS='V24_47_FILE_GOALS_CANDIDATE_VERIFIED'

class Stop(RuntimeError): pass
def require(ok,msg):
    if not ok: raise Stop(msg)
def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(65536),b''): h.update(block)
    return h.hexdigest()
def inventory(folder):
    require(folder.is_dir() and not folder.is_symlink(),'UNSAFE_DIRECTORY '+str(folder))
    rows={}
    for root, dirs, files in os.walk(folder,followlinks=False):
        for name in dirs:
            p=pathlib.Path(root)/name
            require(not p.is_symlink(),'SYMLINK_DIRECTORY '+str(p))
        for name in files:
            p=pathlib.Path(root)/name
            require(p.is_file() and not p.is_symlink() and stat.S_ISREG(p.stat().st_mode),'UNSAFE_FILE '+str(p))
            rows[str(p.relative_to(folder))]=sha_file(p)
    return rows

class Release:
    def __init__(self, home:pathlib.Path, folder:pathlib.Path, failure_site=None):
        self.H=pathlib.Path(home);self.R=pathlib.Path(folder);self.failure_site=failure_site
        require(self.H.is_dir() and self.H.resolve()==self.H,'UNEXPECTED_HOST_HOME')
        require(self.R.is_dir() and self.R.resolve()==self.R and not self.R.is_symlink(),'UNSAFE_RELEASE_ROOT')
        self.manifest=json.loads((self.R/'v24-goals-manifest.json').read_text(encoding='utf8'))
        m=self.manifest
        require(m.get('status')==STATUS and m.get('version')==VERSION,'INVALID_RELEASE_MANIFEST')
        require(m.get('sites')==list(SITES) and m.get('count')==168,'INVALID_RELEASE_SITE_COUNT')
        self.base=m['baseline_sha256'];self.new=m['candidate_sha256']
        allpaths=set()
        for site,count in zip(SITES,(87,81)):
            require(site in self.base and site in self.new,'SITE_NOT_IN_MANIFEST')
            require(set(self.base[site])==set(self.new[site]) and len(self.base[site])==count,'SITE_FILE_COUNT_DRIFT')
            for rel,oldsha in self.base[site].items():
                require(isinstance(rel,str) and re.fullmatch(r'[A-Za-z0-9_./-]+',rel) and '..' not in pathlib.PurePosixPath(rel).parts and not rel.startswith('/'),'BAD_MANIFEST_PATH')
                newsha=self.new[site][rel]
                require(all(isinstance(s,str) and re.fullmatch(r'[a-f0-9]{64}',s) for s in (oldsha,newsha)),'BAD_SHA_IN_MANIFEST')
                allpaths.add(site+'/'+rel)
        changed={site+'/'+rel for site in SITES for rel in self.base[site] if self.base[site][rel]!=self.new[site][rel]}
        require(len(changed)==47 and set(m['changed'])==changed,'UNEXPECTED_CHANGE_SET')
        require(sum(k.startswith('potrebpravo.ru/') for k in changed)==26,'CONSUMER_CHANGE_COUNT')
        require(sum(k.startswith('semya-yurist.ru/') for k in changed)==21,'FAMILY_CHANGE_COUNT')
        for field in ('archive_sha256','backup_sha256'): require(re.fullmatch('[0-9a-f]{64}',m.get(field,'')) is not None,'INVALID_BUNDLE_SHA')
        require(m.get('archive_filename')=='v24-goals-candidate.tar.gz','WRONG_CANDIDATE_ARCHIVE')
        require(re.fullmatch(r'oleg-sites-auto-20261118T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz',m.get('backup_filename','')) is not None,'INVALID_BACKUP_NAME')

    def live(self,site):return self.H/site/'public_html'
    def ready(self,site):return self.H/site/STAGE
    def prior(self,site):return self.H/site/PRIOR
    def withdrawn(self,site):return self.H/site/WITHDRAWN
    def journal(self):
        p=self.R/'release-state.json'
        return json.loads(p.read_text(encoding='utf8')) if p.exists() else {}
    def mark(self,phase,info=''):
        p=self.R/'release-state.json';tmp=self.R/'release-state.json.tmp'
        require(not tmp.exists(),'STATE_TEMP_EXISTS')
        payload={'version':VERSION,'phase':phase,'info':info}
        fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump(payload,f,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
        fd=os.open(str(self.R),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def backup_checked(self):
        m=self.manifest
        p=self.H/'.oleg-safe-backups'/'oleg-managed-daily'/m['backup_filename']
        require(p.is_file() and not p.is_symlink() and sha_file(p)==m['backup_sha256'],'BACKUP_NOT_VALID')
        return p
    def bundle_checked(self):
        p=self.R/'v24-goals-candidate.tar.gz'
        require(p.is_file() and not p.is_symlink() and sha_file(p)==self.manifest['archive_sha256'],'ARCHIVE_SHA_INVALID')
        return p
    def verify(self,dirfun,expected):
        for site in SITES:
            require(inventory(dirfun(site))==expected[site],'INVENTORY_MISMATCH '+str(dirfun(site)))
    def check(self):
        require(not self.journal(),'RELEASE_ALREADY_INITIALIZED')
        self.backup_checked();self.bundle_checked()
        self.verify(self.live,self.base)
        for site in SITES:
            require(not self.ready(site).exists() and not self.prior(site).exists() and not self.withdrawn(site).exists(),'CONFLICTING_RELEASE_DIRECTORY '+site)
        return {'state':'READY_TO_PREPARE','files':168,'changes':47,'live_writes':0}
    def prepare(self):
        result=self.check()
        unpack=self.R/'unpacked'
        require(not unpack.exists(),'STAGING_ALREADY_EXISTS')
        unpack.mkdir(mode=0o700)
        with tarfile.open(self.bundle_checked(),'r:gz') as tf:
            ms=tf.getmembers()
            for m in ms:
                pp=pathlib.PurePosixPath(m.name)
                require(len(pp.parts)>=2 and pp.parts[0] in SITES and pp.parts[1]=='public_html' and not pp.is_absolute() and '..' not in pp.parts,'UNSAFE_TAR_PATH')
                require(m.isfile() or m.isdir(),'UNSAFE_TAR_MEMBER')
            require(sum(m.isfile() for m in ms)==168,'UNEXPECTED_TAR_CONTENT')
            for member in ms:
                dest=unpack/member.name
                require(dest.resolve().is_relative_to(unpack.resolve()),'TAR_PATH_ESCAPE')
                if member.isdir():
                    dest.mkdir(mode=0o700,parents=True,exist_ok=True)
                    continue
                dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with tf.extractfile(member) as source, dest.open('xb') as target:
                    shutil.copyfileobj(source,target)
                os.chmod(dest,member.mode & 0o777)
        self.verify(lambda s:unpack/s/'public_html',self.new)
        for site in SITES:
            shutil.copytree(unpack/site/'public_html',self.ready(site),symlinks=False)
        self.verify(self.ready,self.new)
        self.mark('READY')
        return {'state':'READY','files':168,'staged':47,'live_writes':0}
    def webcheck(self):
        result={}
        for site in SITES:
            p=self.new[site]
            version=sha_file(self.live(site)/'assets/oleg-analytics-v1.js')[:8]
            for name in ('index.html','assets/oleg-analytics-v1.js'):
                uri='https://'+site+'/'+name+'?oleg-v24-validation='+version
                request=urllib.request.Request(uri,headers={'User-Agent':'OlegLegalV24SafeReleaseCheck/1.0','Cache-Control':'no-cache'})
                with urllib.request.urlopen(request,timeout=13) as response:
                    require(response.status==200,'NON200 '+site+'/'+name)
                    payload=response.read(1000000)
                require(sha_bytes(payload)==p[name],'PUBLIC_HTTP_HASH_MISMATCH '+site+'/'+name)
            result[site]={'http':'PASS','assets_version':version}
        return result
    def rollback_swapping(self):
        restored=[]
        for site in reversed(SITES):
            prior=self.prior(site);live=self.live(site);withdrawn=self.withdrawn(site)
            if not prior.exists():continue
            require(inventory(prior)==self.base[site],'REFUSE_ROLLBACK_UNEXPECTED_PRIOR '+site)
            if live.exists():
                require(inventory(live)==self.new[site],'REFUSE_ROLLBACK_FOREIGN_LIVE '+site)
                require(not withdrawn.exists(),'REFUSE_ROLLBACK_WITHDRAWN_EXISTS '+site)
                live.rename(withdrawn)
            prior.rename(live)
            require(inventory(live)==self.base[site],'ROLLBACK_HASH_MISMATCH '+site)
            restored.append(site)
        self.mark('ROLLED_BACK',','.join(restored))
        return {'state':'ROLLED_BACK','sites':restored}
    def release(self):
        require(self.journal().get('phase')=='READY','NOT_STAGED_FOR_RELEASE')
        self.backup_checked();self.verify(self.live,self.base);self.verify(self.ready,self.new)
        for site in SITES:require(not self.prior(site).exists(),'PRIOR_ALREADY_EXISTS')
        self.mark('SWAPPING')
        try:
            for site in SITES:
                self.live(site).rename(self.prior(site))
                self.ready(site).rename(self.live(site))
                self.mark('SWAPPED',site)
                if self.failure_site==site:raise Stop('SIMULATED_FAILURE_AFTER_'+site)
            self.verify(self.live,self.new)
            web=self.webcheck()
            self.mark('LIVE_VERIFIED','2_SITE_HTTP_SHA_PASS')
            return {'state':'LIVE_VERIFIED','public':web}
        except Exception:
            self.rollback_swapping()
            raise
    def recover(self):
        require(self.journal().get('phase') in ('SWAPPING','SWAPPED'),'NOT_AN_INTERRUPTED_RELEASE')
        return self.rollback_swapping()
    def rollback(self):
        require(self.journal().get('phase')=='LIVE_VERIFIED','NO_VERIFIED_RELEASE_TO_ROLLBACK')
        self.verify(self.live,self.new)
        self.verify(self.prior,self.base)
        return self.rollback_swapping()

def main():
    a=argparse.ArgumentParser()
    a.add_argument('mode',choices=('check','prepare','release','recover','rollback'))
    args=a.parse_args()
    root=pathlib.Path('/home/c/cl664853')
    release=root/'.oleg-seo-ops/v24-goals'
    r=Release(root,release)
    result=getattr(r,args.mode)()
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()