#!/usr/bin/env python3
"""V19 two-site Timeweb release using a single shared symlink and durable rollback.
Production-only with explicit --approved flag, immutable V0/V1 snapshots,
fully locked source SHA, full file-inventory validation and web readback.
Never invokes Bitrix, changes account mail, or deploys V17 collector.
"""
import argparse, fcntl, hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, time, urllib.request, urllib.error
from contextlib import contextmanager
H=pathlib.Path('/home/c/cl664853')
HOSTS=('potrebpravo.ru','semya-yurist.ru')
RELEASES=H/'.oleg-seo-releases'
IDENT='v19-20261117-safe-seo'
R=RELEASES/IDENT
SRC='OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT'

class Guard(Exception):pass
def require(b,msg):
    if not b:raise Guard(msg)
def digest(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda:f.read(131072),b''):h.update(chunk)
    return h.hexdigest()
def safe_file(p):
    require(not p.is_symlink() and p.is_file() and stat.S_ISREG(p.stat().st_mode),'UNSAFE_FILE '+str(p))
def root():
    require(H.is_dir() and H.resolve()==H,'WRONG_ACCOUNT')
    require(R.parent == RELEASES and R.name==IDENT,'WRONG_RELEASE_ROOT')
    return R
def json_atomic(path,obj):
    temp=path.with_name(path.name+'.tmp')
    require(not temp.exists() and not temp.is_symlink(),'UNEXPECTED_TMP_JOURNAL')
    fd=os.open(str(temp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(obj,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
        fd=os.open(str(path.parent),os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temp.exists():temp.unlink()
def state():
    p=R/'state.json'
    return json.loads(p.read_text()) if p.exists() else {}
def mark(phase,extra=None):
    s=state()
    s.update({'phase':phase,'at':int(time.time())})
    if extra:s.update(extra)
    json_atomic(R/'state.json',s)
def versions():
    return R/'versions'
def version(name,host=None):
    base=versions()/name
    return base/host/'public_html' if host else base
def legacy(host):
    return H/host/('public_html.original-'+IDENT)
def docroot(host):
    return H/host/'public_html'
def pointer():
    return R/'current'
def expected_link(host):
    return '../.oleg-seo-releases/'+IDENT+'/current/'+host+'/public_html'
def pointer_version():
    require(pointer().is_symlink(),'POINTER_MISSING')
    val=os.readlink(pointer())
    require(val in ('versions/v0','versions/v1'),'UNEXPECTED_POINTER')
    return val.split('/')[-1]
def write_pointer(name):
    require(name in ('v0','v1'),'UNKNOWN_VERSION')
    tmp=R/'.next-pointer'
    require(not tmp.exists() and not tmp.is_symlink(),'UNEXPECTED_POINTER_TEMP')
    os.symlink('versions/'+name,tmp)
    try:
        os.replace(tmp,pointer())
        fd=os.open(str(R),os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if tmp.is_symlink():tmp.unlink()
def hash_inventory(base):
    require(base.is_dir() and not base.is_symlink(),'INVALID_SNAPSHOT_ROOT')
    hashes={}
    for parent,dirs,files in os.walk(base,followlinks=False):
        for name in dirs:
            require(not (pathlib.Path(parent)/name).is_symlink(),'UNSAFE_SYMLINK_IN_SITE_TREE')
        for name in files:
            file=pathlib.Path(parent)/name
            safe_file(file)
            hashes[str(file.relative_to(base))]=digest(file)
    return hashes
def mdata():
    p=R/'candidate-manifest.json'
    safe_file(p)
    d=json.loads(p.read_text())
    rows=d.get('manifest')
    require(d.get('status')==SRC and isinstance(rows,list) and len(rows)==43,'BAD_MANIFEST')
    result={}
    for e in rows:
        host=e.get('host');rel=e.get('path')
        require(host in HOSTS and isinstance(rel,str) and re.fullmatch(r'[a-zA-Z0-9_./-]+',rel) and '..' not in pathlib.PurePosixPath(rel).parts,'UNSAFE_RELEASE_PATH')
        require(rel.endswith('.html') or rel=='assets/legal-assistant-v4.js','UNREVIEWED_RELEASE_PATH')
        k=host+'/'+rel
        require(k not in result and e.get('changed') is True,'DUPLICATE_OR_UNCHANGED_RELEASE')
        a=e.get('original_sha256');b=e.get('proposed_sha256')
        require(all(isinstance(x,str) and re.fullmatch(r'[0-9a-f]{64}',x) for x in (a,b)) and a!=b,'BAD_HASH')
        result[k]=(a,b)
    require(sum(k.endswith('.html') for k in result)==41,'NOT_41_HTML')
    return result
def candidate_check():
    result=mdata()
    for key,(_,new) in result.items():
        host,rel=key.split('/',1)
        p=R/'candidate'/host/'public_html'/rel
        safe_file(p)
        require(digest(p)==new,'CANDIDATE_HASH_BAD '+key)
    return result
def live_hashes():
    out={}
    for host in HOSTS:
        site=docroot(host)
        require(site.is_dir() and not site.is_symlink(),'LIVE_DOCROOT_NOT_PHYSICAL '+host)
        inventory=hash_inventory(site)
        for name,d in inventory.items():out[host+'/'+name]=d
    return out
def check_snapshots(reviewed):
    old={};new={}
    for host in HOSTS:
        for name,h in hash_inventory(version('v0',host)).items():old[host+'/'+name]=h
        for name,h in hash_inventory(version('v1',host)).items():new[host+'/'+name]=h
    require(len(old)>=43 and set(old)==set(new),'FILE_INVENTORY_CHANGED')
    for k,a in old.items():
        original,proposed=reviewed.get(k,(a,a))
        require(a==original and new[k]==proposed,'SHA_MISMATCH '+k)
    require(set(reviewed).issubset(old),'REVIEWED_FILES_MISSING')
    return len(old)
def check_live_equals_old():
    old={}
    for host in HOSTS:
        for name,h in hash_inventory(version('v0',host)).items():old[host+'/'+name]=h
    current=live_hashes()
    require(current==old,'FULL_LIVE_SOURCE_DRIFT')
def prepare():
    require(not R.exists(),'STAGE_ALREADY_EXISTS')
    for host in HOSTS:
        require(docroot(host).is_dir() and not docroot(host).is_symlink(),'NO_PHYSICAL_DOCROOT')
        require(not legacy(host).exists() and not legacy(host).is_symlink(),'OLD_LEGACY_EXISTS')
    RELEASES.mkdir(mode=0o700,exist_ok=True)
    R.mkdir(mode=0o700)
    (R/'versions').mkdir(mode=0o700)
    require((R/'candidate-manifest.json').is_file(),'MANIFEST_MISSING_IN_STAGE')
def assemble():
    require(state().get('phase')=='STAGING','NOT_READY_TO_ASSEMBLE')
    reviewed=candidate_check()
    for name in ('v0','v1'):
        require(not version(name).exists(),'VERSION_ALREADY_EXISTS')
    versions().mkdir(mode=0o700,exist_ok=True)
    version('v0').mkdir(mode=0o700)
    version('v1').mkdir(mode=0o700)
    for host in HOSTS:
        dest=version('v0',host)
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copytree(docroot(host),dest,symlinks=True)
        v1=version('v1',host)
        v1.parent.mkdir(parents=True,exist_ok=True)
        shutil.copytree(dest,v1,symlinks=True)
    for key in reviewed:
        host,rel=key.split('/',1)
        p=version('v1',host)/rel
        origin=version('v0',host)/rel
        safe_file(p);safe_file(origin)
        shutil.copyfile(R/'candidate'/host/'public_html'/rel,p)
        os.chmod(p, stat.S_IMODE(origin.stat().st_mode))
    files=check_snapshots(reviewed)
    check_live_equals_old()
    require(not pointer().exists() and not pointer().is_symlink(),'POINTER_EXISTS')
    os.symlink('versions/v0',pointer())
    mark('STAGED',{'snapshot_files':files,'reviewed':43})
    return {'status':'STAGED','full_snapshot_files':files,'reviewed_sha':43,'old_pointer':pointer_version()}
def http_read(host,rel,wanted,timeout=13):
    uri='https://'+host+rel+'?v19_release_check='+str(int(time.time()))
    req=urllib.request.Request(uri,headers={'Cache-Control':'no-cache','Pragma':'no-cache','User-Agent':'OlegSEOv19-Migration-Selftest'})
    error=None
    for i in range(3):
        try:
            with urllib.request.urlopen(req,timeout=timeout) as r:
                require(r.status==200,'WEB_HTTP_'+str(r.status)+' '+host+rel)
                data=r.read(500000)
            require(hashlib.sha256(data).hexdigest()==wanted,'WEB_SOURCE_SHA_BAD '+host+rel)
            return
        except Exception as e:
            error=e;time.sleep(.4)
    raise Guard('HTTP_READBACK_FAILED '+host+rel+' '+type(error).__name__)
def web_checks(version_name):
    for host in HOSTS:
        folder=version(version_name,host)
        for rel,path in (('/',folder/'index.html'),('/assets/legal-assistant-v4.js',folder/'assets/legal-assistant-v4.js'),
                         ('/robots.txt',folder/'robots.txt'),('/sitemap.xml',folder/'sitemap.xml')):
            safe_file(path)
            http_read(host,rel,digest(path))
    return 8
def check_docroot_links():
    for host in HOSTS:
        p=docroot(host)
        require(p.is_symlink() and os.readlink(p)==expected_link(host),'DOCROOT_NOT_CORRECT_LINK '+host)
        require(p.is_dir(),'DOCROOT_DANGLING '+host)
def restore_physical():
    # Only restore directories we ourselves renamed; refuse overwriting foreign changes.
    for host in HOSTS:
        p=docroot(host);old=legacy(host)
        if p.is_symlink():
            require(os.readlink(p)==expected_link(host),'FOREIGN_DOCROOT_LINK '+host)
        else:
            require(not p.exists() or p.is_dir(),'FOREIGN_DOCROOT_KIND')
            if p.is_dir():
                require(not old.exists(),'FOREIGN_DOCROOT_REPLACEMENT '+host)
        if old.exists():require(old.is_dir() and not old.is_symlink(),'LEGACY_BAD '+host)
    if pointer().is_symlink() and pointer_version()=='v1':write_pointer('v0')
    for host in HOSTS:
        p=docroot(host);old=legacy(host)
        if old.is_dir():
            if p.is_symlink():p.unlink()
            require(not p.exists(),'DOCROOT_NOT_CLEAR '+host)
            os.rename(old,p)
    mark('ORIGINAL_PHYSICAL_RESTORED')
def migrate():
    require(state().get('phase')=='STAGED','BAD_MIGRATION_PHASE')
    reviewed=candidate_check()
    check_snapshots(reviewed)
    check_live_equals_old()
    require(pointer_version()=='v0','BAD_MIGRATION_POINTER')
    mark('MIGRATING')
    try:
        for host in HOSTS:
            os.rename(docroot(host),legacy(host))
            os.symlink(expected_link(host),docroot(host))
            require(docroot(host).is_dir(),'MIGRATED_SYMLINK_DANGLING '+host)
        check_docroot_links()
        n=web_checks('v0')
        mark('MIGRATED_OLD_VERIFIED',{'old_web_checks':n})
        return {'status':'MIGRATED_OLD_VERIFIED','checks':n}
    except BaseException:
        try:restore_physical()
        except Exception:mark('URGENT_MANUAL_ROLLBACK_REQUIRED')
        raise
def switch():
    require(state().get('phase')=='MIGRATED_OLD_VERIFIED','BAD_SWITCH_PHASE')
    check_docroot_links()
    reviewed=candidate_check()
    check_snapshots(reviewed)
    require(pointer_version()=='v0','BAD_SWITCH_POINTER')
    web_checks('v0')
    mark('SWITCH_PREPARED')
    try:
        write_pointer('v1')
        require(pointer_version()=='v1','POINTER_NOT_V1')
        n=web_checks('v1')
        mark('SEO_LIVE_VERIFIED',{'new_web_checks':n})
        return {'status':'SEO_LIVE_VERIFIED','checks':n,'reviewed':43}
    except BaseException:
        try:
            write_pointer('v0')
            web_checks('v0')
            mark('SWITCH_ROLLED_BACK_TO_V0')
        except Exception:mark('URGENT_MANUAL_RECOVERY_REQUIRED')
        raise
def rollback():
    s=state();require(s.get('phase') not in ('STAGING',None),'NO_MIGRATION_TO_ROLLBACK')
    if pointer().is_symlink() and pointer_version()=='v1':write_pointer('v0')
    restore_physical()
    return {'status':'ORIGINAL_PHYSICAL_RESTORED','sites':len(HOSTS)}
def verify():
    s=state();p=s.get('phase')
    if p=='SEO_LIVE_VERIFIED':
        check_docroot_links()
        require(pointer_version()=='v1','NOT_V1')
        n=web_checks('v1')
        return {'status':'PRODUCTION_SEO_VERIFIED','http_sha_checks':n}
    if p=='MIGRATED_OLD_VERIFIED':
        check_docroot_links()
        require(pointer_version()=='v0','NOT_V0')
        n=web_checks('v0')
        return {'status':'OLD_TOPOLOGY_VERIFIED','http_sha_checks':n}
    return {'status':p,'not_live':True}
@contextmanager
def locked():
    R.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(str(R/'lock'),os.O_RDWR|os.O_CREAT,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)
def main():
    args=argparse.ArgumentParser()
    args.add_argument('action',choices=('init','assemble','migrate','switch','rollback','verify','state'))
    args.add_argument('--approved',action='store_true')
    a=args.parse_args()
    require(a.approved,'APPROVAL_FLAG_MISSING')
    root()
    if a.action=='init':
        require(not R.exists(),'STAGE_ALREADY_EXISTS')
        RELEASES.mkdir(mode=0o700,exist_ok=True)
        R.mkdir(mode=0o700)
        (R/'candidate').mkdir(mode=0o700)
        mark('STAGING')
        print(json.dumps({'status':'STAGING_READY','id':IDENT,'version':'V19'}))
        return
    require(R.is_dir() and not R.is_symlink(),'RELEASE_DIR_MISSING')
    with locked():
        result={'status':state().get('phase')}
        if a.action=='assemble':result=assemble()
        elif a.action=='migrate':result=migrate()
        elif a.action=='switch':result=switch()
        elif a.action=='rollback':result=rollback()
        elif a.action=='verify':result=verify()
        elif a.action=='state':result=state()
        print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except BaseException as e:
        print('V19_SAFE_RELEASE_STOP',type(e).__name__,str(e)[:320],file=sys.stderr)
        sys.exit(2)
