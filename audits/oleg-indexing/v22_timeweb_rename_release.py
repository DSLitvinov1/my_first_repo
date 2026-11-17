#!/usr/bin/env python3
"""V22: guarded full-directory rename publication on Timeweb ZFS.

Timeweb ZFS does not support RENAME_EXCHANGE (EINVAL), and nginx failed
when the document root itself was a symlink. Therefore use complete
physical directories with two fast renames per site (brief gap), a
durable journal, full SHA preflight and automatic complete rollback.
Never copy 43 files one-by-one into a live public_html.
"""
from __future__ import annotations
import argparse, fcntl, hashlib, json, os, pathlib, re, shutil, stat, sys, time, urllib.request

H=pathlib.Path('/home/c/cl664853')
R=H/'.oleg-seo-releases/v19-20261117-safe-seo'
SITES=('potrebpravo.ru','semya-yurist.ru')
BACKUP=H/'.oleg-safe-backups/oleg-v19-pre-migration-20261117T155152Z.tar.gz'
BACKUP_SHA='145807d75cd14ce40502afdf059d0600517d3aeb3b45000306b06eaf692f6af7'
VERSION='V22_FOURTY_THREE_SEO_FILES'
CANDIDATE_NAME='public_html.v22-seo-ready'
PRIOR_NAME='public_html.v22-seo-original'
MANIFEST_STATUS='OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT'

class Stop(RuntimeError):pass
def ensure(ok,msg):
    if not ok:raise Stop(msg)
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for buf in iter(lambda:f.read(131072),b''):h.update(buf)
    return h.hexdigest()
def safe_dir(path):
    ensure(path.is_dir() and not path.is_symlink(),'EXPECTED_REAL_DIR '+str(path))
def inv(where):
    safe_dir(where)
    a={}
    for root,dirs,files in os.walk(where,followlinks=False):
        for n in dirs:ensure(not (pathlib.Path(root)/n).is_symlink(),'UNEXPECTED_SYMLINK')
        for n in files:
            f=pathlib.Path(root)/n
            ensure(f.is_file() and not f.is_symlink() and stat.S_ISREG(f.stat().st_mode),'UNEXPECTED_FILE_TYPE')
            a[str(f.relative_to(where))]=sha(f)
    return a
def site_dir(site):return H/site
def live(site):return H/site/'public_html'
def new(site):return H/site/CANDIDATE_NAME
def old(site):return H/site/PRIOR_NAME
def v0(site):return R/'versions'/'v0'/site/'public_html'
def v1(site):return R/'versions'/'v1'/site/'public_html'
def journal():return R/'v22-physical-directory-state.json'
def read_journal():return json.loads(journal().read_text()) if journal().exists() else {}
def mark(phase,site='',detail=''):
    target=journal();tmp=target.with_name(target.name+'.new')
    ensure(not tmp.exists() and not tmp.is_symlink(),'JOURNAL_TEMP_EXISTS')
    entry={'release':VERSION,'phase':phase,'site':site,'detail':detail,'utc':int(time.time())}
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(entry,f,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,target)
        d=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if tmp.exists():tmp.unlink()
def expected():
    m=json.loads((R/'candidate-manifest.json').read_text())
    rows=m.get('manifest')
    ensure(m.get('status')==MANIFEST_STATUS and isinstance(rows,list) and len(rows)==43,'MANIFEST_WRONG')
    changed={}
    for e in rows:
        host=e.get('host');rel=e.get('path')
        ensure(host in SITES and isinstance(rel,str) and re.fullmatch(r'[A-Za-z0-9_./-]+',rel) and '..' not in rel.split('/'),'BAD_RELATIVE_PATH')
        key=host+'/'+rel
        ensure(key not in changed and e.get('changed') is True,'DUPLICATE_OR_UNCHANGED_ROW')
        a=e.get('original_sha256');b=e.get('proposed_sha256')
        ensure(all(isinstance(x,str) and re.fullmatch(r'[0-9a-f]{64}',x) for x in [a,b]),'INVALID_SHA_ROW')
        changed[key]=(a,b)
    ensure(sum(k.endswith('.html') for k in changed)==41,'WRONG_HTML_COUNT')
    before={};after={}
    for site in SITES:
        for rel,digest in inv(v0(site)).items():
            key=site+'/'+rel
            before[key]=digest
            updated=changed.get(key)
            if updated:ensure(updated[0]==digest,'BASELINE_HASH_DRIFT '+key)
            after[key]=updated[1] if updated else digest
    ensure(len(before)==168 and len(changed)==43 and set(changed).issubset(before),'SITE_INVENTORY_WRONG')
    for site in SITES:
        current=inv(v1(site))
        for rel,digest in current.items():
            ensure(after.get(site+'/'+rel)==digest,'STAGED_SOURCE_INVALID '+site+'/'+rel)
        ensure(len(current)==len([x for x in after if x.startswith(site+'/')]),'V1_HAS_EXTRA_OR_MISSING_FILES')
    return before,after
def by_site(target,site):
    return {k.split('/',1)[1]:v for k,v in target.items() if k.startswith(site+'/')}
def matches(path,ref,site):
    return path.is_dir() and not path.is_symlink() and inv(path)==by_site(ref,site)
def preflight():
    ensure(H.is_dir() and H.resolve()==H,'NOT_HOST_ACCOUNT')
    safe_dir(R)
    ensure(json.loads((R/'state.json').read_text()).get('phase')=='ORIGINAL_PHYSICAL_RESTORED','OLD_SYMLINK_MIGRATION_NOT_ROLLED_BACK')
    ensure((R/'current').is_symlink() and os.readlink(R/'current')=='versions/v0','V19_POINTER_UNKNOWN')
    ensure(BACKUP.is_file() and not BACKUP.is_symlink() and sha(BACKUP)==BACKUP_SHA,'BACKUP_NOT_VERIFIED')
    before,after=expected()
    for site in SITES:
        safe_dir(site_dir(site))
        ensure(matches(live(site),before,site),'LIVE_BASELINE_DRIFT '+site)
        ensure(not old(site).exists() and not old(site).is_symlink(),'OLD_RELEASE_ALREADY_PRESENT')
    return before,after
def prepare():
    ensure(not journal().exists(),'ALREADY_STARTED')
    before,after=preflight()
    for site in SITES:
        ensure(not new(site).exists() and not new(site).is_symlink(),'CANDIDATE_ALREADY_EXISTS')
    mark('PREPARING')
    for site in SITES:
        shutil.copytree(v1(site),new(site),symlinks=True)
        ensure(matches(new(site),after,site),'STAGED_COPY_FAILED '+site)
    mark('READY')
    return {'state':'READY','files':len(before),'SEO_files':43,'public_changes':0}
def layout(site,before,after):
    # Old, new, or interruption after moving the old docroot.
    p=live(site);n=new(site);q=old(site)
    if p.is_dir() and not p.is_symlink():
        if matches(p,before,site) and not q.exists():
            ensure(matches(n,after,site),'BAD_READY_CANDIDATE '+site)
            return 'OLD'
        if matches(p,after,site) and matches(q,before,site) and not n.exists():
            return 'NEW'
    if not p.exists() and matches(q,before,site) and matches(n,after,site):
        return 'GAP'
    raise Stop('UNRECOGNIZED_OR_CONCURRENT_MODIFICATION '+site)
def fsync_parent(p):
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def move(src,dest):
    ensure(src.is_dir() and not src.is_symlink(),'SOURCE_NOT_REAL_DIR')
    ensure(not dest.exists() and not dest.is_symlink(),'DEST_NOT_EMPTY')
    ensure(src.stat().st_dev==src.parent.stat().st_dev and src.stat().st_dev==dest.parent.stat().st_dev,'FILESYSTEM_MISMATCH')
    os.rename(src,dest)
    fsync_parent(src);fsync_parent(dest)
def web_sha(site,route):
    req=urllib.request.Request('https://'+site+route+'?v22_check='+str(time.time_ns()),headers={'Cache-Control':'no-cache','Pragma':'no-cache','User-Agent':'OlegV22-live-verify'})
    with urllib.request.urlopen(req,timeout=12) as r:
        ensure(r.status==200,'HTTP_NOT_200')
        content=r.read(500000)
    return hashlib.sha256(content).hexdigest()
def smoke(reference):
    total=0
    for site in SITES:
        for route,rel in (('/','index.html'),('/assets/legal-assistant-v4.js','assets/legal-assistant-v4.js'),('/robots.txt','robots.txt'),('/sitemap.xml','sitemap.xml')):
            want=reference[site+'/'+rel]
            failure=None
            for _ in range(15):
                try:
                    if web_sha(site,route)==want:failure=None;break
                    failure=Stop('HTTP_HASH_WRONG')
                except Exception as e:failure=e
                time.sleep(.9)
            if failure:raise Stop('PUBLIC_HTTP_SHA_FAILED '+site+route+' '+type(failure).__name__)
            total+=1
    return total
def recover(before,after):
    mark('ROLLING_BACK')
    for site in SITES:
        shape=layout(site,before,after)
        if shape=='NEW':
            # Move the new site aside, restore old physical root.
            move(live(site),new(site))
            move(old(site),live(site))
        elif shape=='GAP':
            move(old(site),live(site))
        ensure(layout(site,before,after)=='OLD','RESTORE_INCOMPLETE '+site)
    mark('ORIGINAL_RESTORED')
    try:
        n=smoke(before)
        mark('ORIGINAL_HTTP_VERIFIED')
        return {'state':'ROLLED_BACK_AND_WEB_VERIFIED','HTTP_SHA':n}
    except Exception as e:
        mark('ORIGINAL_RESTORED_BUT_HTTP_UNVERIFIED',detail=type(e).__name__)
        return {'state':'ROLLED_BACK_LOCAL_VERIFIED_HTTP_NOT_CONFIRMED'}
def apply():
    before,after=expected()
    ensure(read_journal().get('phase')=='READY','STAGE_NOT_READY')
    ensure(all(layout(s,before,after)=='OLD' for s in SITES),'EXTERNAL_CHANGES')
    ensure(BACKUP.is_file() and sha(BACKUP)==BACKUP_SHA,'BACKUP_SHA_MISMATCH')
    try:
        for site in SITES:
            mark('MOVING_ORIGINAL',site)
            move(live(site),old(site))
            mark('INSTALLING_NEW',site)
            move(new(site),live(site))
            ensure(matches(live(site),after,site),'POST_MOVE_SHA_FAILED '+site)
        mark('WAITING_FOR_PUBLIC_HTTP')
        n=smoke(after)
        mark('SEO_LIVE_VERIFIED')
        return {'state':'SEO_V15_LIVE_VERIFIED','sites':2,'SEO_files':43,'full_files':len(before),'HTTP_SHA':n,'backup_sha256':BACKUP_SHA}
    except BaseException:
        try:recover(before,after)
        except Exception as err:mark('URGENT_MANUAL_RECOVERY_REQUIRED',detail=type(err).__name__)
        raise
def verify():
    before,after=expected()
    mode={s:layout(s,before,after) for s in SITES}
    if list(mode.values())==['NEW','NEW'] and read_journal().get('phase')=='SEO_LIVE_VERIFIED':
        return {'state':'PRODUCTION_SEO_VERIFIED','HTTP_SHA':smoke(after),'full_files':len(after)}
    return {'state':'NOT_LIVE','mode':mode,'journal':read_journal().get('phase')}
def main():
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['preflight','prepare','apply','verify','rollback','state'])
    p.add_argument('--approved',action='store_true')
    a=p.parse_args()
    ensure(a.approved,'APPROVAL_REQUIRED')
    safe_dir(R)
    fd=os.open(R/'v22-release.lock',os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.action=='preflight':
            b,z=preflight();result={'state':'PREFLIGHT_OK','files':len(b),'seo_files':43,'production_writes':0}
        elif a.action=='prepare':result=prepare()
        elif a.action=='apply':result=apply()
        elif a.action=='verify':result=verify()
        elif a.action=='rollback':
            b,z=expected();result=recover(b,z)
        else:result=read_journal()
        print(json.dumps(result,ensure_ascii=False))
    finally:os.close(fd)
if __name__=='__main__':
    try:main()
    except BaseException as e:
        print('V22_STOP',type(e).__name__,str(e)[:240],file=sys.stderr)
        sys.exit(2)
