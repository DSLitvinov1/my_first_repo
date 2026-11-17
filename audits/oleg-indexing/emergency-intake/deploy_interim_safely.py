#!/usr/bin/env python3
"""V18 strictly limited four-file fallback, journalled per-file swaps and rollback.

This is NOT the 43-file SEO deployment. Two domains cannot switch as one
filesystem pointer; short mixed-version exposure remains during the four swaps.
"""
import argparse, hashlib, json, os, pathlib, shutil, stat, sys, tempfile
try: import fcntl
except ImportError: fcntl=None

SITES={'potrebpravo.ru','semya-yurist.ru'}
PATHS={'index.html','assets/legal-assistant-v4.js'}
EXPECTED_OLD={
'potrebpravo.ru/index.html':'7138aad960cb41c169b3417046f2c9d673110ae39e82be5033f48eb3eb5b0704',
'semya-yurist.ru/index.html':'f7b0b6a897aefe7bf09b06bc550691709988a4cfee1641e7caec48f47a805eaa',
'potrebpravo.ru/assets/legal-assistant-v4.js':'3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a',
'semya-yurist.ru/assets/legal-assistant-v4.js':'3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a'
}
def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(65536),b''): h.update(b)
    return h.hexdigest()
def safe_regular(path):
    if path.is_symlink() or not path.is_file():raise ValueError('Unexpected symlink or missing release file')
def atomic_write(file, data):
    temp=file.with_name('.'+file.name+'.v18-tmp-'+os.urandom(4).hex())
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(temp,file)
        fd_dir=os.open(file.parent,os.O_RDONLY)
        try:os.fsync(fd_dir)
        finally:os.close(fd_dir)
    finally:
        if temp.exists():temp.unlink()
def checkpoint(stage,state,done):
    payload=json.dumps({'state':state,'done':done},sort_keys=True).encode()+b'\n'
    atomic_write(stage/'journal.json',payload)
def preflight(root,stage,manifest):
    if stage.is_symlink() or not stage.is_dir():raise ValueError('Stage missing')
    rows=manifest.get('files')
    if manifest.get('state')!='INTERIM_AVAILABILITY_ONLY_NOT_DEPLOYED' or not isinstance(rows,list) or len(rows)!=4:
        raise ValueError('Unexpected manifest state/count')
    by_path={r['relative_file']:r for r in rows}
    if set(by_path)!=set(EXPECTED_OLD):raise ValueError('Unexpected path list')
    for rel,old in EXPECTED_OLD.items():
        row=by_path[rel]
        if row['previous_sha256']!=old:raise ValueError('Unknown baseline')
        site,part=rel.split('/',1)
        if site not in SITES or part not in PATHS:raise ValueError('Unexpected destination')
        live=root/site/'public_html'/part
        source=stage/'new'/rel
        safe_regular(live);safe_regular(source)
        if digest(source)!=row['new_sha256']:raise ValueError('Stage SHA invalid')
        if digest(live)!=old:raise ValueError('PRODUCTION_SOURCE_DRIFT_STOP '+rel)
    return by_path
def backup_four(root,stage,items):
    for rel,row in items.items():
        backup=stage/'backup'/rel
        backup.parent.mkdir(parents=True,exist_ok=True)
        if backup.exists(): raise ValueError('Backup already present')
        shutil.copyfile(root/rel.split('/',1)[0]/'public_html'/rel.split('/',1)[1],backup)
        os.chmod(backup,0o600)
        if digest(backup)!=row['previous_sha256']:raise ValueError('Backup checksum mismatch')
    checkpoint(stage,'prepared',[])
def rollback_all(root,stage,items):
    for rel,row in items.items():
        site,part=rel.split('/',1)
        live=root/site/'public_html'/part
        backup=stage/'backup'/rel
        safe_regular(backup);safe_regular(live)
        if digest(backup)!=row['previous_sha256']:raise ValueError('Backup altered')
        if digest(live) not in (row['previous_sha256'],row['new_sha256']):
            raise ValueError('Concurrent external modification; refusing rollback')
    for rel,row in items.items():
        site,part=rel.split('/',1)
        live=root/site/'public_html'/part
        backup=stage/'backup'/rel
        if digest(live)!=row['previous_sha256']:
            atomic_write(live,backup.read_bytes())
            if digest(live)!=row['previous_sha256']:raise ValueError('Rollback SHA mismatch')
    checkpoint(stage,'rolled_back',[])
def main():
    a=argparse.ArgumentParser()
    a.add_argument('--root',required=True)
    a.add_argument('--stage',required=True)
    a.add_argument('--action',choices=['preflight','apply','finalize','rollback','recover'],required=True)
    a.add_argument('--production-ok',action='store_true')
    opts=a.parse_args()
    root=pathlib.Path(opts.root).resolve();stage=pathlib.Path(opts.stage).resolve()
    if opts.production_ok:
        if root!=pathlib.Path.home().resolve():raise ValueError('Production home mismatch')
        if not stage.is_relative_to(root/'.oleg-safe-backups'):raise ValueError('Stage not in private backups')
    else:
        if not str(root).startswith('/tmp/oleg-v18-release-test.'):raise ValueError('Sandbox path required')
        if not (root/'.v18-test-marker').is_file():raise ValueError('Sandbox marker required')
    if stage.is_relative_to(root/'potrebpravo.ru') or stage.is_relative_to(root/'semya-yurist.ru'):
        raise ValueError('Stage must not be inside public site')
    manifest=json.loads((stage/'manifest.json').read_text())
    # Lock must cover all operations; no cross-release task races.
    lock=stage/'.v18-lock'
    lockfd=open(lock,'a+')
    if fcntl: fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises when locked
    if opts.action in ('preflight','apply'):
        items=preflight(root,stage,manifest)
    else:
        items={x['relative_file']:x for x in manifest['files']}
    state_file=stage/'journal.json'
    state=json.loads(state_file.read_text())['state'] if state_file.exists() else None
    if opts.action=='preflight':
        print(json.dumps({'state':'PRE_FLIGHT_PASS','source_lock':len(items),'domain_count':2,'writes':0}))
        return
    if opts.action=='apply':
        if state is not None:raise ValueError('Stage was already used')
        backup_four(root,stage,items)
        done=[]
        try:
            checkpoint(stage,'applying',done)
            for rel,row in sorted(items.items()):
                site,part=rel.split('/',1)
                live=root/site/'public_html'/part
                new=stage/'new'/rel
                if digest(live)!=row['previous_sha256']:raise ValueError('Concurrent write; abort')
                atomic_write(live,new.read_bytes())
                if digest(live)!=row['new_sha256']:raise ValueError('Post-apply SHA mismatch')
                done.append(rel)
                checkpoint(stage,'applying',done)
            checkpoint(stage,'awaiting_external_smoke',done)
            print(json.dumps({'state':'APPLIED_AWAITING_EXTERNAL_SMOKE','changed':len(done),'domain_count':2}))
            return
        except Exception:
            rollback_all(root,stage,items)
            raise
    if opts.action=='rollback':
        if state not in ('applying','awaiting_external_smoke','live_verified'):
            raise ValueError('Nothing to roll back')
        rollback_all(root,stage,items)
        print(json.dumps({'state':'ROLLED_BACK','changed':4}))
        return
    if opts.action=='recover':
        if state=='applying':
            rollback_all(root,stage,items)
            print(json.dumps({'state':'INTERRUPTED_APPLY_RECOVERED'}))
        else:print(json.dumps({'state':'NO_RECOVERY_NEEDED','journal':state}))
        return
    if opts.action=='finalize':
        if state!='awaiting_external_smoke':raise ValueError('Smoke gate invalid')
        for rel,row in items.items():
            site,part=rel.split('/',1)
            if digest(root/site/'public_html'/part)!=row['new_sha256']:raise ValueError('Unexpected live SHA; not finalized')
        checkpoint(stage,'live_verified',list(items))
        print(json.dumps({'state':'LIVE_SHA_VERIFIED','files':4,'domains':2,'seo_changes':0,'customer_data_changes':0}))
if __name__=='__main__':
    try:main()
    except Exception as e:print('V18_SAFE_RELEASE_BLOCKED:',type(e).__name__,str(e),file=sys.stderr);sys.exit(2)
