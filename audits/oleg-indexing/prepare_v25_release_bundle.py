from pathlib import Path
import json,hashlib,tarfile,os
ROOT=Path('/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118')
PRIV=ROOT/'.private-v25-offline'
SITES=('potrebpravo.ru','semya-yurist.ru')
prior=Path('/home/cloudagent/projects/oleg-seo-v24-analytics-intake-20261118/.private-v24-offline/timeweb-live-inventory.json')
live=json.loads(prior.read_text())['sites']
current={};changed=[]
for host in SITES:
 src=PRIV/'snapshot'/host/'public_html'
 current[host]={str(p.relative_to(src)):hashlib.sha256(p.read_bytes()).hexdigest() for p in src.rglob('*') if p.is_file()}
 assert set(current[host])==set(live[host])
 changed += [host+'/'+rel for rel in live[host] if current[host][rel]!=live[host][rel]]
assert len(changed)==49,len(changed)
bundle=PRIV/'v25-utm-candidate.tar.gz'
assert not bundle.exists()
with tarfile.open(bundle,'w:gz') as tar:
 for host in SITES:tar.add(PRIV/'snapshot'/host/'public_html',arcname=host+'/public_html',recursive=True)
with tarfile.open(bundle,'r:gz') as tar:assert len([p for p in tar.getmembers() if p.isfile()])==168
old=json.loads(Path('/home/cloudagent/projects/oleg-seo-v24-analytics-intake-20261118/.private-v24-offline/v24-goals-manifest.json').read_text())
m={'status':'V25_49_FILE_UTM_AND_GOALS_CANDIDATE_VERIFIED','version':'v25-utm-20261118','sites':list(SITES),'baseline_sha256':live,'candidate_sha256':current,'changed':changed,'count':168,'archive_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),'archive_filename':bundle.name,'backup_filename':old['backup_filename'],'backup_sha256':old['backup_sha256']}
target=PRIV/'v25-utm-manifest.json';assert not target.exists()
target.write_text(json.dumps(m,ensure_ascii=False,indent=2))
bundle.chmod(0o600);target.chmod(0o600)
print(json.dumps({'files':168,'changed':len(changed),'per_site':{k:sum(x.startswith(k+'/') for x in changed) for k in SITES},'archive_bytes':bundle.stat().st_size,'backup_existing':m['backup_filename']}))