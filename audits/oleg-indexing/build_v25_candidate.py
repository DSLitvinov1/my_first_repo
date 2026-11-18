from pathlib import Path
import tarfile, subprocess,hashlib,json,re,shutil
ROOT=Path('/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118')
PRIVATE=ROOT/'.private-v25-offline'
SNAP=PRIVATE/'snapshot'
BASE=Path('/home/cloudagent/projects/oleg-seo-v23-analytics-watch-20261117/.private-v23-timeweb/approved-live-site-snapshot.tar.gz')
INV=Path('/home/cloudagent/projects/oleg-seo-v24-analytics-intake-20261118/.private-v24-offline/timeweb-live-inventory.json')
SITES=('potrebpravo.ru','semya-yurist.ru')
assert BASE.is_file() and INV.is_file()
assert not SNAP.exists(),'REFUSE_OVERWRITE_PREVIOUS_BUILD'
SNAP.mkdir(parents=True,mode=0o700)
with tarfile.open(BASE,'r:gz') as t:
 files=[x for x in t.getmembers() if x.isfile()]
 assert len(files)==168 and all(len(Path(x.name).parts)>=3 and Path(x.name).parts[0] in SITES and Path(x.name).parts[1]=='public_html' and '..' not in Path(x.name).parts for x in files)
 t.extractall(SNAP,filter='data')
process=subprocess.run(['python3',str(ROOT/'audits/oleg-indexing/apply_metrika_goals.py'),'--root-parent',str(SNAP),'--goals-only','--apply'],capture_output=True,text=True,check=True)
result=json.loads(process.stdout)
assert result['filesChanged']==47,result
patched=(ROOT/'audits/oleg-indexing/legal-assistant-v4-utm.js').read_bytes()
assistant_hash=hashlib.sha256(patched).hexdigest()[:8]
for host in SITES:
 root=SNAP/host/'public_html'
 current=root/'assets/legal-assistant-v4.js'
 assert hashlib.sha256(current.read_bytes()).hexdigest()=='bdc89e956c80712fdb25c0333d941377d3b1b09afe0bf842a97cea1e9fb64c74'
 current.write_bytes(patched)
 changed=0
 for html in root.rglob('*.html'):
  txt=html.read_text()
  old='assets/legal-assistant-v4.js'
  if old not in txt:continue
  assert txt.count(old)==1,(host,html)
  html.write_text(txt.replace(old,old+'?v='+assistant_hash,1))
  changed+=1
 print(host,'assistant_js_sha8',assistant_hash,'cache_bust_html',changed)
print('V25_OFFLINE_PREPARED','base_count',len(files),'goal_changes',result['filesChanged'],'extra_assistant_js',2)