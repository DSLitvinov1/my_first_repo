#!/usr/bin/env python3
"""Safe V51 offline-only repair of misleading service-page form calls to action."""
import argparse,hashlib,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'.private-v25-offline'/'snapshot'
STAGING=ROOT/'.private-v51-offline'/'candidate'
FORM={
 'potrebpravo.ru':'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',
 'semya-yurist.ru':'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/'
}
SERVICES={
 'potrebpravo.ru':('nekachestvennye-uslugi','neustoyka-zastroishchika','pretenziya-prodavcu','strahovye-spory','vozvrat-avtomobilya','vozvrat-deneg'),
 'semya-yurist.ru':('alimenty','brachnyi-dogovor','ipotechnaya-kvartira','razdel-imushchestva','razvod','spory-o-detyakh')
}
OLD_P1='Электронный приём заявок появится после завершения согласования и проверки CRM.'
NEW_P1='Заявку на консультацию можно отправить через форму Битрикс24. После отправки проверьте сообщение о результате.'
OLD_P2='Онлайн-заявки на сайте пока отключены.'
NEW_P2='Для обращения воспользуйтесь онлайн-формой, телефоном или электронной почтой. Отправка формы подтверждается отдельным сообщением.'
OLD_ASIDE='без передачи чувствительной информации через неработающие формы.'
NEW_ASIDE='не отправляя пароли, паспортные данные и документы через открытые сообщения.'
def sha(b):return hashlib.sha256(b).hexdigest()
def render(host,s):
 if s.count('<section class="cta">')!=1:raise ValueError('CTA section is not unique')
 if ('oleg-analytics-v1.js' not in s) or ('legal-assistant-v4.js' not in s):raise ValueError('Missing V25 scripts')
 old_count=s.count(OLD_P1)+s.count(OLD_P2)
 if old_count!=1:raise ValueError('Unexpected stale CTA text count: '+str(old_count))
 s=s.replace(OLD_P1,NEW_P1).replace(OLD_P2,NEW_P2)
 if OLD_ASIDE in s:
  if s.count(OLD_ASIDE)!=1:raise ValueError('Unexpected aside count')
  s=s.replace(OLD_ASIDE,NEW_ASIDE)
 start=s.index('<section class="cta">')
 end=s.index('</section>',start)
 sect=s[start:end]
 if FORM[host] in sect:raise ValueError('Direct link already exists')
 pos=sect.find('</p>')
 if pos<0:raise ValueError('CTA first paragraph missing')
 pos+=len('</p>')
 direct='<p class="oleg-direct-crm-link"><a href="'+FORM[host]+'" target="_blank" rel="noopener noreferrer" aria-label="Оставить заявку на юридическую консультацию">Оставить заявку на консультацию</a></p>'
 sect=sect[:pos]+direct+sect[pos:]
 s=s[:start]+sect+s[end:]
 if OLD_P1 in s or OLD_P2 in s or OLD_ASIDE in s:raise ValueError('Stale text survives')
 if s.count(FORM[host])!=1:raise ValueError('Incorrect CRM-form link count')
 if s.count('<section class="cta">')!=1:raise ValueError('Changed CTA structure')
 return s
def main():
 p=argparse.ArgumentParser();p.add_argument('--apply',action='store_true');args=p.parse_args()
 changed=[]
 for host,names in SERVICES.items():
  for name in names:
   path=BASE/host/'public_html'/'services'/(name+'.html')
   before=path.read_text()
   after=render(host,before)
   changed.append({'site':host,'path':'services/'+name+'.html','old_sha':sha(before.encode()),'new_sha':sha(after.encode()),'old_len':len(before),'new_len':len(after)})
 assert len(changed)==12
 if not args.apply:
  print('V51_DRY_RUN_PASS',len(changed),'service pages; originals untouched')
  return
 if STAGING.exists():raise FileExistsError('Candidate directory already exists, refuse overwrite')
 STAGING.parent.mkdir(parents=True,exist_ok=True)
 for host in SERVICES:
  shutil.copytree(BASE/host/'public_html', STAGING/host/'public_html')
 for row in changed:
  f=STAGING/row['site']/'public_html'/row['path']
  before=f.read_text()
  assert sha(before.encode())==row['old_sha']
  after=render(row['site'],before)
  f.write_text(after)
  assert sha(f.read_bytes())==row['new_sha']
 for host in SERVICES:
  prior=BASE/host/'public_html'
  files=list(p for p in prior.rglob('*') if p.is_file())
  for f in files:
   dest=STAGING/host/'public_html'/f.relative_to(prior)
   if not dest.is_file():raise AssertionError('File lost: '+str(f))
   expected=next((x for x in changed if x['site']==host and x['path']==str(f.relative_to(prior))),None)
   if not expected and f.read_bytes()!=dest.read_bytes():raise AssertionError('Unexpected modification '+str(f))
 manifest={'scope':'OFFLINE ONLY — NOT PUBLISHED','source':'Existing V25 snapshot','changed_count':len(changed),'sites':list(SERVICES),'changes':changed}
 path=STAGING.parent/'v51-service-cta-manifest.json'
 path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
 print('V51_OFFLINE_PREPARED',len(changed),'changed, all other V25 files preserved')
 print('MANIFEST',path)
if __name__=='__main__':main()