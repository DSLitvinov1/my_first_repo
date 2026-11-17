#!/usr/bin/env python3
"""V17 availability-only hotfix builder. Four known live files, no production writer."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

HOST_FORMS = {"potrebpravo.ru":"crm_form_fhi3n","semya-yurist.ru":"crm_form_ep5fd"}
SOURCE_SHA = {
 "potrebpravo.ru/index.html":"7138aad960cb41c169b3417046f2c9d673110ae39e82be5033f48eb3eb5b0704",
 "semya-yurist.ru/index.html":"f7b0b6a897aefe7bf09b06bc550691709988a4cfee1641e7caec48f47a805eaa",
 "potrebpravo.ru/assets/legal-assistant-v4.js":"3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a",
 "semya-yurist.ru/assets/legal-assistant-v4.js":"3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a",
}
OLD_NOTICE = '<div class="lead-form-unavailable" role="status">Для консультации воспользуйтесь телефоном или электронной почтой.</div>'
OLD_FALLBACK = """  const fallback = create('p');
  fallback.className = 'legal-small';
  fallback.append(create('span', 'Если форма не отображается, '));
  const open = create('a', 'откройте её на отдельной странице');
  open.className = 'legal-open';
  open.href = formUrl;
  open.target = '_blank';
  open.rel = 'noopener noreferrer';
  fallback.append(open, create('span', '.'));
  formStep.append(fallback);"""
NEW_FALLBACK = """  const fallback = create('p');
  fallback.className = 'legal-small';
  fallback.append(create('span', 'Если форма не отображается, '));
  const open = create('a', 'откройте её на отдельной странице');
  open.className = 'legal-open';
  open.href = formUrl;
  open.target = '_blank';
  open.rel = 'noopener noreferrer';
  const reserve = create('a', 'сохраните резервное обращение');
  reserve.className = 'legal-open';
  const attribution = new URLSearchParams(location.search);
  const trusted = new URLSearchParams('entry=assistant');
  for (const name of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content']) {
    const value = attribution.get(name);
    if (value && value.length <= 100 && !/[<>@]|https?:|\\d{10,}/i.test(value)) {
      trusted.set(name, value);
    }
  }
  reserve.href = '/emergency-lead.php?' + trusted.toString();
  const phone = create('a', 'позвоните');
  phone.className = 'legal-open';
  phone.href = 'tel:+79172052125';
  const email = create('a', 'напишите на почту');
  email.className = 'legal-open';
  email.href = 'mailto:centr-uprav@inbox.ru';
  fallback.append(open, create('span', '. Если Битрикс24 недоступен, '), reserve,
    create('span', '. Также можно '), phone, create('span', ' или '), email,
    create('span', '. Резервная форма подтверждает сохранение на сервере, а не поступление в Битрикс24.'));
  formStep.insertBefore(fallback, frame);"""

def sha(b):return hashlib.sha256(b).hexdigest()
def patch_home(text,host):
    if host not in HOST_FORMS or text.count(OLD_NOTICE)!=1:raise ValueError("Homepage source anchor mismatch")
    if text.count('data-form-mode="demo"')!=1 or text.count('id="lead-form" novalidate hidden aria-disabled="true"')!=1:
        raise ValueError("Existing unverified legacy form must stay disabled")
    if "tel:+79172052125" not in text or "mailto:centr-uprav@inbox.ru" not in text:
        raise ValueError("Independent visible contact source missing")
    form="https://b24-s2dosa.bitrix24site.ru/"+HOST_FORMS[host]+"/"
    replacement=(
      '<div class="lead-form-unavailable" role="status">'
      'Для консультации <a href="'+form+'" target="_blank" rel="noopener noreferrer">откройте форму Битрикс24</a>. '
      'Если она не загружается, <a href="/emergency-lead.php?entry=homepage">сохраните резервное обращение</a> '
      'непосредственно на нашем сервере. Также можно <a href="tel:+79172052125">позвонить</a> '
      'или <a href="mailto:centr-uprav@inbox.ru">написать на почту</a>. '
      'Подтверждение резервной формы означает сохранение на сервере, а не регистрацию в CRM.'
      '</div>')
    result=text.replace(OLD_NOTICE,replacement)
    if result.replace(replacement,OLD_NOTICE,1)!=text:raise AssertionError("Unexpected homepage changes")
    if result.count(form)!=1 or result.count('href="/emergency-lead.php?entry=homepage"')!=1:raise AssertionError("Missing site-specific links")
    return result

def patch_assistant(text):
    if text.count(OLD_FALLBACK)!=1 or "Qwen" in text or "qwen" in text:raise ValueError("Unexpected assistant JS baseline")
    result=text.replace(OLD_FALLBACK,NEW_FALLBACK)
    if result.replace(NEW_FALLBACK,OLD_FALLBACK,1)!=text:raise AssertionError("Unexpected JS changes")
    if result.count("reserve.href = '/emergency-lead.php?' + trusted.toString()")!=1 or result.count('formStep.insertBefore(fallback, frame)')!=1:raise AssertionError("Hotfix not visible above iframe")
    for marker in ("crm_form_fhi3n","crm_form_ep5fd","tel:+79172052125","mailto:centr-uprav@inbox.ru"):
        if marker not in result:raise AssertionError("Missing fallback or CRM marker")
    return result

def build(source,out):
    source,out=Path(source).resolve(),Path(out).resolve()
    if not source.is_dir() or out.exists() or out.is_relative_to(source):raise ValueError("Invalid source/output root")
    checked=[]
    for rel,expected in SOURCE_SHA.items():
        p=source/rel
        if not p.is_file() or p.is_symlink() or sha(p.read_bytes())!=expected:raise ValueError("Live source SHA drift: "+rel)
    out.mkdir(parents=True,exist_ok=False)
    for rel,expected in SOURCE_SHA.items():
        orig=source/rel
        text=orig.read_text('utf8')
        host=rel.split('/')[0]
        revised=patch_home(text,host) if rel.endswith('/index.html') else patch_assistant(text)
        dest=out/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(revised,'utf8')
        checked.append({'host':host,'file':rel.partition('/')[2],'previous_sha256':expected,'prepared_sha256':sha(dest.read_bytes()),'size':dest.stat().st_size})
    manifest={
      'state':'OFFLINE_AVAILABILITY_HOTFIX_V17_NOT_DEPLOYED',
      'changes':checked,'source_lock':len(checked),'public_endpoint':'/emergency-lead.php',
      'private_backend_required':True,
      'crm_auto_delivery':False,'success_semantics':'local_sqlite_commit_only',
      'production_writes':0,'test_submissions_real':0,
      'scope':'2 home HTML and 2 shared assistant JS ONLY; no SEO metadata changes',
    }
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    return manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',required=True)
    parser.add_argument('--out',required=True)
    args=parser.parse_args()
    print(json.dumps(build(args.source,args.out),ensure_ascii=False))
