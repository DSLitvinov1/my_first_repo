#!/usr/bin/env python3
"""Safety-scoped emergency contact release: no new PII collector, no SEO."""
import hashlib, json, argparse
from pathlib import Path
from build_hotfix import SOURCE_SHA,OLD_NOTICE,OLD_FALLBACK,HOST_FORMS

JS_FALLBACK="""  const fallback = create('p');
  fallback.className = 'legal-small';
  fallback.append(create('span', 'Если Битрикс24 недоступен, '));
  const open = create('a', 'откройте форму отдельно');
  open.className = 'legal-open';
  open.href = formUrl;
  open.target = '_blank';
  open.rel = 'noopener noreferrer';
  const phone = create('a', 'позвоните');
  phone.className = 'legal-open';
  phone.href = 'tel:+79172052125';
  const email = create('a', 'напишите на почту');
  email.className = 'legal-open';
  email.href = 'mailto:centr-uprav@inbox.ru';
  fallback.append(open, create('span', '. Или '), phone, create('span', ' / '), email,
    create('span', '. Не направляйте конфиденциальные документы обычной почтой.'));
  formStep.insertBefore(fallback, frame);"""

FORM_OLD="  const formUrl = isFamily ? forms.family : forms.consumer;"
FORM_NEW="""  const formLink = new URL(isFamily ? forms.family : forms.consumer);
  const provided = new URLSearchParams(location.search);
  for (const name of ['utm_source','utm_medium','utm_campaign','utm_term','utm_content']) {
    const v = provided.get(name);
    if (v && v.length <= 100 && !/[<>@]|https?:|\\d{10,}/i.test(v)) formLink.searchParams.set(name, v);
  }
  const formUrl = formLink.toString();"""

def sha(data):return hashlib.sha256(data).hexdigest()
def single(text,old,new):
    if text.count(old)!=1:raise ValueError("Unique source anchor missing: STOP")
    patched=text.replace(old,new,1)
    if patched.replace(new,old,1)!=text:raise ValueError("Unexpected mutation")
    return patched
def homepage(text,host):
    if host not in HOST_FORMS:raise ValueError("Bad host")
    if text.count('data-form-mode="demo"')!=1 or text.count('id="lead-form" novalidate hidden aria-disabled="true"')!=1:raise ValueError("Hidden legacy form guard")
    if "tel:+79172052125" not in text or "mailto:centr-uprav@inbox.ru" not in text:raise ValueError("Existing contacts drift")
    url="https://b24-s2dosa.bitrix24site.ru/"+HOST_FORMS[host]+"/"
    replacement=(
      '<div class="lead-form-unavailable" role="status">'
      'Для обращения <a href="'+url+'" target="_blank" rel="noopener noreferrer">откройте форму Битрикс24</a>. '
      'Если форма не загружается, <a href="tel:+79172052125">позвоните</a> или '
      '<a href="mailto:centr-uprav@inbox.ru">напишите на почту</a>. '
      'Не отправляйте конфиденциальные документы до согласования безопасного способа связи.'
      '</div>')
    patched=single(text,OLD_NOTICE,replacement)
    if patched.count('href="'+url+'"')!=1:raise ValueError("Wrong site-specific CRM form")
    return patched
def assistant(text):
    if "Qwen" in text or "qwen" in text:raise ValueError("Qwen detected")
    patched=single(text,FORM_OLD,FORM_NEW)
    patched=single(patched,OLD_FALLBACK,JS_FALLBACK)
    for name in ('crm_form_fhi3n','crm_form_ep5fd','tel:+79172052125','mailto:centr-uprav@inbox.ru'):
        if name not in patched:raise ValueError("Missing expected source")
    if "formStep.insertBefore(fallback, frame)" not in patched:raise ValueError("Unavailable fallback below iframe")
    return patched
def build(source,out):
    source=Path(source).resolve();out=Path(out).resolve()
    if not source.is_dir() or out.exists() or out.is_relative_to(source):raise ValueError("Invalid paths")
    result=[]
    for rel,expected in SOURCE_SHA.items():
        current=source/rel
        if not current.is_file() or current.is_symlink() or sha(current.read_bytes())!=expected:
            raise ValueError("Timeweb source drift: "+rel)
    out.mkdir(parents=True)
    for rel,expected in SOURCE_SHA.items():
        data=(source/rel).read_text("utf8")
        modified=homepage(data,rel.split("/")[0]) if rel.endswith("/index.html") else assistant(data)
        file=out/rel;file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(modified,encoding="utf8")
        result.append({'relative_file':rel,'previous_sha256':expected,'new_sha256':sha(file.read_bytes()),'bytes':file.stat().st_size})
    manifest={'state':'INTERIM_AVAILABILITY_ONLY_NOT_DEPLOYED','files':result,'requires_private_queue':False,'changes_PII_collection':False,'SEO_changed':False,'fallback':'phone+email+existing_Bitrix_forms','UTM_behavior':'pass through only when present and sanitized; CRM readback still required'}
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n")
    return manifest
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    print(json.dumps(build(a.source,a.out),ensure_ascii=False))
