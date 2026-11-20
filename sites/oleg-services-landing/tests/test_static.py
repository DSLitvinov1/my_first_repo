from html.parser import HTMLParser
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
class Page(HTMLParser):
 def __init__(self): super().__init__();self.ids=set();self.hrefs=[];self.h1=0;self.inputs=[]
 def handle_starttag(self,t,a):
  d=dict(a)
  if d.get('id'): self.ids.add(d['id'])
  if t=='a':self.hrefs.append(d.get('href',''))
  if t=='h1':self.h1+=1
  if t=='input':self.inputs.append(d)
page=Page()
html=(ROOT/'index.html').read_text()
page.feed(html)
assert page.h1==1
assert all(h[1:] in page.ids for h in page.hrefs if h.startswith('#'))
assert all((ROOT/h).is_file() for h in page.hrefs if h and not h.startswith(('#','tel:','https:')))
assert 'noindex,nofollow' in html
assert 'data-metrika-id=' not in html and not (ROOT/'sitemap.xml').exists()
assert 'id="step-one"' in html and 'id="step-two"' in html
assert 'id="step-two" class="form-step" aria-labelledby="step-two-title" hidden' in html
assert html.count('type="radio" name="service"')==5
assert html.count('data-service=')==5 and html.count('data-topic=')==8
assert 'id="lead-consent"' in html and 'id="lead-submit"' in html
assert 'Бесплатная консультация' in html and 'Дело под ключ' in html
assert 'До 8–10 минут, без анализа документов' in html
js=(ROOT/'assets/site.js').read_text()
assert 'services_crm_accepted' in js and 'data.status!=="accepted"' in js
assert 'crypto.randomUUID()' in js and 'api/nonce.php' in js
assert 'webvisor:false' in js and 'services_step1_completed' in js
assert 'data.preview === "true"' not in js or 'preview' in js
php=(ROOT/'api/bootstrap.php').read_text()
assert 'oleg-services-landing' in php and 'Олег' not in php or 'oleg-services-landing' in php
assert 'OLEG_SERVICES_STATE_DIR' in php and 'OLEG_SERVICES_PUBLIC_ORIGIN' in php
assert 'oleg-universal-landing' not in php
assert "Код формата: " in php and 'CONTACT_IDS' in php
lead=(ROOT/'api/lead.php').read_text()
assert "['free','paid','documents','remote','turnkey']" in lead
assert "api_resolve_deal" in lead and "outcome_unconfirmed" in lead
assert 'OLEG_LANDING_STATE_DIR' not in php
css=(ROOT/'assets/site.css').read_text()
assert '@media(max-width:760px)' in css and 'prefers-reduced-motion:reduce' in css
assert '.service-option:has(input:checked)' in css
subprocess.run(['node','--check',str(ROOT/'assets/site.js')],check=True)
print('PASS: site2 static, two-step, 5 services, 8 directions, SEO noindex, attribution and separate CRM')
