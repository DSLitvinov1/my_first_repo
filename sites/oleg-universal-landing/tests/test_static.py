from html.parser import HTMLParser
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
class Site(HTMLParser):
 def __init__(self): super().__init__();self.ids=set();self.links=[];self.headings=[]
 def handle_starttag(self,tag,attrs):
  d=dict(attrs)
  if 'id' in d: self.ids.add(d['id'])
  if tag=='a': self.links.append(d.get('href',''))
  if tag in ('h1','h2','h3'):self.headings.append(tag)
site=Site();html=(ROOT/'index.html').read_text(encoding='utf-8');site.feed(html)
assert site.headings.count('h1')==1
assert all(url[1:] in site.ids for url in site.links if url.startswith('#'))
assert all((ROOT/url).is_file() for url in site.links if url and not url.startswith(('#','tel:','https:')))
assert 'noindex,nofollow' in html
assert 'data-metrika-id=' not in html
assert 'ОБРАЩЕНИЕ К ЮРИСТУ' in html
js=(ROOT/'assets/site.js').read_text()
assert 'landing_crm_accepted' in js and 'data.status!=="accepted"' in js
assert 'api/nonce.php' in js and 'credentials:"same-origin"' in js
assert "window.ym(metrikaId" in js
api=(ROOT/'api/lead.php').read_text()
assert "api_resolve_deal" in api and "outcome_unconfirmed" in api
assert "crm.deal.get" in (ROOT/"api/bootstrap.php").read_text()
assert 'api_crm_config()' in api and 'HTTP_ORIGIN' in api
assert not (ROOT/'sitemap.xml').exists()
subprocess.run(['node','--check',str(ROOT/'assets/site.js')],check=True)
print('PASS: static structure, staging gates, no fake lead goals')
