from pathlib import Path
from tempfile import TemporaryDirectory
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'seo'))
from build_release import build
with TemporaryDirectory() as tmp:
 base = Path(tmp)
 try:
  build('example.org',123456789,Path(__file__).resolve().parents[1]/'privacy.html',base/'rejected')
  raise AssertionError('draft must be rejected')
 except ValueError as e:
  assert 'Approved standalone privacy' in str(e)
 privacy=base/'approved.html'
 privacy.write_text('<!doctype html><html lang="ru"><head><title>Политика</title></head><body><h1>Согласованная политика</h1>'+('<p>Проверенный оператор, контакты, цели и права субъекта. </p>'*18)+'</body></html>')
 out=base/'release'
 build('example.org',123456789,privacy,out)
 html=(out/'index.html').read_text()
 assert 'noindex,nofollow' not in html and 'index,follow' in html
 assert '<link rel="canonical" href="https://example.org/">' in html
 assert 'data-metrika-id="123456789"' in html
 assert 'https://example.org/sitemap.xml' in (out/'robots.txt').read_text()
 assert 'https://example.org/' in (out/'sitemap.xml').read_text()
 assert (out/'api/lead.php').is_file() and (out/'assets/site.js').is_file()
 try:
  build('example.org',123456789,privacy,out)
  raise AssertionError('overwrite not blocked')
 except ValueError as e:
  assert 'already exists' in str(e)
print('PASS: privacy release gate, canonical, counter, sitemap, no overwrite')
