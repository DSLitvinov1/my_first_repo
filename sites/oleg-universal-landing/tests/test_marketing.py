from pathlib import Path
import csv,json,re
from urllib.parse import urlparse,parse_qs
ROOT=Path(__file__).resolve().parents[1]
first=(ROOT.name=='oleg-universal-landing')
regions={'Ростовская область','Краснодарский край'}
with (ROOT/'seo/direct-search-ready.csv').open(encoding='utf-8',newline='') as handle:
    rows=list(csv.DictReader(handle,delimiter=';'))
assert len(rows)==(28 if first else 10),len(rows)
assert {row['region'] for row in rows}==regions
assert len({r['campaign'] for r in rows})==len(rows)
assert len({(r['region'],r['group']) for r in rows})==len(rows)
html=(ROOT/'index.html').read_text()
javascript=(ROOT/'assets/site.js').read_text()
for r in rows:
    assert r['status'].startswith('Черновик')
    assert 'ПОИСК' in r['channel'] and 'НЕ ВКЛЮЧАТЬ' in r['channel']
    assert len(r['headline'])<=56 and len(r['body'])<=81
    assert max(map(len,r['headline'].split()))<=22
    assert max(map(len,r['body'].split()))<=23
    assert len(re.findall(r'[^\w\s]',r['body']))<=15
    qs=parse_qs(urlparse(r['relative_url']).query)
    assert qs['utm_campaign']==[r['campaign']]
    assert qs['utm_source']==['yandex']
    assert qs['utm_medium']==['cpc']
    assert qs['utm_content']==['{ad_id}']
    assert qs['utm_term']==['{keyword}']
    if first:
        assert f'<option>{r["group"]}</option>' in html
        assert qs['topic']==[r['group']]
    else:
        assert qs['service']==[r['service_code']]
        assert f'value="{r["service_code"]}"' in html
for region in regions:
    assert sum(r['region']==region for r in rows)==(14 if first else 5)
with (ROOT/'seo/semantic-map.csv').open(encoding='utf-8',newline='') as f:
    keywords=list(csv.DictReader(f,delimiter=';'))
assert len(keywords)==28
assert {x['region'] for x in keywords}==regions
assert len({x['service_topic'] for x in keywords})==14
for r in keywords:
    assert r['service_topic'] in html
goals=json.loads((ROOT/'seo/metrika-goals.json').read_text(encoding='utf-8'))['events']
assert len(goals)==(3 if first else 5)
assert sum(bool(g['primary']) for g in goals)==1
for goal in goals:assert f'"{goal["id"]}"' in javascript
assert 'noindex,nofollow' in html and not (ROOT/'sitemap.xml').exists()
print('PASS: marketing handoff: 2 regions /',len(rows),'search drafts / 14 organic subjects / verified goals; no launched ads')
