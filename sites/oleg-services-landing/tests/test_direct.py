from pathlib import Path
import csv
from urllib.parse import urlparse,parse_qs
ROOT=Path(__file__).resolve().parents[1]
with (ROOT/'seo/direct-draft.csv').open(encoding='utf-8') as fp:
 rows=list(csv.DictReader(fp,delimiter=';'))
assert len(rows)==5
assert {r['Код услуги'] for r in rows}=={'free','paid','documents','remote','turnkey'}
assert len({r['UTM кампания'] for r in rows})==5
for r in rows:
 assert 0<len(r['Заголовок'])<=56
 assert 0<len(r['Текст'])<=81
 assert 'Черновик' in r['Статус']
 uri=urlparse(r['Ссылка (относительная)'])
 assert uri.path=='/'
 args=parse_qs(uri.query)
 assert args['service']==[r['Код услуги']]
 assert args['utm_source']==['yandex'] and args['utm_medium']==['cpc']
 assert args['utm_content']==['{ad_id}']
 assert args['utm_campaign']==[r['UTM кампания']]
print('PASS: 5 isolated Direct service groups, UTM and length checks, no paid launch')
