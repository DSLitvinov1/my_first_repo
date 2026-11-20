from pathlib import Path
from tempfile import TemporaryDirectory
import json, csv, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'seo'))
sys.path.insert(0,str(ROOT/'deploy'))
from build_release import build
from audit_release import check_release
with TemporaryDirectory() as temp:
    work=Path(temp)
    advertiser=work/'advertiser.json'
    company='ООО Тестовая юридическая организация'
    advertiser.write_text(json.dumps({'review_status':'approved','legal_name':company,
     'physical_address':'г. Краснодар, ул. Примерная, 10','inn':'1234567890',
     'ogrn_or_ogrnip':'1234567890123'},ensure_ascii=False))
    privacy=work/'policy.html'
    privacy.write_text('<!doctype html><html lang="ru"><head><title>Политика</title></head><body>'+
      '<h1>Политика обработки персональных данных</h1><p>'+company+'</p>'+
      ('<p>Тестовое описание утвержденной политики, не предназначенное для размещения.</p>'*20)+'</body></html>')
    target=work/'release'
    build('example.org',123456789,privacy,advertiser,target)
    check_release(target,'example.org')
    print('PASS: full SEO/canonical/robots/14 services/CRM release package')
    original=(target/'robots.txt').read_text()
    (target/'robots.txt').write_text('User-agent: *\nAllow: /\n')
    try:
        check_release(target,'example.org')
        raise AssertionError('Missing api safeguard accepted')
    except ValueError as e:
        assert 'robots api protected' in str(e)
    (target/'robots.txt').write_text(original)
    original=(target/'index.html').read_text()
    (target/'index.html').write_text(original.replace('https://example.org/','https://other.org/',1))
    try:
        check_release(target,'example.org')
        raise AssertionError('Incorrect canonical accepted')
    except ValueError as e:
        assert 'canonical' in str(e)
    for unsafe in ('localhost','temp.trycloudflare.com','-invalid.ru','example..ru'):
        try:build(unsafe,123456789,privacy,advertiser,work/('unsafe-'+unsafe.replace('.','-')))
        except ValueError:pass
        else:raise AssertionError('Unsafe hostname allowed: '+unsafe)
    print('PASS: fail-closed SEO audit & unsafe-domain rejection')
