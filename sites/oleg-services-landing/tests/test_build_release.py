from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import json
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "seo"))
from build_release import build
root = Path(__file__).resolve().parents[1]
with TemporaryDirectory() as tmp:
    base = Path(tmp)
    privacy = root / "privacy.html"
    advertiser = base / "advertiser.json"
    advertiser.write_text(json.dumps({
        "review_status": "approved", "legal_name": "ООО Юридический Пример",
        "physical_address": "Москва, Примерная улица, дом 17",
        "inn": "1234567890", "ogrn_or_ogrnip": "1234567890123"
    }, ensure_ascii=False))
    try:
        build("example.org",123456789,privacy,advertiser,base/"rejected")
        raise AssertionError("draft privacy must be rejected")
    except ValueError as err:
        assert "Approved standalone privacy" in str(err)
    approved = base / "approved.html"
    approved.write_text("<!doctype html><html lang='ru'><head><title>Политика</title></head><body><h1>ООО Юридический Пример</h1>" + ("<p>Согласованный документ оператора данных.</p>" * 22) + "</body></html>")
    release = base / "release"
    pending = json.loads(advertiser.read_text())
    pending['review_status']='pending'
    advertiser.write_text(json.dumps(pending, ensure_ascii=False))
    try:
        build("example.org",123456789,approved,advertiser,release)
        raise AssertionError('unapproved advertiser must not be published')
    except ValueError as err:
        assert 'approval' in str(err)
    pending['review_status']='approved'
    advertiser.write_text(json.dumps(pending, ensure_ascii=False))
    build("example.org",123456789,approved,advertiser,release)
    html = (release/"index.html").read_text()
    assert "noindex,nofollow" not in html and "index,follow" in html
    assert '<link rel="canonical" href="https://example.org/">' in html
    assert 'data-metrika-id="123456789"' in html
    assert "ООО Юридический Пример" in html and "ИНН: 1234567890" in html
    assert '"@type": "LegalService"' in html
    assert "https://example.org/sitemap.xml" in (release/"robots.txt").read_text()
    assert (release/"api/lead.php").is_file()
    try:
        build("example.org",123456789,approved,advertiser,release)
        raise AssertionError("overwriting existing release allowed")
    except ValueError as err:
        assert "Refusing overwrite" in str(err)
print("PASS: SEO/legal release gates, canonical, schema, Metrika ID, sitemap, overwrite")
