#!/usr/bin/env python3
"""Generate a public SEO release only after privacy, domain, analytics and advertiser facts are approved."""
from __future__ import annotations
import argparse
import json
import re
import shutil
from pathlib import Path
from html import escape
ROOT = Path(__file__).resolve().parents[1]

def build(domain: str, counter: int, privacy: Path, advertiser: Path, dest: Path) -> None:
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain) or '.' not in domain:
        raise ValueError("Verified HTTPS domain name required")
    if counter < 1000000:
        raise ValueError("Provide a distinct verified Metrika counter")
    approved = privacy.read_text(encoding="utf-8")
    if len(approved) < 500 or '<html' not in approved.lower() or 'на согласование' in approved.lower():
        raise ValueError("Approved standalone privacy HTML is required; draft privacy file is not accepted")
    data = json.loads(advertiser.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Advertiser identity must be an object")
    if data.get('review_status') != 'approved':
        raise ValueError('Verified advertiser details require explicit owner approval')
    required = ('legal_name', 'physical_address', 'inn')
    if any(not isinstance(data.get(k), str) or len(data[k].strip()) < (10 if k != 'inn' else 10) for k in required):
        raise ValueError("Verified legal name, actual address and INN are mandatory")
    if not re.fullmatch(r"\d{10}|\d{12}", data["inn"].strip()):
        raise ValueError("INN format invalid")
    if data["legal_name"].strip() not in approved:
        raise ValueError("Advertiser and approved privacy operator must match")
    ogrn = data.get("ogrn_or_ogrnip", "")
    if ogrn and not re.fullmatch(r"\d{13}|\d{15}", str(ogrn)):
        raise ValueError("Invalid OGRN/OGRNIP")
    if dest.resolve() == ROOT.resolve() or ROOT.resolve() in dest.resolve().parents:
        raise ValueError("Build output must be outside source tree")
    if dest.exists():
        raise ValueError("Refusing overwrite of an existing release")
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    if html.count('<meta name="robots" content="noindex,nofollow">') != 1:
        raise ValueError("Staging source drift; refused")
    if '<footer class="footer">' not in html:
        raise ValueError("Footer anchor missing")
    html = html.replace('<meta name="robots" content="noindex,nofollow">',
                        '<meta name="robots" content="index,follow">', 1)
    html = html.replace('<html lang="ru">', f'<html lang="ru" data-metrika-id="{counter}">', 1)
    url = f"https://{domain}/"
    html = html.replace('</head>', f'<link rel="canonical" href="{url}">\n<meta property="og:url" content="{url}">\n</head>', 1)
    legal = (f'<div class="wrap legal-details"><strong>{escape(data["legal_name"].strip())}</strong>'
             f'<span>{escape(data["physical_address"].strip())}</span>'
             f'<span>ИНН: {escape(data["inn"].strip())}</span>'
             + (f'<span>ОГРН/ОГРНИП: {escape(str(ogrn))}</span>' if ogrn else '')
             + '</div>')
    html = html.replace('</footer>', legal + '</footer>', 1)
    schema = {
        "@context": "https://schema.org", "@type": "LegalService",
        "name": data['legal_name'].strip(), "url": url,
        "telephone": "+79172052125", "address": data['physical_address'].strip(),
        "areaServed": [{"@type": "AdministrativeArea", "name": "Ростовская область"},
                       {"@type": "AdministrativeArea", "name": "Краснодарский край"}]
    }
    html = html.replace('</head>',
        '<script type="application/ld+json">' + json.dumps(schema, ensure_ascii=False).replace('<', '\\u003c')
        + '</script>\n</head>', 1)
    dest.mkdir(parents=True)
    shutil.copytree(ROOT / 'assets', dest / 'assets')
    shutil.copytree(ROOT / 'api', dest / 'api')
    (dest / 'index.html').write_text(html, encoding='utf-8')
    (dest / 'privacy.html').write_text(approved, encoding='utf-8')
    (dest / 'robots.txt').write_text(f'User-agent: *\nAllow: /\nSitemap: {url}sitemap.xml\n', encoding='utf-8')
    (dest / 'sitemap.xml').write_text(
      f'<?xml version="1.0" encoding="UTF-8"?>\n'
      f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{url}</loc></url></urlset>\n',
      encoding='utf-8')
    print("Release built:", dest)
    print("Still gated: verified CRM readback, domain SSL, separate goals, advertising approval.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('--domain', required=True)
    p.add_argument('--metrika', required=True, type=int)
    p.add_argument('--privacy-file', required=True, type=Path)
    p.add_argument('--advertiser-file', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    build(a.domain, a.metrika, a.privacy_file, a.advertiser_file, a.output)
