#!/usr/bin/env python3
"""Build a public SEO release only after approved privacy text and domain are supplied."""
from __future__ import annotations
import argparse
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse
from html import escape
ROOT = Path(__file__).resolve().parents[1]
def build(domain: str, counter: int, privacy: Path, dest: Path) -> None:
    parsed = urlparse("https://" + domain)
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain) or not parsed.hostname or '.' not in domain:
        raise ValueError("Use a verified DNS hostname without path or scheme")
    if counter < 1000000:
        raise ValueError("Provide the distinct verified Metrika counter for this domain")
    approved = privacy.read_text(encoding="utf-8")
    if len(approved) < 500 or '<html' not in approved.lower() or 'не опубликовано' in approved.lower() or 'на согласование' in approved.lower():
        raise ValueError("Approved standalone privacy HTML is required; draft privacy file is not accepted")
    if dest.resolve() == ROOT.resolve() or ROOT.resolve() in dest.resolve().parents:
        raise ValueError("Destination must be outside source tree")
    if dest.exists():
        raise ValueError("Destination already exists; refusing to overwrite a release")
    dest.mkdir(parents=True)
    for folder in ("assets", "api"):
        shutil.copytree(ROOT / folder, dest / folder)
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    if html.count('<meta name="robots" content="noindex,nofollow">') != 1:
        raise ValueError("Unexpected index template")
    html = html.replace('<meta name="robots" content="noindex,nofollow">', '<meta name="robots" content="index,follow">')
    html = html.replace('<html lang="ru">', f'<html lang="ru" data-metrika-id="{counter}">', 1)
    html = html.replace('</head>', f'  <link rel="canonical" href="https://{escape(domain)}/">\n  <meta property="og:url" content="https://{escape(domain)}/">\n</head>', 1)
    (dest / "index.html").write_text(html, encoding="utf-8")
    (dest / "privacy.html").write_text(approved, encoding="utf-8")
    (dest / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n",encoding="utf-8")
    (dest / "sitemap.xml").write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://{domain}/</loc></url></urlset>\n',encoding="utf-8")
    print("Built release:", dest)
    print("Still required: server env configuration, authorized CRM live readback, HTTPS and ad review.")
if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--domain", required=True)
    p.add_argument("--metrika", type=int, required=True)
    p.add_argument("--privacy-file", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a=p.parse_args()
    build(a.domain,a.metrika,a.privacy_file,a.output)
