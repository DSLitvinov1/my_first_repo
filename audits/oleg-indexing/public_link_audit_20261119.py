#!/usr/bin/env python3
"""Read-only smoke audit for Oleg Legal production links. Never submits forms."""
import concurrent.futures, datetime, json, urllib.parse, urllib.request, urllib.error
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

HOSTS = ("potrebpravo.ru", "semya-yurist.ru")
HEADERS = {"User-Agent": "OlegLegalQA/2026-11-19 (+read-only; no forms)"}
ROOT = Path(__file__).resolve().parents[2] / ".private-v25-offline"
class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.h1 = 0
        self.main = 0
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link", "script", "img"):
            val = a.get("href") if tag in ("a", "link") else a.get("src")
            if val:
                self.links.append((tag, val))
        if tag == "img":
            self.images.append({"src": a.get("src", ""), "alt": a.get("alt")})
        if tag == "h1":
            self.h1 += 1
        if tag == "main":
            self.main += 1

def fetch(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=13) as r:
            body = r.read(1400000)
            return {"url": url, "code": r.status, "final_url": r.url, "bytes": len(body), "html": body.decode("utf-8", "replace") if "text/html" in r.headers.get("Content-Type", "") else ""}
    except Exception as e:
        return {"url": url, "error": str(e)[:180]}

all_pages = {}
for host in HOSTS:
    xml = urllib.request.urlopen(urllib.request.Request(f"https://{host}/sitemap.xml", headers=HEADERS), timeout=13).read()
    all_pages[host] = [el.text.strip() for el in ET.fromstring(xml).iter() if el.tag.endswith("loc") and el.text]
page_results = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    for r in executor.map(fetch, [u for pages in all_pages.values() for u in pages]):
        page_results[r["url"]] = r

discovered = {}
page_issues = []
for url, r in page_results.items():
    if r.get("code") != 200 or not r.get("html"):
        page_issues.append({"url": url, "kind": "page_unavailable", "detail": r.get("error", r.get("code"))})
        continue
    parser = Links()
    parser.feed(r["html"])
    if parser.h1 != 1:
        page_issues.append({"url": url, "kind": "h1_count", "detail": parser.h1})
    if parser.main != 1:
        page_issues.append({"url": url, "kind": "main_count", "detail": parser.main})
    for image in parser.images:
        if image["alt"] is None:
            page_issues.append({"url": url, "kind": "missing_image_alt", "detail": image["src"][:100]})
    host = urllib.parse.urlparse(url).hostname
    for tag, raw in parser.links:
        if raw.startswith(("mailto:", "tel:", "javascript:", "#", "data:", "blob:")):
            continue
        absolute = urllib.parse.urljoin(url, raw)
        pu = urllib.parse.urlparse(absolute)
        if pu.scheme not in ("http", "https") or pu.hostname != host:
            continue
        normalized = urllib.parse.urlunparse((pu.scheme, pu.netloc, pu.path or "/", "", "", ""))
        discovered.setdefault(normalized, {"pages": [], "tags": set()})
        discovered[normalized]["pages"].append(url)
        discovered[normalized]["tags"].add(tag)

to_check = [x for x in discovered if x not in page_results]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    extras = list(executor.map(fetch, to_check))
bad = []
for r in extras:
    if r.get("code") != 200:
        x = discovered[r["url"]]
        bad.append({"target": r["url"], "code": r.get("code"), "error": r.get("error", "")[:150], "linked_from": list(dict.fromkeys(x["pages"]))[:5], "tags": sorted(x["tags"])})
report = {
    "checkedAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "sitemap_count": {h: len(urls) for h, urls in all_pages.items()},
    "page_count": len(page_results),
    "unique_internal_targets": len(discovered),
    "additional_targets_checked": len(extras),
    "page_issues": page_issues,
    "broken_internal_targets": bad
}
ROOT.mkdir(exist_ok=True, parents=True)
out = ROOT / "public-link-audit-20261119.json"
out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"report": str(out), "sitemap_count": report["sitemap_count"], "unique_internal_targets": len(discovered), "additional_targets_checked": len(extras), "page_issue_count": len(page_issues), "page_issues_first": page_issues[:15], "broken_target_count": len(bad), "broken_targets_first": bad[:20]}, ensure_ascii=False))
