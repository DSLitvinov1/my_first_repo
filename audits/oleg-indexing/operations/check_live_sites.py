#!/usr/bin/env python3
"""Read-only public health and SEO checks for two Oleg legal websites.

No cookies, analytics identifiers, applicant fields, hidden admin URLs or writes.
A Bitrix CRM form response with HTTP 200 is *not* evidence of successful
JavaScript hydration or delivery to CRM.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
import re
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

SITES = {
    "potrebpravo.ru": {"form": "crm_form_fhi3n", "counter": "114249897", "min_sitemap": 23},
    "semya-yurist.ru": {"form": "crm_form_ep5fd", "counter": "114251443", "min_sitemap": 18},
}
FORM_HOST = "b24-s2dosa.bitrix24site.ru"
MAX_BODY = 1024 * 1024
USER_AGENT = "OlegLegalAvailabilityMonitor/1.0 (read-only; no applicant submission)"
TIMEOUT = 12

class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.in_title = False
        self.meta = []
        self.links = []
        self.scripts = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title": self.in_title = True
        elif tag == "meta": self.meta.append(a)
        elif tag == "link": self.links.append(a)
        elif tag == "script": self.scripts.append(a)
    def handle_endtag(self, tag):
        if tag == "title": self.in_title = False
    def handle_data(self, data):
        if self.in_title: self.title += data

def fetch(url: str) -> tuple[int, bytes, str]:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    with urlopen(req, timeout=TIMEOUT) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY: raise ValueError("response too large")
        return int(response.status), body, response.geturl()

def noindex(page: Page) -> bool:
    return any(m.get("name", "").lower() == "robots"
               and re.search(r"\bnoindex\b", m.get("content", ""), re.I) for m in page.meta)

def canonical(page: Page) -> str:
    matches = [x.get("href", "") for x in page.links
               if "canonical" in x.get("rel", "").lower().split()]
    return matches[0] if len(matches) == 1 else ""

def sitemap_pages(host: str, xml: bytes) -> list[str]:
    # XML document must be an actual sitemap, not HTML or attacker-controlled
    # URLs. Do not follow nested sitemap index or foreign URLs.
    if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
        raise ValueError("unsafe xml document")
    root = ET.fromstring(xml)
    if not root.tag.endswith("urlset"): raise ValueError("not a URL sitemap")
    pages = [((element.text or "").strip()) for element in root.iter()
             if element.tag.endswith("loc")]
    unique = list(dict.fromkeys(pages))
    if len(unique) != len(pages): raise ValueError("duplicate sitemap URLs")
    for address in unique:
        parsed = urlparse(address)
        if parsed.scheme != "https" or parsed.netloc != host or parsed.fragment:
            raise ValueError("foreign or insecure sitemap URL")
        if not parsed.path.startswith("/"):raise ValueError("noncanonical path")
    return unique

def check_site(host: str, config: dict, get=fetch, *, all_pages=True) -> dict:
    errors, checks = [], []
    origin = "https://" + host
    def load(path, name):
        try:
            code, body, final = get(origin + path)
            if code != 200 or urlparse(final).netloc != host or not final.startswith(origin):
                raise ValueError("HTTP status or redirect origin mismatch")
            checks.append(name)
            return body
        except Exception as exc:
            errors.append(name + ": " + type(exc).__name__)
            return None
    body = load("/", "homepage")
    if body is not None:
        try:
            text = body.decode("utf8", "replace")
            page = Page();page.feed(text)
            expected_form = "https://" + FORM_HOST + "/" + config["form"] + "/"
            expected = {
                "title": bool(page.title.strip()),
                "description": any(m.get("name", "").lower() == "description" and m.get("content") for m in page.meta),
                "canonical": canonical(page) == origin + "/",
                "indexable": not noindex(page),
                "form_link": expected_form in text,
                "telephone": 'tel:+79172052125' in text,
                "email": 'mailto:centr-uprav@inbox.ru' in text,
                "qwen_removed": "qwen" not in text.lower(),
                "jsonld": any(s.get("type", "").lower() == "application/ld+json" for s in page.scripts),
                "metrika_asset": "oleg-analytics-v1.js" in text,
            }
            for key, ok in expected.items():
                if ok:checks.append("homepage_" + key)
                else:errors.append("homepage_" + key)
        except Exception as exc: errors.append("homepage_parse:" + type(exc).__name__)
    robots = load("/robots.txt", "robots")
    if robots is not None:
        t=robots.decode("utf8", "replace").lower()
        if "sitemap: "+origin.lower()+"/sitemap.xml" not in t: errors.append("robots_sitemap_missing")
        if re.search(r"(?m)^\s*disallow:\s*/\s*$", t): errors.append("robots_global_disallow")
    sitemap = load("/sitemap.xml", "sitemap")
    urls = []
    if sitemap is not None:
        try:
            urls = sitemap_pages(host, sitemap)
            if len(urls) < config["min_sitemap"]:
                errors.append("sitemap_page_count_below_baseline")
            else: checks.append("sitemap_count")
        except Exception as exc: errors.append("sitemap_invalid:" + type(exc).__name__)
    if all_pages:
        for url in urls:
            p=urlparse(url)
            relative = p.path + (("?" + p.query) if p.query else "")
            html=load(relative,"page_" + p.path)
            if html is None:continue
            parser=Page()
            try:
                parser.feed(html.decode("utf8","replace"))
                if not parser.title.strip():errors.append("no_title_"+p.path)
                if noindex(parser):errors.append("noindex_"+p.path)
                if canonical(parser) != url:errors.append("canonical_"+p.path)
            except Exception as exc:errors.append("page_parse_"+p.path+":"+type(exc).__name__)
    # This external HTTP GET proves at most shell availability, not form
    # fields, consent, successful JS hydration, POST, CRM record or notification.
    return {"host":host, "ok":not errors, "errors":errors, "checks":len(checks),
            "sitemap_url_count":len(urls), "external_form_dom_checked":False}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",help="Write a non-sensitive JSON status atomically")
    ap.add_argument("--homepage-only",action="store_true",help="Skip all sitemap page requests")
    args=ap.parse_args()
    sites={}
    for host,cfg in SITES.items():
        sites[host]=check_site(host,cfg,all_pages=not args.homepage_only)
    # Public CRM form check is a separate, low-trust signal.
    shells={}
    for host,cfg in SITES.items():
        url="https://"+FORM_HOST+"/"+cfg["form"]+"/"
        try:
            status,data,final=fetch(url)
            shells[host]={"http_ok":status==200,"form_ui_verified":False,
                "crm_delivery_verified":False}
        except Exception as exc:
            shells[host]={"http_ok":False,"form_ui_verified":False,
                "crm_delivery_verified":False,"error":type(exc).__name__}
    report={
        "date_utc":datetime.now(timezone.utc).isoformat(),
        "overall_public_healthy":all(x["ok"] for x in sites.values()) and all(x["http_ok"] for x in shells.values()),
        "site_checks":sites,"bitrix_public_form_http_shells":shells,
        "crm_real_delivery_checked":False,
        "search_console_indexation_checked":False,
        "customer_personal_data_collected":False,
    }
    output=json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    if args.out:
        import os, pathlib
        dst=pathlib.Path(args.out)
        dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        tmp=dst.with_suffix(dst.suffix+".tmp")
        with open(tmp,"x",encoding="utf8") as f:
            f.write(output);f.flush();os.fsync(f.fileno())
        os.chmod(tmp,0o600);os.replace(tmp,dst)
    print(output)
    raise SystemExit(0 if report["overall_public_healthy"] else 2)

if __name__=="__main__":main()
