#!/usr/bin/env python3
"""Deployment-time local/remote audit without sending forms or reading private credentials."""
from __future__ import annotations
import argparse, json, re, ssl, sys
from pathlib import Path
from html.parser import HTMLParser
from urllib.request import Request, urlopen
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.anchors: set[str] = set()
    def handle_starttag(self, name, attrs):
        d = dict(attrs)
        if d.get('id'): self.anchors.add(d['id'])
        if name == 'a' and d.get('href'): self.links.append(d['href'])

def audit_files(files: dict[str, str], domain: str) -> list[str]:
    problems: list[str] = []
    html = files['index.html']
    robots = files['robots.txt']
    sitemap = files['sitemap.xml']
    privacy = files['privacy.html']
    expected = f'https://{domain}/'
    checks = {
        'canonical': f'<link rel="canonical" href="{expected}">' in html,
        'og:url': f'<meta property="og:url" content="{expected}">' in html,
        'indexing allowed': '<meta name="robots" content="index,follow">' in html and 'noindex,nofollow' not in html,
        'all 14 topics': html.count('data-topic=') == 14,
        'real form': 'id="lead-form"' in html and ('api_resolve_deal' in files['api/lead.php'] or files['api/lead.php']=='REMOTE_UNVERIFIED'),
        'privacy ready': len(privacy)>500 and 'на согласование' not in privacy.lower() and 'на утверждение' not in privacy.lower(),
        'robots api protected': 'Disallow: /api/' in robots,
        'robots sitemap': f'Sitemap: {expected}sitemap.xml' in robots,
        'domain-specific sitemap': f'<loc>{expected}</loc>' in sitemap,
        'no temporary domain': 'trycloudflare.com' not in html,
        'legal disclosure': 'ИНН:' in html and 'ОГРН/ОГРНИП:' in html,
        'analytics configured': bool(re.search(r'data-metrika-id="\d{7,}"', html)),
        'no real tokens in HTML': 'OLEG_BITRIX_WEBHOOK_URL=' not in html,
        'separate service': files['api/bootstrap.php']=='REMOTE_UNVERIFIED' or (('oleg-services-landing' in files['api/bootstrap.php']) != ('oleg-universal-landing' in files['api/bootstrap.php'])),
    }
    for check, passed in checks.items():
        if not passed: problems.append(check)
    page = Page(); page.feed(html)
    for link in page.links:
        if link.startswith('#') and link[1:] not in page.anchors:
            problems.append(f'broken anchor {link}')
    try:
        xml = ET.fromstring(sitemap)
        locs = [i.text for i in xml.iter() if i.tag.endswith('}loc')]
        if locs != [expected]: problems.append('unexpected sitemap URLs')
    except ET.ParseError:
        problems.append('invalid sitemap xml')
    try:
        metadata = re.search(r'<script type="application/ld\+json">(.*?)</script>', html,re.S)
        schema = json.loads(metadata.group(1)) if metadata else {}
        catalog = schema.get('hasOfferCatalog',{}).get('itemListElement',[])
        if schema.get('@type') != 'LegalService' or len(catalog)!=14:
            problems.append('structured data mismatch')
        if schema.get('url') != expected: problems.append('schema domain mismatch')
        area = [x.get('name') for x in schema.get('areaServed',[])]
        if area != ['Ростовская область','Краснодарский край']:
            problems.append('schema geographic mismatch')
    except (ValueError,AttributeError,TypeError):
        problems.append('invalid structured data')
    return problems

def check_release(folder: Path, domain: str) -> None:
    names = ['index.html','privacy.html','robots.txt','sitemap.xml','assets/site.css','assets/site.js','api/lead.php','api/bootstrap.php','api/nonce.php']
    data={}
    for name in names:
        path=folder/name
        if not path.is_file():raise ValueError(f'missing {name}')
        data[name]=path.read_text(encoding='utf-8')
    problems=audit_files(data,domain)
    if problems:raise ValueError('Release audit failed: '+', '.join(problems))

def check_remote(url: str) -> None:
    parsed=urlparse(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.path not in ('','/') or parsed.username:
        raise ValueError('Expected https://verified-domain.tld/')
    def get(path: str):
        req=Request(url.rstrip('/') + path,headers={'User-Agent':'OlegDeploymentPreflight/1.0','Accept':'text/html'})
        with urlopen(req,timeout=12,context=ssl.create_default_context()) as resp:
            if resp.status!=200:raise ValueError(f'GET {path} status {resp.status}')
            if urlparse(resp.url).hostname != parsed.hostname:raise ValueError('Unexpected redirect to another host')
            return resp.read(2000000).decode('utf-8')
    files={name:get('/'+name) for name in ('index.html','privacy.html','robots.txt','sitemap.xml','assets/site.css','assets/site.js')}
    # Do not call api/lead.php, do not send personal data. A nonce GET is not required for this read-only audit.
    files['api/lead.php']='REMOTE_UNVERIFIED'  # read-only remote checks cannot inspect PHP source
    files['api/bootstrap.php']='REMOTE_UNVERIFIED'
    files['api/nonce.php']=''
    failures=audit_files(files,parsed.hostname)
    if failures:raise ValueError('Remote audit failed: '+', '.join(failures))
    print('REMOTE SEO READ-ONLY PASS',parsed.hostname)
    print('Server-side CRM confirmation and Metika real events still require a separately authorized smoke test.')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--release-dir',type=Path)
    group.add_argument('--url',type=str)
    parser.add_argument('--domain')
    args=parser.parse_args()
    if args.release_dir:
        if not args.domain:parser.error('--domain is required with --release-dir')
        check_release(args.release_dir,args.domain)
        print('OFFLINE RELEASE SEO/SERVER FILES AUDIT PASS',args.domain)
    else: check_remote(args.url)
