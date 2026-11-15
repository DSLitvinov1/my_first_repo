#!/usr/bin/env python3
"""Build a *non-production* 39-page assistant rollout using exact public HTML locks."""
import argparse
import hashlib
import json
import re
import shutil
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

DOMAINS = {'potrebpravo.ru': 23, 'semya-yurist.ru': 18}
ASSISTANT = '<script defer src="/assets/legal-assistant-v4.js"></script>'
ASSET_SHA256 = '3ae643d908b5cc3b7a5cc1081b06183fbe686887323ad345639e57e01b846e8a'
MAX_HTML_BYTES = 1500000

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def inject_assistant(src):
    """Insert precisely once, preserving all original markup and Metrika consent."""
    if not isinstance(src, bytes):
        raise TypeError('Bytes required')
    text = src.decode('utf-8')
    if 'legal-assistant-v4.js' in text:
        return src, False
    closings = list(re.finditer(r'</body\s*>', text, flags=re.I))
    if len(closings) != 1:
        raise ValueError('Missing or ambiguous HTML body closing tag')
    anchor = closings[0]
    new = text[:anchor.start()] + '\n' + ASSISTANT + '\n' + text[anchor.start():]
    if new.count('legal-assistant-v4.js') != 1:
        raise ValueError('Assistant insertion was not unique')
    if new.replace('\n' + ASSISTANT + '\n', '', 1) != text:
        raise ValueError('Mutation exceeded single assistant script tag')
    return new.encode('utf-8'), True

class SameHostOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if old.hostname != new.hostname or new.scheme != 'https':
            raise ValueError('Cross-host or insecure redirect denied')
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)

OPENER = urllib.request.build_opener(SameHostOnly())

def fetch_url(url, maximum=MAX_HTML_BYTES):
    before = urllib.parse.urlsplit(url)
    if before.scheme != 'https' or before.hostname not in DOMAINS or before.username:
        raise ValueError('Source hostname not allowed')
    request = urllib.request.Request(url, headers={'User-Agent':'OlegSEO-OwnerReadOnlyStage/1.0','Accept':'text/html,application/xml,*/*'})
    with OPENER.open(request, timeout=19) as resp:
        after = urllib.parse.urlsplit(resp.geturl())
        if resp.status != 200 or after.scheme != 'https' or after.hostname != before.hostname:
            raise ValueError('Unexpected status or redirect')
        content = resp.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError('Unexpectedly large HTML')
    return content

def path_for(url, host):
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https' or p.hostname != host or p.query or p.fragment or p.port or p.username or p.password:
        raise ValueError('Unapproved URL in sitemap')
    path = p.path
    if path == '/':
        return PurePosixPath('index.html')
    if not re.fullmatch(r'/[A-Za-z0-9_/-]+\.html', path):
        raise ValueError('Unapproved sitemap pathname')
    cleaned = PurePosixPath(path.lstrip('/'))
    if '..' in cleaned.parts or len(cleaned.parts) > 6:
        raise ValueError('Traversal or too deeply nested')
    return cleaned

def build(lock, destination):
    lock_sites = lock.get('sites')
    if not isinstance(lock_sites, dict) or set(lock_sites) != set(DOMAINS):
        raise ValueError('Locked source list missing domains')
    if destination.exists():
        raise ValueError('Stage destination already exists; never overwrite')
    # Network preflight occurs BEFORE materializing edited files.
    gathered = {}
    for host, expected_count in DOMAINS.items():
        asset = fetch_url('https://' + host + '/assets/legal-assistant-v4.js', 50000)
        if sha256(asset) != ASSET_SHA256:
            raise ValueError('Unexpected live assistant JS content on ' + host)
        doc = ET.fromstring(fetch_url('https://' + host + '/sitemap.xml', 250000))
        urls = list(dict.fromkeys(x.text.strip() for x in doc.iter() if x.tag.endswith('}loc') or x.tag == 'loc'))
        if len(urls) != expected_count:
            raise ValueError('Sitemap page count changed')
        expected = lock_sites[host]['entries']
        if set(expected) != set(urllib.parse.urlsplit(u).path or '/' for u in urls):
            raise ValueError('Sitemap URLs differ from reviewed lock')
        for url in urls:
            rel = path_for(url,host)
            path = urllib.parse.urlsplit(url).path or '/'
            raw = fetch_url(url)
            if sha256(raw) != expected[path]:
                raise ValueError('Source drift at ' + host + path)
            new, edited = inject_assistant(raw)
            should_edit = (path != '/')
            if edited != should_edit:
                raise ValueError('Assistant insertion state disagrees with reviewed page at ' + host + path)
            gathered[(host,str(rel))] = (raw,new,edited)
    if len(gathered) != 41 or sum(v[2] for v in gathered.values()) != 39:
        raise ValueError('Wrong stage page count')
    destination.mkdir(parents=True, exist_ok=False)
    originals = destination / '.originals'
    originals.mkdir()
    manifest = []
    for (host,rel),(raw,new,edited) in sorted(gathered.items()):
        staging = destination / host / 'public_html' / rel
        backup = originals / host / rel
        staging.parent.mkdir(parents=True,exist_ok=True)
        backup.parent.mkdir(parents=True,exist_ok=True)
        staging.write_bytes(new)
        backup.write_bytes(raw)
        if sha256(staging.read_bytes()) != sha256(new) or sha256(backup.read_bytes()) != sha256(raw):
            raise RuntimeError('Local stage write verification failed')
        manifest.append({'site':host,'path':rel,'changed':edited,'old_sha256':sha256(raw),'new_sha256':sha256(new)})
    archive = destination/'original-public-html-backup.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for f in sorted(originals.rglob('*.html')):
            z.write(f,f.relative_to(originals))
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None or len(z.namelist()) != 41:
            raise RuntimeError('Public HTML backup archive corrupt')
    report={'status':'OFFLINE_ONLY_39_PAGE_ASSISTANT_STAGE_PASS',
       'sites':{host:len([m for m in manifest if m['site']==host and m['changed']]) for host in DOMAINS},
       'pages_total':41,'pages_changed':40,'assistant_sha256':ASSET_SHA256,
       'offline_backup_verified':True,'backups_are_not_timeweb_backups':True,
       'production_modified':False,'bitrix_deals_created':0,
       'manifest':manifest,'archive':str(archive),'stage_dir':str(destination)}
    (destination/'stage-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('OLEG_ASSISTANT_STAGE_RESULT='+json.dumps({k:v for k,v in report.items() if k!='manifest'},ensure_ascii=False))
    return report

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--lock',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    build(json.loads(args.lock.read_text(encoding='utf-8')),args.out)
