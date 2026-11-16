#!/usr/bin/env python3
"""Read-only-first installer for Oleg's existing Bitrix24 chatbot on all sitemap pages.

Uses each site's actual local sitemap and existing legal-assistant-v4.js. Does NOT
change the bot's logic or submit contacts. All edits are backed up before publish.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

from metadata_guard import apply_edits

SITE_COUNTS={'potrebpravo.ru':23,'semya-yurist.ru':18}
SCRIPT='<script defer src="/assets/legal-assistant-v4.js"></script>'
# Keep consent/refusal controls above the floating assistant on narrow viewports.
CONSENT_PRIORITY='<style id="oleg-consent-priority">#oleg-analytics-choice{z-index:2147483647!important}</style>'
SCRIPT_RE=re.compile(r'''(?i)<script\b[^>]*\bsrc\s*=\s*["'][^"']*/assets/legal-assistant-v4\.js(?:\?[^"']*)?["'][^>]*>''')
CLOSE_BODY=re.compile(r'(?i)</body\s*>')
FORMS={'potrebpravo.ru':'crm_form_fhi3n','semya-yurist.ru':'crm_form_ep5fd'}


def site_pages(root,host):
    sitemap=root/'sitemap.xml'
    if sitemap.is_symlink() or not sitemap.is_file():
        raise ValueError('Cannot find verified sitemap: '+str(sitemap))
    tree=ET.parse(sitemap)
    raw=[node.text.strip() for node in tree.iter() if node.tag.split('}')[-1]=='loc' and node.text]
    if len(raw)!=SITE_COUNTS[host] or len(set(raw))!=len(raw):
        raise ValueError('Sitemap URL count differs from Playwright release baseline: '+host)
    files=[]
    for url in raw:
        parsed=urlparse(url)
        if parsed.scheme!='https' or parsed.netloc!=host or parsed.params or parsed.query or parsed.fragment:
            raise ValueError('Unsafe sitemap URL '+url)
        rel=parsed.path.lstrip('/') if parsed.path!='/' else 'index.html'
        if rel.startswith('/') or '..' in Path(rel).parts or '\\' in rel or not rel.endswith('.html'):
            raise ValueError('Unexpected sitemap page path '+rel)
        files.append(rel)
    return files


def patch(source, host):
    if host not in SITE_COUNTS:
        raise ValueError('Unsupported site')
    if SCRIPT_RE.search(source):
        return source
    if 'legal-help-toggle' in source:
        raise ValueError('Page has other assistant code; review before install')
    endings=list(CLOSE_BODY.finditer(source))
    if len(endings)!=1:
        raise ValueError('Expected one closing body')
    if 'oleg-consent-priority' in source:
        raise ValueError('Existing consent style marker requires manual review')
    at=endings[0].start()
    return source[:at]+CONSENT_PRIORITY+'\n'+SCRIPT+'\n'+source[at:]


def prepare(root_parent):
    edits={}
    for host in SITE_COUNTS:
        root=root_parent/host/'public_html'
        if not root.is_dir() or root.is_symlink():
            raise FileNotFoundError('Site root not verified '+str(root))
        root_real=root.resolve()
        asset=root/'assets'/'legal-assistant-v4.js'
        if asset.is_symlink() or not asset.is_file() or not asset.resolve().is_relative_to(root_real):
            raise ValueError('Verified live bot asset missing: '+str(asset))
        js=asset.read_text(encoding='utf-8')
        if FORMS[host] not in js or 'legal-help-toggle' not in js or 'crm_form_' not in js:
            raise ValueError('Live assistant is not connected to expected Bitrix24 form on '+host)
        if 'qwen' in js.lower():
            raise ValueError('Unexpected external Qwen integration in Oleg bot')
        for rel in site_pages(root,host):
            target=root/rel
            if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root_real):
                raise ValueError('Unsafe or missing sitemap page '+str(target))
            old=target.read_bytes()
            new=patch(old.decode('utf-8'),host).encode('utf-8')
            if target in edits:
                raise ValueError('Duplicate target '+str(target))
            edits[target]={'old':old,'new':new,'domain':host,'path':rel}
    return edits


def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--root-parent',default=str(Path.home()))
    ap.add_argument('--apply',action='store_true')
    args=ap.parse_args(argv)
    edits=prepare(Path(args.root_parent))
    changed=sum(x['new']!=x['old'] for x in edits.values())
    print(json.dumps({'mode':'apply' if args.apply else 'dry-run',
                      'sitemapPages':len(edits),'assistantMissing':changed},ensure_ascii=False))
    if args.apply:
        backup,count=apply_edits(edits,Path(args.root_parent))
        print(json.dumps({'status':'applied','changed':count,'backup':str(backup)},ensure_ascii=False))
    else:
        print('DRY_RUN_ONLY; no live files were changed')


if __name__=='__main__':
    try:main()
    except Exception as e:
        print('ABORTED:',e,file=sys.stderr)
        sys.exit(2)
