#!/usr/bin/env python3
"""Review-first insertion of relevant internal links in 13 verified court-case pages.

No legal facts are inserted. Dry run by default. Requires existing live files and
refuses source drift, cross-domain links, symlinks, or ambiguous markup.
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from metadata_guard import apply_edits

TITLE = re.compile(r'(?is)<title\b[^>]*>(.*?)</title>')
ARTICLE = re.compile(r'(?is)<article\b[^>]*\bclass\s*=\s*(["\'])(.*?)\1[^>]*>')
CLOSE_ARTICLE = re.compile(r'(?is)</article\s*>')
ALLOWED_HOSTS = frozenset(('potrebpravo.ru', 'semya-yurist.ru'))
MUST_EXIST = ('<main', '</main>')
MARKER_PREFIX = "oleg-related-"


def normalize(value):
    return re.sub(r'\s+', ' ', html.unescape(value)).strip()


def validate_link(host, item):
    href = item['href']
    label = normalize(item['label'])
    p = urlsplit(href)
    if not href.startswith('/') or href.startswith('//') or p.scheme or p.netloc or p.query or p.fragment:
        raise ValueError('Invalid internal link '+repr(href))
    if '..' in Path(p.path).parts or p.path == '/':
        raise ValueError('Unsafe or meaningless related link')
    if not label or len(label) > 120 or any(c in label for c in '<>'):
        raise ValueError('Invalid related anchor')
    return p.path, label


def make_section(item):
    host=item['host']
    slug=Path(item['path']).stem
    section_id=MARKER_PREFIX+slug
    links = []
    for link in item['related']:
        href, label = validate_link(host, link)
        links.append((href,label))
    if not (1 <= len(links) <= 3) or len(set(href for href,_ in links)) != len(links):
        raise ValueError('Expected 1–3 unique internal links')
    anchor_id=section_id+'-title'
    lis='\n'.join(
        f'        <li><a href="{html.escape(href,quote=True)}">{html.escape(label)}</a></li>'
        for href,label in links
    )
    section=(
        f'\n    <nav class="article-related" id="{section_id}" aria-labelledby="{anchor_id}">\n'
        f'      <h2 id="{anchor_id}">Смежные правовые вопросы</h2>\n'
        f'      <ul>\n{lis}\n      </ul>\n'
        f'    </nav>\n'
    )
    return section_id, section


def transform(source, item):
    if item['host'] not in ALLOWED_HOSTS:
        raise ValueError('Invalid host')
    path=item['path']
    if path.startswith('/') or '\\' in path or '..' in Path(path).parts or not path.startswith('practice/cases/') or not path.endswith('.html'):
        raise ValueError('Unsafe case path')
    expected_url='https://'+item['host']+'/'+path
    if item['url'] != expected_url:
        raise ValueError('URL must match the exact case file')
    titles=list(TITLE.finditer(source))
    if len(titles)!=1 or normalize(titles[0].group(1))!=normalize(item['expectedTitle']):
        raise ValueError('Page title changed since Playwright audit')
    if any(s.lower() not in source.lower() for s in MUST_EXIST):
        raise ValueError('Missing main container')
    opening=list(ARTICLE.finditer(source))
    closing=list(CLOSE_ARTICLE.finditer(source))
    if len(opening)!=1 or len(closing)!=1 or 'article' not in opening[0].group(2).split():
        raise ValueError('Expected one <article class="article">')
    if closing[0].start()<=opening[0].end():
        raise ValueError('Misordered article')
    section_id,section=make_section(item)
    if f'id="{section_id}"' in source:
        if section.strip() in source:
            return source
        raise ValueError('Existing related-links marker differs; manual review required')
    for link in item['related']:
        href,_=validate_link(item['host'],link)
        # Keep the page clean; if an intended link is already present, refuse
        # rather than duplicating a navigation path in new link blocks.
        if re.search(r'\bhref\s*=\s*(["\'])'+re.escape(href)+r'\1',source):
            raise ValueError('Link already present; review link plan '+href)
    return source[:closing[0].start()]+section+source[closing[0].start():]


def prepare(plan,parent):
    if plan.get('status')!='REVIEW_ONLY_NOT_DEPLOYED':
        raise ValueError('Unexpected plan status')
    edits={}
    for item in plan['changes']:
        host=item['host']
        if host not in ALLOWED_HOSTS:
            raise ValueError('Unexpected host')
        root=parent/host/'public_html'
        if not root.is_dir() or root.is_symlink():
            raise FileNotFoundError('Cannot find authorized real site root '+str(root))
        real=root.resolve()
        rel=item['path']
        if rel.startswith('/') or '\\' in rel or '..' in Path(rel).parts:
            raise ValueError('Unsafe relative path')
        target=root/rel
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(real):
            raise ValueError('Unsafe or missing file '+str(target))
        if target in edits:
            raise ValueError('Duplicate case path')
        old=target.read_bytes()
        new=transform(old.decode('utf-8'),item).encode('utf-8')
        edits[target]={'old':old,'new':new,'domain':host,'path':rel}
    return edits


def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--plan',default=str(Path(__file__).with_name('CASE_RELATED_LINKS_20261115.json')))
    ap.add_argument('--root-parent',default=str(Path.home()))
    ap.add_argument('--apply',action='store_true')
    args=ap.parse_args(argv)
    plan=json.loads(Path(args.plan).read_text(encoding='utf-8'))
    edits=prepare(plan,Path(args.root_parent))
    changed=sum(i['old']!=i['new'] for i in edits.values())
    print(json.dumps({'mode':'apply' if args.apply else 'dry-run',
                      'filesChecked':len(edits),'plannedChanges':changed},ensure_ascii=False))
    if args.apply:
        backup,count=apply_edits(edits,Path(args.root_parent))
        print(json.dumps({'backup':str(backup),'filesChanged':count},ensure_ascii=False))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('ABORTED:',exc,file=sys.stderr)
        sys.exit(2)
