#!/usr/bin/env python3
"""Guarded, dry-run-by-default metadata edits for Oleg's two static websites.

Requires META proposals from a just-completed public crawl. Does not run automatically.
No search engine submissions, no hosting login, no changes to robots/sitemap or privacy pages.
"""
import argparse
import hashlib
import html
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

TITLE = re.compile(r'(?is)(<title\b[^>]*>)(.*?)(</title>)')
META = re.compile(r'(?is)<meta\b[^>]*>')
DESC_NAME = re.compile(r'''(?i)\bname\s*=\s*(["'])description\1''')
CONTENT = re.compile(r'''(?is)(\bcontent\s*=\s*)(["'])(.*?)\2''')

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def replace_once(source, kind, expected, replacement, sitefile):
    if replacement is None:
        return source
    if kind == 'title':
        found = list(TITLE.finditer(source))
        if len(found) != 1:
            raise ValueError(f'{sitefile}: expected exactly one <title>, got {len(found)}')
        match, segment = found[0], 2
        old = html.unescape(match.group(segment).strip())
        if old == replacement:
            return source
        if old != expected:
            raise ValueError(f'{sitefile}: title changed since audit; STOP')
        return source[:match.start(segment)] + html.escape(replacement) + source[match.end(segment):]
    found = [m for m in META.finditer(source) if DESC_NAME.search(m.group(0))]
    if len(found) != 1:
        raise ValueError(f'{sitefile}: expected exactly one description meta, got {len(found)}')
    match = found[0]
    attr = CONTENT.search(match.group(0))
    if not attr:
        raise ValueError(f'{sitefile}: description content attribute missing')
    old = html.unescape(attr.group(3).strip())
    if old == replacement:
        return source
    if old != expected:
        raise ValueError(f'{sitefile}: description changed since audit; STOP')
    newtag = match.group(0)[:attr.start(3)] + html.escape(replacement, quote=True) + match.group(0)[attr.end(3):]
    return source[:match.start()] + newtag + source[match.end():]

def prepare(plan, root_parent):
    edits = {}
    for site in plan['sites']:
        domain = site['host']
        if domain not in ('potrebpravo.ru', 'semya-yurist.ru'):
            raise ValueError('Unexpected domain')
        root = root_parent / domain / 'public_html'
        if not root.is_dir():
            raise FileNotFoundError(f'Hosting directory missing: {root}')
        root_real = root.resolve()
        for item in site['changes']:
            path = item['path']
            if path.startswith('/') or '..' in Path(path).parts or not path.endswith('.html'):
                raise ValueError(f'Unsafe relative path: {path}')
            target = root / path
            if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root_real):
                raise ValueError(f'Unsafe/missing file: {target}')
            if target in edits:
                raise ValueError(f'Duplicate target: {target}')
            old = target.read_bytes()
            text = old.decode('utf-8')
            for kind in ('title','description'):
                if kind in item['proposed']:
                    text = replace_once(text,kind,item['expected'].get(kind),item['proposed'][kind],target)
            new = text.encode('utf-8')
            edits[target] = {'old':old,'new':new,'domain':domain,'path':path}
    return edits

def apply_edits(edits, root_parent):
    stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    backup = root_parent / f'.oleg-seo-metadata-backup-{stamp}'
    if backup.exists():
        raise FileExistsError(backup)
    # Refuse stale prepared edits before creating any backup or modifying pages.
    for target, info in edits.items():
        if target.is_symlink() or not target.is_file() or target.read_bytes() != info['old']:
            raise ValueError(f'{target}: source changed since preflight; STOP')
    backup.mkdir(mode=0o700)
    manifest,changed = [],[]
    original_modes = {target: target.stat().st_mode for target in edits}
    try:
        for target, info in edits.items():
            archive = backup / info['domain'] / info['path']
            archive.parent.mkdir(parents=True,exist_ok=True)
            archive.write_bytes(info['old'])
            # A failed or corrupted server-side backup must halt BEFORE any live edits.
            if archive.read_bytes() != info['old'] or sha256(archive.read_bytes()) != sha256(info['old']):
                raise IOError(f'{archive}: backup write verification failed; STOP')
            manifest.append({'target':str(target),'before_sha256':sha256(info['old']),'after_sha256':sha256(info['new']),'changed':info['old']!=info['new']})
        manifest_path = backup / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding='utf-8')
        if json.loads(manifest_path.read_text(encoding='utf-8')) != manifest:
            raise IOError('Backup manifest verification failed; STOP')
        for target, info in edits.items():
            if info['old'] == info['new']:
                continue
            # One more drift check immediately before replace; prevent overwriting a concurrent edit.
            if target.is_symlink() or target.read_bytes() != info['old']:
                raise ValueError(f'{target}: source changed before write; STOP')
            tmp = target.with_name(target.name + '.oleg-tmp')
            if tmp.exists():
                raise FileExistsError(tmp)
            try:
                tmp.write_bytes(info['new'])
                os.chmod(tmp,target.stat().st_mode)
                os.replace(tmp,target)
                changed.append(target)
                if target.read_bytes() != info['new']:
                    raise IOError(f'{target}: post-write readback differs; rollback required')
            finally:
                if tmp.exists():
                    tmp.unlink()
    except BaseException:
        for target in reversed(changed):
            original = edits[target]['old']
            tmp = target.with_name(target.name+'.oleg-rollback')
            tmp.write_bytes(original)
            os.chmod(tmp, original_modes[target])
            os.replace(tmp,target)
            if target.read_bytes() != original:
                raise IOError(f'{target}: rollback verification failed')
        raise
    return backup, len(changed)

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--plan', default=str(Path(__file__).with_name('METADATA_PROPOSALS_20261115.json')))
    ap.add_argument('--root-parent', default=str(Path.home()))
    ap.add_argument('--apply', action='store_true',help='Explicitly publish only after backup, review and authorized access')
    args=ap.parse_args(argv)
    plan=json.loads(Path(args.plan).read_text(encoding='utf-8'))
    if plan.get('status')!='REVIEW_ONLY_NOT_DEPLOYED':
        raise ValueError('Unexpected plan status')
    edits=prepare(plan,Path(args.root_parent))
    proposed=sum(1 for item in edits.values() if item['old']!=item['new'])
    print(json.dumps({'mode':'apply' if args.apply else 'dry-run','files_checked':len(edits),'files_to_change':proposed},ensure_ascii=False))
    if args.apply:
        backup,changed=apply_edits(edits,Path(args.root_parent))
        print(json.dumps({'changed':changed,'backup':str(backup)},ensure_ascii=False))
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except Exception as err:
        print('ABORTED:',err,file=sys.stderr)
        sys.exit(2)
