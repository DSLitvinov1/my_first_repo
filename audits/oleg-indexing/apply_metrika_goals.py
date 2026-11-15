#!/usr/bin/env python3
"""Safely append Oleg's opt-in Metrika goals to two verified live analytics assets.

Local hosting operation, not a remote deploy. Dry-run by default. Refuses
unknown roots, source drift, suspicious files, and mismatched counters. The user
must arrange authorized hosting file access; this script never reads credentials.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from metadata_guard import apply_edits

COUNTERS = {'potrebpravo.ru': '114249897', 'semya-yurist.ru': '114251443'}
ANALYTICS = Path('assets/oleg-analytics-v1.js')
EXTENSION_FILE = Path(__file__).with_name('oleg-metrika-goals-v1.js')
MARKER = '__olegMetrikaIntentGoalsV1'

def digest(x):
    return hashlib.sha256(x).hexdigest()

def prepare(root_parent: Path, extension: str):
    if MARKER not in extension or 'oleg_lead_success' not in extension:
        raise ValueError('Goal extension safety markers missing')
    if extension.count('addEventListener') < 1:
        raise ValueError('Goal extension incomplete')

    edits = {}
    for host, counter in COUNTERS.items():
        document_root = root_parent / host / 'public_html'
        if document_root.is_symlink() or not document_root.is_dir():
            raise FileNotFoundError('Hosting document root missing or unsafe: ' + str(document_root))
        root = document_root.resolve(strict=True)
        target = document_root / ANALYTICS
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
            raise ValueError('Missing/unsafe analytics asset: ' + str(target))
        old = target.read_bytes()
        if len(old) < 300 or len(old) > 75000:
            raise ValueError('Unexpected original analytics asset length for ' + host)
        try:
            text = old.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError('Non-UTF8 current analytics asset') from e
        if counter not in text or 'oleg.analytics.choice.v1' not in text or 'webvisor' not in text:
            raise ValueError('Current live file does not match the independently verified counter/consent implementation')
        for other, number in COUNTERS.items():
            if other != host and number in text:
                raise ValueError('Cross-counter leakage in asset ' + host)
        if MARKER in text:
            if text.endswith('\n' + extension.rstrip() + '\n'):
                new = old
            else:
                raise ValueError('Existing goal extension differs: manual inspection required')
        else:
            if '<script' in text.lower():
                raise ValueError('Unexpected HTML code in JavaScript asset')
            new = (text.rstrip() + '\n\n' + extension.rstrip() + '\n').encode('utf-8')
        edits[target] = {'old': old, 'new': new, 'domain': host, 'path': str(ANALYTICS)}
    return edits

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root-parent', required=True, help='Authorized parent directory containing <domain>/public_html for both sites')
    parser.add_argument('--apply', action='store_true', help='Explicitly apply only after backup and exact-source checks')
    args = parser.parse_args()
    parent = Path(args.root_parent).resolve(strict=True)
    extension = EXTENSION_FILE.read_text(encoding='utf-8')
    edits = prepare(parent, extension)
    changed = sum(item['old'] != item['new'] for item in edits.values())
    result = {'mode': 'apply' if args.apply else 'dry-run', 'filesChecked': len(edits),
              'filesToChange': changed,
              'expectedAssets': [{'domain': v['domain'], 'path': v['path'],
                                  'currentSha256': digest(v['old']),
                                  'updatedSha256': digest(v['new'])} for v in edits.values()]}
    if args.apply:
        backup, count = apply_edits(edits, parent)
        result['backupDirectory'] = str(backup)
        result['filesChanged'] = count
        for target, item in edits.items():
            if target.read_bytes() != item['new']:
                raise ValueError('Post-write mismatch: ' + str(target))
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ABORTED:', exc, file=sys.stderr)
        sys.exit(2)
