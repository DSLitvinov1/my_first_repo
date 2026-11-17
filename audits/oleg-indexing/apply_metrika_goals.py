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
FALLBACK_FILE = Path(__file__).with_name('oleg-crm-backup-links-v1.js')

def extension_contents() -> str:
    goals = EXTENSION_FILE.read_text(encoding='utf-8').rstrip()
    fallback = FALLBACK_FILE.read_text(encoding='utf-8').rstrip()
    if '__olegCrmBackupLinksV1' not in fallback or 'https://b24-s2dosa.bitrix24site.ru/' not in fallback:
        raise ValueError('Sitewide CRM fallback script source is missing required markers')
    # The fallback changes only visitor-visible links, NEVER form data or real
    # CRM submissions. Combining into the existing HTML-loaded JS allows one
    # atomic, cache-busted release of 2 scripts + 45 HTML references.
    return goals + '\n\n' + fallback + '\n'

MARKER = '__olegMetrikaIntentGoalsV1'
# Versions and the page counts were verified with Playwright from both live sites.
BASELINE_VERSIONS = {'potrebpravo.ru': 'f96b5eb2', 'semya-yurist.ru': '173e16dd'}
PAGE_COUNTS = {'potrebpravo.ru': 25, 'semya-yurist.ru': 20}
SCRIPT_URL_PATTERN = re.compile(r'((?:/|(?:\.\./)*)assets/oleg-analytics-v1\.js\?v=)([A-Za-z0-9._-]+)')

def digest(x):
    return hashlib.sha256(x).hexdigest()

def prepare(root_parent: Path, extension: str, expected_counts=None):
    expected_counts = PAGE_COUNTS if expected_counts is None else expected_counts
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
        if MARKER in text:
            # The appended, reviewed extension deliberately contains both
            # host->counter mappings. Recognize ONLY an exact previous append.
            if text.endswith('\n' + extension.rstrip() + '\n'):
                new = old
            else:
                raise ValueError('Existing goal extension differs: manual inspection required')
        else:
            for other, number in COUNTERS.items():
                if other != host and number in text:
                    raise ValueError('Cross-counter leakage in original asset ' + host)
            if '<script' in text.lower():
                raise ValueError('Unexpected HTML code in JavaScript asset')
            new = (text.rstrip() + '\n\n' + extension.rstrip() + '\n').encode('utf-8')
        edits[target] = {'old': old, 'new': new, 'domain': host, 'path': str(ANALYTICS)}
        # A static cache-busting query is present on every live HTML page.
        # Update it atomically along with the JavaScript; otherwise browser
        # caches can retain the previous file indefinitely.
        old_version = BASELINE_VERSIONS[host]
        new_version = digest(new)[:8]
        referenced = 0
        for html_path in document_root.rglob('*.html'):
            if html_path.is_symlink() or not html_path.is_file() or not html_path.resolve().is_relative_to(root):
                raise ValueError('Unsafe symlink/HTML path in hosting root: ' + str(html_path))
            html_bytes = html_path.read_bytes()
            try:
                html_source = html_bytes.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise ValueError('Non-UTF8 HTML page: ' + str(html_path)) from exc
            found = list(SCRIPT_URL_PATTERN.finditer(html_source))
            if not found:
                continue
            if len(found) != 1:
                raise ValueError('Multiple analytics script URLs found in page ' + str(html_path))
            if found[0].group(2) not in (old_version, new_version):
                raise ValueError('Analytics script version drift in ' + str(html_path))
            referenced += 1
            patched = SCRIPT_URL_PATTERN.sub(lambda m: m.group(1) + new_version, html_source)
            relative = html_path.relative_to(document_root)
            edits[html_path] = {
                'old': html_bytes,
                'new': patched.encode('utf-8'),
                'domain': host,
                'path': str(relative)
            }
        if referenced != expected_counts[host]:
            raise ValueError(f'Unexpected number of instrumented pages for {host}: {referenced}; expected {expected_counts[host]}. STOP')
    return edits

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root-parent', required=True, help='Authorized parent directory containing <domain>/public_html for both sites')
    parser.add_argument('--apply', action='store_true', help='Explicitly apply only after backup and exact-source checks')
    args = parser.parse_args()
    parent = Path(args.root_parent).resolve(strict=True)
    extension = extension_contents()
    edits = prepare(parent, extension)
    changed = sum(item['old'] != item['new'] for item in edits.values())
    result = {'mode': 'apply' if args.apply else 'dry-run', 'filesChecked': len(edits),
              'filesToChange': changed,
              'verifiedFiles': [{'domain': v['domain'], 'path': v['path'],
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
