#!/usr/bin/env python3
"""V9: build one combined release OFFLINE from reviewed public sources only.

Never connects to Timeweb as a server admin, never sends CRM submissions,
and never deploys. Source locks and plan gates fail closed.
"""
import argparse
import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path

from assistant_sitewide_stage import (
    DOMAINS, ASSET_SHA256, build as build_assistant_baseline,
    fetch_url,
)
from deploy_oleg_seo import build_full_release, verify_public_lock

HERE = Path(__file__).resolve().parent
PLANS = {
    'meta': 'METADATA_PROPOSALS_20261115.json',
    'links': 'CASE_RELATED_LINKS_20261115.json',
    'lock': 'ASSISTANT_COVERAGE_SOURCE_LOCK_20261116.json',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def assemble(out):
    if out.exists():
        raise FileExistsError('Refuse to overwrite an existing staged release: '+str(out))
    out.mkdir(mode=0o700, parents=True)
    assistant_stage = out / 'assistant-baseline'
    lock = json.loads((HERE / PLANS['lock']).read_text(encoding='utf-8'))
    baseline = build_assistant_baseline(lock, assistant_stage)
    if baseline['pages_total'] != 41 or baseline['pages_changed'] != 39:
        raise ValueError('Unexpected baseline coverage; STOP')

    source_root = out / 'verified-public-source'
    for host in DOMAINS:
        public_root = source_root / host / 'public_html'
        public_root.mkdir(parents=True)
        sitemap = fetch_url('https://' + host + '/sitemap.xml', 250000)
        (public_root / 'sitemap.xml').write_bytes(sitemap)
        bot = fetch_url('https://' + host + '/assets/legal-assistant-v4.js', 50000)
        if sha(bot) != ASSET_SHA256:
            raise ValueError('Assistant asset differs from reviewed public source; STOP '+host)
        asset_file = public_root / 'assets' / 'legal-assistant-v4.js'
        asset_file.parent.mkdir(parents=True)
        asset_file.write_bytes(bot)

    for item in baseline['manifest']:
        host = item['site']
        rel = item['path']
        from_stage = assistant_stage / '.originals' / host / rel
        source = from_stage.read_bytes()
        if sha(source) != item['old_sha256']:
            raise ValueError('Baseline source digest mismatch; STOP '+host+'/'+rel)
        dest = source_root / host / 'public_html' / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(source)

    # Diagnose the exact script URL form without copying client data or HTML.
    from lead_assistant_guard import SCRIPT_RE
    import re
    for host in DOMAINS:
        homepage = (source_root / host / 'public_html' / 'index.html').read_text(encoding='utf-8')
        urls = re.findall(r'<script\\b[^>]*\\bsrc\\s*=\\s*["\\x27]([^"\\x27]*legal-assistant-v4\\.js[^"\\x27]*)["\\x27]', homepage, flags=re.I)
        print('OLEG_V9_PUBLIC_HOME_ASSISTANT_SCRIPT=' + json.dumps({
            'host': host, 'srcs': urls, 'strictRecognized': bool(SCRIPT_RE.search(homepage)), 'mentions': homepage.count('legal-assistant-v4.js'), 'publicContext': homepage[max(0, homepage.find('legal-assistant-v4.js')-120):homepage.find('legal-assistant-v4.js')+140].replace(chr(10),' '), 'hasToggleMarkup': 'legal-help-toggle' in homepage
        }, ensure_ascii=False))

    metadata = json.loads((HERE / PLANS['meta']).read_text(encoding='utf-8'))
    links = json.loads((HERE / PLANS['links']).read_text(encoding='utf-8'))
    changes, overlaps, missing = build_full_release(metadata, links, source_root)
    if len(changes) != 43 or overlaps != 9 or missing != 39:
        raise ValueError(f'Combined plan differs from expected: files={len(changes)}, overlap={overlaps}, missing={missing}; STOP')
    verified = verify_public_lock(changes, lock)
    if verified != 41:
        raise ValueError('41 public-source lock pages missing; STOP')

    release_root = out / 'unified-release'
    manifest = []
    for target, item in sorted(changes.items(), key=lambda p: (p[1]['domain'], p[1]['path'])):
        if not target.is_file() or target.read_bytes() != item['old']:
            raise ValueError('Source drift during release assembly; STOP '+str(target))
        destination = release_root / item['domain'] / 'public_html' / item['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(item['new'])
        if sha(destination.read_bytes()) != sha(item['new']):
            raise IOError('Bad offline release readback; STOP '+str(destination))
        manifest.append({
            'host': item['domain'], 'path': item['path'],
            'original_sha256': sha(item['old']), 'proposed_sha256': sha(item['new']),
            'changed': item['old'] != item['new'],
        })
    if len(manifest) != 43 or sum(x['path'].endswith('.html') for x in manifest) != 41:
        raise ValueError('Manifest incomplete')
    changed_html = sum(x['changed'] for x in manifest if x['path'].endswith('.html'))
    changed_js = sum(x['changed'] for x in manifest if x['path'].endswith('.js'))
    if changed_html != 39 or changed_js not in (0, 1, 2):
        raise ValueError(
            f'Unexpected staged change count: HTML={changed_html}, JS={changed_js}; STOP'
        )

    # This archive contains reviewed PUBLIC source files ONLY. It is NOT a Timeweb backup.
    archive = out / 'original-public-source-43-files.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for item in manifest:
            original = source_root / item['host'] / 'public_html' / item['path']
            z.write(original, item['host'] + '/public_html/' + item['path'])
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None or len(z.namelist()) != 43:
            raise ValueError('Public source archive integrity failure')
        for item in manifest:
            file_path = item['host'] + '/public_html/' + item['path']
            if sha(z.read(file_path)) != item['original_sha256']:
                raise ValueError('Public source archive byte mismatch: '+file_path)

    report = {
        'status': 'OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT',
        'production_modified': False, 'timeweb_backup_created': False,
        'bitrix_leads_created': 0, 'real_crm_verified': False,
        'source': 'read-only publicly served HTML/JS, NOT verified Timeweb filesystem',
        'release_dir': str(release_root),
        'public_source_archive': str(archive),
        'verified_html_sha_locks': verified,
        'html_pages': 41, 'js_assets': 2,
        'seo_targets': 24, 'assistant_inner_page_insertions': missing,
        'files_changed': changed_html + changed_js,
        'html_files_changed': changed_html, 'js_assets_changed': changed_js,
        'overlapping_metadata_case_targets': overlaps,
        'source_and_output_sha_readback': True,
        'manifest': manifest,
    }
    report_path = out / 'unified-manifest.json'
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print('OLEG_V9_UNIFIED_STAGE=' + json.dumps({
        k: v for k, v in report.items() if k not in {'manifest', 'public_source_archive', 'release_dir'}
    }, ensure_ascii=False))
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()
    assemble(args.out)
