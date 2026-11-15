#!/usr/bin/env python3
"""Safely prepare and (only when requested) apply all staged SEO changes as one batch.

This deployer never connects to hosting by itself. It is run inside the authorized
hosting terminal against *verified* live site roots. No Bitrix24, tracking, or
search-console settings are modified.
"""
import argparse
import json
import sys
from pathlib import Path

from metadata_guard import prepare as prepare_meta, replace_once, apply_edits
from case_links_guard import prepare as prepare_links

SITES = {'potrebpravo.ru', 'semya-yurist.ru'}
DEFAULT_META = 'METADATA_PROPOSALS_20261115.json'
DEFAULT_LINKS = 'CASE_RELATED_LINKS_20261115.json'


def build_release(metadata_plan, links_plan, root_parent):
    if metadata_plan.get('status') != 'REVIEW_ONLY_NOT_DEPLOYED':
        raise ValueError('Unexpected metadata plan status')
    if links_plan.get('status') != 'REVIEW_ONLY_NOT_DEPLOYED':
        raise ValueError('Unexpected link plan status')
    metadata_sites={site['host'] for site in metadata_plan['sites']}
    links_sites={item['host'] for item in links_plan['changes']}
    if metadata_sites != SITES or links_sites != SITES:
        raise ValueError('Release site allowlist differs')
    if sum(len(site['changes']) for site in metadata_plan['sites']) != 20:
        raise ValueError('Expected exactly 20 metadata changes')
    if len(links_plan['changes']) != 13:
        raise ValueError('Expected exactly 13 case-link changes')

    metas = prepare_meta(metadata_plan, root_parent)
    links = prepare_links(links_plan, root_parent)
    items={}
    for site in metadata_plan['sites']:
        for meta in site['changes']:
            key=(site['host'],meta['path'])
            if key in items:
                raise ValueError('Duplicate metadata plan path '+repr(key))
            items[key]=meta
    combined={target:dict(info) for target,info in metas.items()}
    overlaps=0
    for target,info in links.items():
        if target not in combined:
            combined[target]=dict(info)
            continue
        old_info=combined[target]
        if old_info['old']!=info['old']:
            raise ValueError('Source drift between metadata and link plans '+str(target))
        if old_info['domain']!=info['domain'] or old_info['path']!=info['path']:
            raise ValueError('Mismatched metadata and links for '+str(target))
        meta=items[(info['domain'],info['path'])]
        output=info['new'].decode('utf-8')
        for field in ('title','description'):
            if field in meta['proposed']:
                output=replace_once(output,field,meta['expected'].get(field),meta['proposed'][field],target)
        old_info['new']=output.encode('utf-8')
        overlaps+=1
    if len(combined)!=33-overlaps:
        raise ValueError('Unexpected number of unique release targets')
    return combined,overlaps


def main(argv=None):
    ap=argparse.ArgumentParser()
    here=Path(__file__).parent
    ap.add_argument('--metadata-plan',default=str(here/DEFAULT_META))
    ap.add_argument('--links-plan',default=str(here/DEFAULT_LINKS))
    ap.add_argument('--root-parent',default=str(Path.home()))
    ap.add_argument('--apply',action='store_true',help='Perform guarded and backed-up publication')
    args=ap.parse_args(argv)
    meta=json.loads(Path(args.metadata_plan).read_text(encoding='utf-8'))
    links=json.loads(Path(args.links_plan).read_text(encoding='utf-8'))
    root=Path(args.root_parent)
    changes,overlaps=build_release(meta,links,root)
    summary={'mode':'apply' if args.apply else 'dry-run',
             'root':str(root),'uniqueFiles':len(changes),
             'overlappingFiles':overlaps,
             'filesWithRealChanges':sum(x['new']!=x['old'] for x in changes.values())}
    print(json.dumps(summary,ensure_ascii=False))
    if args.apply:
        backup,count=apply_edits(changes,root)
        print(json.dumps({'status':'applied','changed':count,'backup':str(backup)},ensure_ascii=False))
    else:
        print('DRY_RUN_ONLY: no site files were modified')


if __name__=='__main__':
    try:main()
    except Exception as e:
        print('ABORTED:',str(e),file=sys.stderr)
        sys.exit(2)
