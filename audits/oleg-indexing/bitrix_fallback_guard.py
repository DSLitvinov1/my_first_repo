#!/usr/bin/env python3
"""Move the already-existing Bitrix24 direct-form fallback above iframe on both sites.

Tiny guarded patch to the *existing* legal-assistant-v4.js assets. Both hosts use
the same code but select distinct Bitrix24 forms using location.hostname.
No new analytics, third-party scripts, Qwen, or request submissions.
"""
import argparse
import json
import sys
from pathlib import Path
from metadata_guard import apply_edits

HOSTS={'potrebpravo.ru':'crm_form_fhi3n','semya-yurist.ru':'crm_form_ep5fd'}

FROM=[
 ("  fallback.className = 'legal-small';",
  "  fallback.className = 'legal-small';\n  fallback.style.cssText = 'background:#f1f8f5;border:1px solid #bed4c9;border-radius:9px;padding:10px 12px;margin:10px 0';"),
 ("  fallback.append(create('span', 'Если форма не отображается, '));",
  "  fallback.append(create('span', 'Если форма загружается долго, '));"),
 ("  const open = create('a', 'откройте её на отдельной странице');",
  "  const open = create('a', 'откройте форму Битрикс24 напрямую');"),
 ("  formStep.append(fallback);\n  panel.append(formStep);",
  "  formStep.insertBefore(fallback, frame);\n  panel.append(formStep);")
]

def patch(content):
    if 'formStep.insertBefore(fallback, frame);' in content:
        for _,new in FROM:
            if new not in content:
                raise ValueError('Existing fallback patch differs; manual review needed')
        return content
    result=content
    for before,after in FROM:
        if result.count(before)!=1:
            raise ValueError('Expected one known fallback segment; stop '+repr(before[:44]))
        result=result.replace(before,after)
    return result


def prepare(parent):
    edits={}
    for host,form_id in HOSTS.items():
        root=parent/host/'public_html'
        if not root.is_dir() or root.is_symlink():
            raise FileNotFoundError('Live hosting root missing '+str(root))
        asset=root/'assets'/'legal-assistant-v4.js'
        if asset.is_symlink() or not asset.is_file() or not asset.resolve().is_relative_to(root.resolve()):
            raise ValueError('Unsafe Bitrix asset '+str(asset))
        original=asset.read_bytes()
        text=original.decode('utf-8')
        if form_id not in text or 'legal-help-form-step' not in text or 'crm_form_' not in text:
            raise ValueError('Unexpected current Bot/Bitrix form '+host)
        if 'qwen' in text.lower():
            raise ValueError('Qwen should not be bound to Oleg sites')
        new=patch(text).encode('utf-8')
        edits[asset]={'old':original,'new':new,'domain':host,'path':'assets/legal-assistant-v4.js'}
    return edits


def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--root-parent',default=str(Path.home()))
    ap.add_argument('--apply',action='store_true')
    args=ap.parse_args(argv)
    changes=prepare(Path(args.root_parent))
    print(json.dumps({'mode':'apply' if args.apply else 'dry-run',
                       'assets':len(changes),'changes':sum(x['old']!=x['new'] for x in changes.values())}))
    if args.apply:
        backup,count=apply_edits(changes,Path(args.root_parent))
        print(json.dumps({'status':'applied','files':count,'backup':str(backup)},ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('ABORTED:',e,file=sys.stderr);sys.exit(2)
