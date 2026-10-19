"""Isolated negative verification of installed CORE/HOST/provider source manifest.

Never executes copied code or registers services.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

def run(app,components):
    sys.path.insert(0,str(app))
    from installed_integrity import verify,IntegrityDenied
    good=verify(components)
    if good["files_verified"]!=16 or good["live_execution_allowed"] is not False:
        raise AssertionError("Invalid pinned installed-code trust status")
    with tempfile.TemporaryDirectory(prefix="nf-installed-integrity-") as tmp:
        root=Path(tmp)
        def clone():
            path=root/("trial"+str(len(list(root.iterdir()))))
            shutil.copytree(components,path)
            return path
        corrupted=clone()
        with (corrupted/"core"/"one_task_core.py").open("ab") as h:
            h.write(b"tampered")
        candidates=[corrupted]
        for edit in ("queue_permission","commit","duplicate","manifest_hash"):
            path=clone()
            doc=json.loads((path/"manifest.json").read_text(encoding="utf-8"))
            if edit=="queue_permission":
                doc["core_queue_wired"]=True
            if edit=="commit":
                doc["entries"][0]["source_commit"]="a"*40
            if edit=="duplicate":
                doc["entries"][1]=doc["entries"][0]
            if edit=="manifest_hash":
                doc["entries"][0]["git_blob"]="f"*40
            (path/"manifest.json").write_text(
                json.dumps(doc,ensure_ascii=False),encoding="utf-8")
            candidates.append(path)
        for path in candidates:
            try:
                verify(path)
            except IntegrityDenied:
                continue
            raise AssertionError("Untrusted installed component accepted")
    print("NF_INSTALLED_COMPONENT_TAMPER_AND_PRIVILEGE_ESCALATION=DENIED")
    print("NF_INSTALLED_COMPONENT_INTEGRITY=PINNED_16_NO_LIVE")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--app",type=Path,required=True)
    p.add_argument("--components",type=Path,required=True)
    args=p.parse_args()
    run(args.app,args.components)
if __name__=="__main__":
    main()
