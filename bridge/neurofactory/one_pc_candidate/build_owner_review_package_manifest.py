"""Create inert OWNER review-only per-user installed-file checksum inventory.

Staging manifest only. Its SHA256 MUST be independently delivered to the
operator from an authenticated CI job. Self-consistency is not independent
review or code-signing. It never authorizes CORE/HOST or downloads models.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import stat

SCHEMA="nf.owner.local_review_all_installed_files.v1"
APPROVED_ROOTS=frozenset(("runtime","app","ui","components"))
EXTRA={"owner_pc_readonly_acceptance.ps1":"acceptance/owner_pc_readonly_acceptance.ps1",
       "start_neurofactory.cmd":"start_neurofactory.cmd","README.txt":"README.txt"}
SHA40=re.compile(r"[a-f0-9]{40}\Z")

class SourceStageDenied(ValueError):
    pass

def build_manifest(*,stage:Path,source_sha40:str):
    if (not isinstance(stage,Path) or not stage.is_absolute() or stage.is_symlink()
        or not stage.is_dir() or type(source_sha40) is not str
        or not SHA40.fullmatch(source_sha40)):
        raise SourceStageDenied("Untrusted or nonimmutable source staging")
    if (stage/"package-integrity.json").exists():
        raise SourceStageDenied("Package manifest already present; no overwriting")
    for part in APPROVED_ROOTS:
        folder=stage/part
        if not folder.is_dir() or folder.is_symlink():
            raise SourceStageDenied("Stage source folder missing or reparse")
    found={}
    for file in sorted(stage.rglob("*")):
        if file.is_symlink():
            raise SourceStageDenied("Stage tree contains linked path")
        if file.is_dir():
            continue
        if not file.is_file() or not stat.S_ISREG(file.lstat().st_mode):
            raise SourceStageDenied("Non-file item in stage")
        rel=file.relative_to(stage).as_posix()
        chunks=rel.split("/")
        if (chunks[0] not in APPROVED_ROOTS and
            rel not in EXTRA):
            raise SourceStageDenied("Undeclared file in staged executable source")
        if len(chunks)>5 or any(c in ("",".","..") for c in chunks):
            raise SourceStageDenied("Invalid nested file source")
        install=EXTRA.get(rel,rel)
        if install.lower() in found:
            raise SourceStageDenied("Case-insensitive collision in Windows destination")
        blob=file.read_bytes()
        if len(blob)==0 or len(blob)>20_000_000:
            raise SourceStageDenied("Source out of bounded size")
        found[install.lower()]={"path":install,"bytes":len(blob),
                                "sha256":sha256(blob).hexdigest()}
    if len(found)<35 or len(found)>90 or (
        len([p for p in found if p.startswith("components/")])<16
    ):
        raise SourceStageDenied("Source complement incomplete")
    payload={
        "schema":SCHEMA,"source_sha40":source_sha40,
        "status":"INERT_REVIEW_ONLY_NEVER_RELEASE_AUTHORITY",
        "production_signed":False,"host_effects_allowed":False,
        "files":[found[k] for k in sorted(found)],
    }
    raw=(json.dumps(payload,sort_keys=True,separators=(",",":"),
                    ensure_ascii=True)+"\n").encode("ascii")
    path=stage/"package-integrity.json"
    path.write_bytes(raw)
    return {"package_manifest_sha256":sha256(raw).hexdigest(),
            "file_count":len(found),
            "source_sha40":source_sha40,"status":"INERT_REVIEW_STAGED_NO_PROD"}

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--stage",type=Path,required=True)
    parser.add_argument("--source-sha40",required=True)
    args=parser.parse_args()
    print(json.dumps(build_manifest(stage=args.stage,
                    source_sha40=args.source_sha40),sort_keys=True))
