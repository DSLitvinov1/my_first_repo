"""Verify packaged CORE/HOST/PROVIDERS/COORDINATOR bytes, never enable them.

This is a consistency diagnostic in a per-user install directory, not a
cryptographic authorization primitive: the manifest and files share ownership.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

SHA40=re.compile(r"[a-f0-9]{40}\Z")
SHA64=re.compile(r"[a-f0-9]{64}\Z")
ROLES={"core","host_ci_only","providers","coordinator"}
FLAGS=("release_approved","host_service_installed","core_queue_dispatch_enabled",
       "model_inference_enabled","owner_approval_present",
       "independent_review_passed")
EXPECTED_COUNTS={"core":1,"host_ci_only":4,"providers":6,"coordinator":3}


def verify(component_dir:Path):
    base=Path(component_dir)
    if not base.is_absolute() or base.is_symlink() or not base.is_dir():
        raise ValueError("Missing or linked component directory")
    manifest_file=base/"manifest.json"
    if not manifest_file.is_file() or manifest_file.is_symlink() or manifest_file.stat().st_size>12000:
        raise ValueError("Invalid component manifest")
    manifest=json.loads(manifest_file.read_text(encoding="utf-8"))
    required={"schema","integration_source_commit","host_is_ci_only",
              "files",*FLAGS}
    if (type(manifest) is not dict or set(manifest)!=required or
        manifest["schema"]!="neurofactory.onepc.components.unreleased.v1" or
        type(manifest["integration_source_commit"]) is not str or
        not SHA40.fullmatch(manifest["integration_source_commit"]) or
        manifest["host_is_ci_only"] is not True or
        any(manifest[name] is not False for name in FLAGS) or
        type(manifest["files"]) is not list or
        len(manifest["files"])!=sum(EXPECTED_COUNTS.values())):
        raise ValueError("Unsafe or altered component manifest")
    counts={role:0 for role in ROLES}
    paths=set()
    for entry in manifest["files"]:
        if type(entry) is not dict or set(entry)!={
            "role","relative_path","origin_path","origin_commit","bytes","sha256"}:
            raise ValueError("Invalid component entry")
        role=entry["role"]
        if type(role) is not str or role not in ROLES:
            raise ValueError("Invalid component role")
        relative=entry["relative_path"]
        if type(relative) is not str or not re.fullmatch(
            r"(?:core|host_ci_only|providers|coordinator)/[a-zA-Z0-9_]+\.py",relative
        ) or relative in paths or relative.split("/")[0]!=role:
            raise ValueError("Unsafe component path")
        paths.add(relative)
        counts[role]+=1
        expected_commit=(manifest["integration_source_commit"]
                         if role in ("core","host_ci_only") else
                         {"providers":"827b654d9f7c6a10a9b90a9c97802e63116711b9",
                          "coordinator":"ad82e853d9db2a0567c61e8d9a3f1e5f62905271"}[role])
        if type(entry["origin_commit"]) is not str or entry["origin_commit"]!=expected_commit:
            raise ValueError("Unpinned component origin")
        if (type(entry["bytes"]) is not int or not 1<=entry["bytes"]<=250000 or
            type(entry["sha256"]) is not str or not SHA64.fullmatch(entry["sha256"]) or
            type(entry["origin_path"]) is not str or not entry["origin_path"].endswith("/"+relative.split("/")[-1])):
            raise ValueError("Invalid component metadata")
        path=base/relative
        if (path.is_symlink() or path.parent.is_symlink() or not path.is_file() or
            path.stat().st_size!=entry["bytes"]):
            raise ValueError("Missing/linked/mismatched installed component")
        with path.open("rb") as fp:
            content=fp.read(250001)
        if hashlib.sha256(content).hexdigest()!=entry["sha256"]:
            raise ValueError("Installed component checksum mismatch")
    if counts!=EXPECTED_COUNTS:
        raise ValueError("Missing component role or file count")
    return {
        "component_sources_verified":True,
        "component_files":len(paths),
        "core_host_execution_enabled":False,
        "model_inference_verified":False,
        "release_approved":False,
        "independent_review_passed":False,
        "source_sha":manifest["integration_source_commit"],
    }


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--components",type=Path,required=True)
    opt=cli.parse_args()
    print(json.dumps(verify(opt.components),sort_keys=True))


if __name__=="__main__":
    main()
