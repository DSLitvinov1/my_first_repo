"""Read-only external-operator preflight for untrusted VPS witness staging ZIP.

A SHA256 expected by a SEPARATELY trusted reviewer/operator is REQUIRED.
Comparing files only to a manifest inside the same archive is insufficient
to authenticate a software release. This verifier does NOT install, unpack,
grant authority, generate credentials, activate services or query GitHub.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

_EXPECTED=frozenset((
    "external_highwater_daemon.py",
    "external_highwater_store.py",
    "external_highwater_mtls_server.py",
    "independent_witness_receipt.py",
    "remote_highwater_client.py",
    "vps_witness_systemd/neurofactory-witness.service",
    "vps_witness_systemd/production.json.example",
    "vps_witness_systemd/requirements-witness.txt",
    "vps_witness_systemd/OPERATOR_VPS_INSTALLATION_RU.md",
    "vps_witness_systemd/verify_witness_source_archive.py",
    "WITNESS_REMOTE_NODE_DEPLOYMENT_BLOCKERS_20261027_RU.md",
))
_HASH=re.compile(r"[0-9a-f]{64}\Z")
_SOURCE=re.compile(r"[0-9a-f]{40}\Z")

class OperatorArchiveDenied(ValueError): pass
def _deny(reason):
    raise OperatorArchiveDenied("VPS operator review refused: "+reason)
def _parse_manifest(raw):
    if type(raw) is not bytes or len(raw)>9000: _deny("manifest not bounded")
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:_deny("duplicate manifest field")
            out[k]=v
        return out
    try:
        doc=json.loads(raw.decode("ascii"),object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError) as e:
        raise OperatorArchiveDenied("VPS operator review refused: invalid manifest") from e
    if (type(doc) is not dict or set(doc)!={"schema","source_sha40","mode","files"} or
        doc["schema"]!="nf.vps_witness.source_review_bundle.v1" or
        doc["mode"]!="UNSIGNED_OPERATOR_REVIEW_NO_KEYS_NO_PRODUCTION" or
        type(doc["source_sha40"]) is not str or not _SOURCE.fullmatch(doc["source_sha40"]) or
        type(doc["files"]) is not list or len(doc["files"])!=len(_EXPECTED)):
        _deny("manifest identity differs")
    got={}
    for item in doc["files"]:
        if (type(item) is not dict or set(item)!={"path","sha256","bytes"} or
            type(item["path"]) is not str or item["path"] not in _EXPECTED or
            item["path"] in got or type(item["sha256"]) is not str or
            not _HASH.fullmatch(item["sha256"]) or
            type(item["bytes"]) is not int or not 1<=item["bytes"]<=150000):
            _deny("manifest entry invalid or repeated")
        got[item["path"]]=item
    if set(got)!=_EXPECTED:_deny("missing pinned witness staging source")
    return doc,got

def verify_archive(*,path:Path,operator_approved_archive_sha256:str):
    if (not isinstance(path,Path) or not path.is_absolute() or path.is_symlink()
        or not path.is_file() or path.suffix.lower()!=".zip"
        or type(operator_approved_archive_sha256) is not str or
        not _HASH.fullmatch(operator_approved_archive_sha256)):
        _deny("missing externally pinned source archive")
    meta=path.lstat()
    if not stat.S_ISREG(meta.st_mode) or not 500<=meta.st_size<=3_000_000:
        _deny("unsafe source archive size/type")
    if sha256(path.read_bytes()).hexdigest()!=operator_approved_archive_sha256:
        _deny("archive does not match separately approved digest")
    try:
        with zipfile.ZipFile(path) as z:
            entries=z.infolist()
            names=[x.filename for x in entries]
            if (len(entries)!=len(_EXPECTED)+1 or len(names)!=len(set(names))
                or set(names)!=_EXPECTED|{"source-manifest.json"}):
                _deny("unexpected archive paths, duplicates or missing modules")
            for info in entries:
                if (info.is_dir() or info.flag_bits&0x1 or info.file_size>150000
                    or info.file_size<=0 or info.compress_size>3_000_000
                    or info.filename.startswith(("/",".","\\"))
                    or ".." in info.filename.split("/")
                    or "\\" in info.filename
                    or ((info.external_attr>>16)&0o170000)==0o120000):
                    _deny("linked, traversal, encrypted or oversized ZIP entry")
            doc,expected=_parse_manifest(z.read("source-manifest.json"))
            for name,listed in expected.items():
                data=z.read(name)
                if len(data)!=listed["bytes"] or sha256(data).hexdigest()!=listed["sha256"]:
                    _deny("actual ZIP source mismatches internal file digest")
                if b"-----BEGIN PRIVATE KEY-----" in data:
                    _deny("private signer included in source staging")
    except (zipfile.BadZipFile,RuntimeError,OSError,ValueError) as e:
        if isinstance(e,OperatorArchiveDenied):raise
        raise OperatorArchiveDenied("VPS operator review refused: malformed archive") from e
    return {
        "schema":"nf.vps_witness.operator_source_preflight.v1",
        "status":"SOURCE_ONLY_HASHES_MATCH_NO_RELEASE_AUTHORITY",
        "source_sha40":doc["source_sha40"],
        "verified_files":len(expected),
        "production_signed":False,
        "external_host_provisioned":False,
        "real_private_keys_provisioned":False,
        "reviewer_signature_verified":False,
        "may_install_or_activate":False,
    }

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("Usage: python verify_witness_source_archive.py /absolute/file.zip expected_external_sha256")
    try:
        report=verify_archive(path=Path(sys.argv[1]),
            operator_approved_archive_sha256=sys.argv[2])
    except OperatorArchiveDenied as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report,sort_keys=True,separators=(",",":")))
