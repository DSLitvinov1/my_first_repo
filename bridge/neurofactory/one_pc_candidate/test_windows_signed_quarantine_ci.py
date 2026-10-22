"""Windows hosted CI only: real NTFS private ACLs + ACTUAL older verified installer.

All two-person keys below are ephemeral disposable test keys, not owner keys.
Never opens, installs or executes the quarantined file. The tested installer
SHA was separately observed in genuine cloud Inno build #39701930342.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from signed_release_staging import (
    _canon, DOMAIN_OWNER,DOMAIN_REVIEW,INSTALLER_SOURCE_COMMIT,
    SCHEMA,SCOPE,StagingDenied,operator_stage_signed_candidate,_privileged_acl,
)

def main():
    if (os.name!="nt" or os.getenv("GITHUB_ACTIONS")!="true"
            or os.getenv("RUNNER_ENVIRONMENT")!="github-hosted"
            or os.getenv("NF_TEST_DISPOSABLE_RELEASE_STAGING")!="1"):
        raise RuntimeError("Only GitHub-hosted disposable Windows is authorized")
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Hosted test principal must be administrator")
    artifact=Path(sys.argv[1]).resolve(strict=True)
    if artifact.name!="Neurofactory-Local-Draft-Setup.exe":
        raise RuntimeError("Only exact archived installer test")
    expected_digest="648dc60f51390578c1835ca46b5151b61f1cb64858c34d6e164a8092381e35cf"
    if sha256(artifact.read_bytes()).hexdigest()!=expected_digest:
        raise RuntimeError("Untrusted artifact download")
    data_root=Path(os.environ["PROGRAMDATA"])/"Neurofactory"
    if data_root.exists() or data_root.is_symlink():
        raise RuntimeError("Never reuse existing system release staging")
    try:
        data_root.mkdir()
        trust=data_root/"TrustPins"
        trust.mkdir()
        args=["icacls",str(trust),"/inheritance:r","/grant:r",
            "*S-1-5-18:(OI)(CI)F","*S-1-5-32-544:(OI)(CI)F"]
        subprocess.run(args,check=True,timeout=15,capture_output=True)
        owner=Ed25519PrivateKey.generate()
        reviewer=Ed25519PrivateKey.generate()
        (trust/"owner-ed25519.pub").write_bytes(
            owner.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        (trust/"reviewer-ed25519.pub").write_bytes(
            reviewer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        for p in (trust,trust/"owner-ed25519.pub",trust/"reviewer-ed25519.pub"):
            _privileged_acl(p)
        now=int(time.time())
        packet={
            "schema":SCHEMA,"scope":SCOPE,
            "source_commit":INSTALLER_SOURCE_COMMIT,
            "installer_sha256":expected_digest,
            "installer_run_id":39701930342,"scm_run_id":39702159425,
            "qwen_run_id":39702865907,
            "nonce":"d"*32,"issued_unix":now-1,"expires_unix":now+300,
        }
        signed={**packet,
            "owner_signature_base64":base64.b64encode(
                owner.sign(DOMAIN_OWNER+_canon(packet))).decode(),
            "reviewer_signature_base64":base64.b64encode(
                reviewer.sign(DOMAIN_REVIEW+_canon(packet))).decode(),
        }
        approval=data_root/"ci-test-release-approval.json"
        approval.write_text(json.dumps(signed),encoding="ascii")
        result=operator_stage_signed_candidate(
            artifact,approval,expected_source_commit=INSTALLER_SOURCE_COMMIT)
        dest=data_root/"Quarantine"/artifact.name
        _privileged_acl(dest.parent)
        if (result["status"]!="TWO_PERSON_SIGNATURES_VERIFIED_QUARANTINE_ONLY"
                or not result["quarantine_copy_verified"]
                or result["service_enrollment_authorized"]
                or result["production_execution_authorized"]
                or dest.read_bytes()!=artifact.read_bytes()):
            raise AssertionError("Staging incomplete, corrupt, or unexpectedly executable")
        try:
            operator_stage_signed_candidate(
                artifact,approval,expected_source_commit=INSTALLER_SOURCE_COMMIT)
        except StagingDenied:
            pass
        else:
            raise AssertionError("Staging replay overwrote an existing candidate")
        # Never run the quarantined .exe, not even /SILENT.
        print("NF_WINDOWS_ACTUAL_INSTALLER_TWO_PERSON_SIGNED_QUARANTINE=PASS_TEST_KEYS_ONLY")
        print("NF_WINDOWS_ROOTED_NTFS_PRIVATE_OWNER_REVIEWER_PINS=PASS_TEST_ONLY")
        print("NF_WINDOWS_QUARANTINE_REPLAY_WRITE=DENIED")
        print("NF_WINDOWS_SERVICE_CREATED=FALSE")
        print("NF_WINDOWS_INSTALLER_EXECUTED=FALSE")
        print("NF_WINDOWS_INDEPENDENT_REVIEW_APPROVED=FALSE")
        print("NF_WINDOWS_PHYSICAL_OWNER_MACHINE=NOT_TESTED")
    finally:
        shutil.rmtree(data_root,ignore_errors=False)

if __name__=="__main__":
    main()
