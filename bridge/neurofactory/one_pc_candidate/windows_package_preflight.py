"""Read-only Windows setup Authenticode/hash inspection.

No installer launch, no elevation, no changing Windows services or files.
Current Neurofactory-Local-Draft-Setup.exe is an UNRELEASED candidate and
must remain blocked if unsigned or publisher cert not separately pinned.
"""
from __future__ import annotations

from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SHA = re.compile(r"[0-9a-f]{64}\Z")
THUMB = re.compile(r"[0-9A-F]{40}\Z")
class WindowsPackageDenied(ValueError):
    pass

def _deny(reason):
    raise WindowsPackageDenied("Windows package denied: " + reason)

def inspect_windows_package(*, installer, expected_sha256,
                            pinned_publisher_thumbprint):
    if (os.name != "nt" or not isinstance(installer, Path)
            or not installer.is_absolute() or installer.is_symlink()
            or not installer.is_file() or installer.suffix.lower() != ".exe"
            or type(expected_sha256) is not str or not SHA.fullmatch(expected_sha256)
            or type(pinned_publisher_thumbprint) is not str
            or not THUMB.fullmatch(pinned_publisher_thumbprint)):
        _deny("operating system, path or operator-pinned certificate")
    try:
        st=installer.lstat()
        if (not stat.S_ISREG(st.st_mode) or
                st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT or
                not 1024 <= st.st_size <= 200_000_000):
            _deny("not a regular bounded Windows executable")
        digest=sha256()
        with installer.open("rb") as stream:
            while True:
                chunk=stream.read(1024*1024)
                if not chunk:break
                digest.update(chunk)
        if digest.hexdigest()!=expected_sha256:
            _deny("installed artifact differs from reviewer-pinned SHA256")
    except OSError as exc:
        raise WindowsPackageDenied("Windows package denied: cannot read installer") from exc
    # Use Base64-encoded PowerShell to avoid interpolating untrusted paths into
    # PowerShell syntax; path is provided ONLY through the child process env.
    script=(
        "$ErrorActionPreference='Stop';"
        "$p=$env:NF_ATTEST_READONLY_SETUP;"
        "$a=Get-AuthenticodeSignature -LiteralPath $p;"
        "$cert=$a.SignerCertificate;"
        "$thumb=if($null -ne $cert){$cert.Thumbprint}else{''};"
        "[pscustomobject]@{status=[string]$a.Status;thumbprint=[string]$thumb}"
        "|ConvertTo-Json -Compress"
    )
    command=base64.b64encode(script.encode("utf-16le")).decode("ascii")
    env=os.environ.copy()
    env["NF_ATTEST_READONLY_SETUP"]=str(installer)
    try:
        proc=subprocess.run(
            ["powershell.exe","-NoProfile","-NonInteractive",
             "-EncodedCommand",command],
            capture_output=True, stdin=subprocess.DEVNULL, text=True,
            timeout=20, env=env, check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise WindowsPackageDenied("Windows package denied: Authenticode unavailable") from exc
    if proc.returncode!=0 or len(proc.stdout)>1000:
        _deny("Authenticode check unsuccessful")
    try:
        obj=json.loads(proc.stdout)
    except (TypeError, ValueError) as exc:
        raise WindowsPackageDenied("Windows package denied: malformed Authenticode report") from exc
    if (type(obj) is not dict or set(obj)!={"status","thumbprint"}
            or obj["status"]!="Valid" or
            type(obj["thumbprint"]) is not str or
            obj["thumbprint"].upper()!=pinned_publisher_thumbprint):
        _deny("unsigned, untrusted or wrong publisher")
    return {
        "schema":"nf.onepc.windows_authenticode_preflight.v1",
        "status":"SIGNED_PACKAGE_AND_PIN_MATCH_NO_INSTALL",
        "installer_sha256":expected_sha256,
        "publisher_certificate_thumbprint":pinned_publisher_thumbprint,
        "publisher_certificate_pinned":True,
        "signature_trust_reported_valid_by_windows":True,
        "operator_and_review_approvals_checked":False,
        "service_install_allowed":False,
        "production_release_allowed":False,
        "installer_was_executed":False,
        "windows_services_modified":False,
    }
