"""Offline, non-root ONE-TIME provisioning of a self-managed Linux witness.

Must run on the physically separate already owned Linux device. Uses an SSH
forced key scoped exclusively to the highwater code; no shell or forwarding.
Refuses every existing database, signer or policy, including partial states:
never silently destroys or resets a witness to "fix" an ambiguous deployment.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from personal_ssh_highwater import provision_new_offline

SHA40=re.compile(r"[a-f0-9]{40}\Z")
SHA64=re.compile(r"[a-f0-9]{64}\Z")
SSH_ED25519=re.compile(r"ssh-ed25519 ([a-zA-Z0-9+/]+={0,3})(?: [a-zA-Z0-9_.-]{3,80})?\Z")


def main(argv=None):
    p=argparse.ArgumentParser(description="Provision separate Linux personal highwater without reset")
    p.add_argument("--root",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--machine-sha",required=True)
    p.add_argument("--package-sha",required=True)
    p.add_argument("--windows-ssh-public",required=True)
    args=p.parse_args(argv)
    if os.name!="posix" or os.geteuid()==0:
        raise SystemExit("Use the existing unprivileged Linux operator account")
    for n,v,pat in (("source",args.source_sha,SHA40),
                     ("machine",args.machine_sha,SHA64),
                     ("package",args.package_sha,SHA64)):
        if not pat.fullmatch(v):
            raise SystemExit("invalid pinned "+n+" fingerprint")
    match=SSH_ED25519.fullmatch(args.windows_ssh_public.strip())
    if not match:
        raise SystemExit("exact Windows OpenSSH Ed25519 public key required")
    raw=base64.b64decode(match.group(1),validate=True)
    if not raw.startswith(b"\x00\x00\x00\x0bssh-ed25519"):
        raise SystemExit("not an Ed25519 SSH public key")
    root=Path(args.root)
    if (not root.is_absolute() or root.is_symlink()
            or root.exists() and any(root.iterdir())):
        raise SystemExit("root must be empty; NEVER reset existing highwater")
    os.umask(0o077)
    if not root.exists():
        root.mkdir(mode=0o700,parents=False)
    if (root.stat().st_mode&0o777)!=0o700:
        raise SystemExit("private witness root must be 0700")
    signer=Ed25519PrivateKey.generate()
    private=signer.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    private_file=root/"ed25519-signing.key"
    with private_file.open("xb") as out:
        out.write(private)
        out.flush()
        os.fsync(out.fileno())
    private_file.chmod(0o600)
    scope={
        "schema":"nf.personal.highwater.pinned_scope.v1",
        "source_sha40":args.source_sha,
        "machine_sha256":args.machine_sha,
        "package_sha256":args.package_sha,
    }
    with (root/"operator-scope.json").open("x",encoding="ascii") as out:
        json.dump(scope,out,sort_keys=True,separators=(",",":"))
        out.flush()
        os.fsync(out.fileno())
    (root/"operator-scope.json").chmod(0o600)
    provision_new_offline(root)
    # No external shell: sshd forcibly runs only this immutable executable
    # source, with a single bounded request and no SSH_ORIGINAL_COMMAND.
    script=Path(__file__).resolve()
    if script.is_symlink() or not script.is_file():
        raise SystemExit("trusted script path not ordinary file")
    runner=script.with_name("personal_ssh_highwater.py")
    if runner.is_symlink() or not runner.is_file():
        raise SystemExit("trusted highwater implementation missing")
    # Use a pinned install path, not a client-supplied forced command.
    command="/usr/bin/python3 "+str(runner)+" "+str(root)
    if '"' in command or "\n" in command:
        raise SystemExit("invalid trusted runtime path")
    ssh_home=Path.home()/".ssh"
    auth=ssh_home/"authorized_keys"
    if (not ssh_home.is_dir() or not auth.is_file() or auth.is_symlink()
            or auth.stat().st_mode&0o077):
        raise SystemExit("existing SSH authorization file not operator-safe")
    fingerprint=sha256(raw).hexdigest()[:20]
    comment="NF-personal-highwater-"+fingerprint
    if comment in auth.read_text("utf-8"):
        raise SystemExit("SSH client already enrolled")
    line=("restrict,command=\""+command+"\" "+
          "ssh-ed25519 "+match.group(1)+" "+comment+"\n")
    with auth.open("a",encoding="utf-8") as out:
        out.write(line)
        out.flush()
        os.fsync(out.fileno())
    pub=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    print(json.dumps({
        "status":"PERSONAL_LINUX_WITNESS_PROVISIONED_NOT_INDEPENDENT",
        "root":str(root),
        "witness_public_base64":base64.b64encode(pub).decode("ascii"),
        "client_key_fingerprint":fingerprint,
        "first_expected_remote_epoch":1,
        "private_keys_exported":False,
        "independent_operator_assured":False,
        "windows_only_rollback_deduplication_available":True,
    },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
