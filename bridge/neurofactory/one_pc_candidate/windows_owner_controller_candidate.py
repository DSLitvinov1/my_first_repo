"""Windows offline owner signing candidate; NOT a production trust root.

The signing key is protected at rest with CurrentUser DPAPI and Windows NTFS
DACL limited to the operator SID. The UI must use a DIFFERENT Windows SID.
An independent operator-pinned public key is a required argument: the local
manifest is NEVER sufficient to bootstrap trust. No HTTP, CORE enqueue, HOST
effect, app installation, or automatic approval in this module.

Caveat: DPAPI is decryptable by other code executing as the owner SID. A
different OS account, independent review, human prompt, and live permission
checks are still required; rollback and physical presence are NOT attested.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

from signed_owner_admission import (
    _canon, _CORE_SPEC_KEYS, _SCOPE, verify_owner_permit
)

ROOT_SCHEMA = "nf.windows.owner.dpapi_candidate.v1"
SID_PATTERN = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
PRIVATE_FILE = "owner-ed25519.dpapi"
PUBLIC_FILE = "public-owner-pin.json"
DPAPI_CONTEXT = b"NF_ONEPC_OWNER_KEY_V1\x00"


class WindowsOwnerDenied(ValueError):
    pass


def deny(reason):
    raise WindowsOwnerDenied(reason)


def windows():
    if os.name != "nt":
        deny("Windows only")
    try:
        import win32api
        import win32con
        import win32crypt
        import win32security
    except ImportError as exc:
        raise WindowsOwnerDenied("Windows native crypto dependency unavailable") from exc
    return win32api, win32con, win32crypt, win32security


def operator_sid():
    api, con, _, sec = windows()
    token = sec.OpenProcessToken(api.GetCurrentProcess(), con.TOKEN_QUERY)
    return sec.ConvertSidToStringSid(
        sec.GetTokenInformation(token, sec.TokenUser)[0])


def check_root(root, *, exists=True):
    if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink():
        deny("Absolute nonlinked controller directory required")
    if not root.parent.is_dir() or root.parent.is_symlink():
        deny("Controller parent must be a normal existing directory")
    if exists and not root.is_dir():
        deny("Controller not enrolled")
    if root.exists():
        data = root.lstat()
        if (not stat.S_ISDIR(data.st_mode) or
                data.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            deny("Controller directory must not be reparse point")
    return root


def acl_check(path, *, directory):
    _, _, _, sec = windows()
    if path.is_symlink() or (
            path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        deny("Symlink or reparse point in controller")
    if (directory and not path.is_dir()) or (
            not directory and not path.is_file()):
        deny("Invalid signed controller file type")
    descriptor = sec.GetNamedSecurityInfo(
        str(path), sec.SE_FILE_OBJECT,
        sec.OWNER_SECURITY_INFORMATION | sec.DACL_SECURITY_INFORMATION)
    owner = sec.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    dacl = descriptor.GetSecurityDescriptorDacl()
    if owner != operator_sid() or dacl is None or dacl.GetAceCount() != 1:
        roles = [] if dacl is None else [
            (dacl.GetAce(i)[0][0],
             sec.ConvertSidToStringSid(dacl.GetAce(i)[2]) == operator_sid(),
             dacl.GetAce(i)[0][1])
            for i in range(dacl.GetAceCount())
        ]
        deny("Controller ACL not exclusive: owner_matches_signer=" +
             str(owner == operator_sid()) + " ace_roles=" + str(roles))
    ace = dacl.GetAce(0)
    (atype, flags), mask, sid = ace
    if (atype != sec.ACCESS_ALLOWED_ACE_TYPE or
            sec.ConvertSidToStringSid(sid) != operator_sid() or
            not mask):
        deny("Controller ACL has unauthorized ACE")
    return True


def protect_acl(path, *, directory):
    _, con, _, sec = windows()
    sid = sec.ConvertStringSidToSid(operator_sid())
    acl = sec.ACL()
    flags = (con.CONTAINER_INHERIT_ACE | con.OBJECT_INHERIT_ACE) if directory else 0
    acl.AddAccessAllowedAceEx(sec.ACL_REVISION, flags, con.GENERIC_ALL, sid)
    sec.SetNamedSecurityInfo(
        str(path), sec.SE_FILE_OBJECT,
        sec.DACL_SECURITY_INFORMATION | sec.PROTECTED_DACL_SECURITY_INFORMATION |
        sec.OWNER_SECURITY_INFORMATION,
        sid, None, acl, None)
    return acl_check(path, directory=directory)


def read_file(root, filename):
    check_root(root)
    acl_check(root, directory=True)
    p = root / filename
    if not p.is_file() or p.is_symlink() or not 1 <= p.stat().st_size <= 8192:
        deny("Owner key file missing or oversized")
    acl_check(p, directory=False)
    raw = p.read_bytes()
    if len(raw) != p.stat().st_size:
        deny("Controller file changed during read")
    return raw


def write_once(root, filename, raw):
    p = root / filename
    if not isinstance(raw, bytes) or p.exists() or p.is_symlink():
        deny("Owner controller never overwrites existing key files")
    with p.open("xb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    protect_acl(p, directory=False)
    if read_file(root, filename) != raw:
        deny("Owner controller file readback mismatch")


def operator_confirm(callback, challenge, *, ci):
    if ci:
        if not (os.getenv("GITHUB_ACTIONS") == "true" and
                os.getenv("RUNNER_ENVIRONMENT") == "github-hosted" and
                os.getenv("NF_OWNER_SIGNER_DISPOSABLE_CI") == "1"):
            deny("Simulated owner confirmation not permitted outside disposable CI")
    elif not (sys.stdin.isatty() and sys.stdout.isatty()):
        deny("Real offline interactive console is required")
    if not callable(callback) or callback(challenge) != challenge:
        deny("Owner confirmation denied")


def enroll(root, *, ui_sid, confirm, ci=False):
    """Manual separate-account key enrollment, no owner-PC automation."""
    sid = operator_sid()
    if (not isinstance(ui_sid, str) or not SID_PATTERN.fullmatch(ui_sid) or
            ui_sid == sid):
        deny("Require actual distinct unprivileged Windows UI SID")
    root = check_root(root, exists=False)
    if root.exists():
        deny("No automatic overwrite or key rotation")
    operator_confirm(confirm, "ENROLL " + sid, ci=ci)
    root.mkdir()
    protect_acl(root, directory=True)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    entropy = hashlib.sha256(DPAPI_CONTEXT + public + sid.encode()).digest()
    _, _, crypt, _ = windows()
    blob = crypt.CryptProtectData(
        private, "NF_OWNER_CI_CANDIDATE", entropy, None, None,
        crypt.CRYPTPROTECT_UI_FORBIDDEN)
    write_once(root, PRIVATE_FILE, blob)
    manifest = {
        "schema": ROOT_SCHEMA,
        "owner_sid": sid,
        "ui_sid": ui_sid,
        "public_base64": base64.b64encode(public).decode("ascii"),
        "public_sha256": hashlib.sha256(public).hexdigest(),
        "storage": "CURRENT_USER_DPAPI_NTFS_SINGLE_SID",
        "owner_presence_attested": False,
        "independent_enrollment": False,
        "rollback_fenced": False,
        "release_allowed": False,
    }
    write_once(root, PUBLIC_FILE, _canon(manifest) + b"\n")
    return manifest


def read_manifest(root, pinned_public):
    try:
        manifest = json.loads(read_file(root, PUBLIC_FILE).decode("ascii"))
        public = base64.b64decode(manifest["public_base64"], validate=True)
    except (ValueError, UnicodeError, KeyError, TypeError, binascii.Error) as exc:
        raise WindowsOwnerDenied("Owner manifest invalid") from exc
    required = {
        "schema", "owner_sid", "ui_sid", "public_base64",
        "public_sha256", "storage", "owner_presence_attested",
        "independent_enrollment", "rollback_fenced", "release_allowed",
    }
    if (type(manifest) is not dict or set(manifest) != required or
            manifest["schema"] != ROOT_SCHEMA or
            manifest["owner_sid"] != operator_sid() or
            not SID_PATTERN.fullmatch(manifest["ui_sid"]) or
            manifest["ui_sid"] == operator_sid() or
            type(pinned_public) is not bytes or len(pinned_public) != 32 or
            public != pinned_public or
            hashlib.sha256(public).hexdigest() != manifest["public_sha256"] or
            manifest["storage"] != "CURRENT_USER_DPAPI_NTFS_SINGLE_SID" or
            any(manifest[x] is not False for x in (
                "owner_presence_attested", "independent_enrollment",
                "rollback_fenced", "release_allowed",
            ))):
        deny("Owner SID or separately pinned trust root invalid")
    return manifest, public


def signed_enqueue_only(root, *, prepared_draft, spec,
                        pinned_public, confirm, now=None, ci=False):
    """Sign only immutable one-task pending-core admission, NEVER execute it.

    Trusted CORE independently rereads the real workspace and source Git SHA.
    """
    manifest, pub = read_manifest(root, pinned_public)
    if (type(prepared_draft) is not dict or
            prepared_draft.get("schema") != "nf.onepc.draft_admission_request.v1" or
            prepared_draft.get("owner_signed") is not False or
            prepared_draft.get("queue_mutation_allowed") is not False or
            prepared_draft.get("execution_allowed") is not False or
            type(spec) is not dict or set(spec) != _CORE_SPEC_KEYS or
            spec.get("schema") != "neurofactory.core.task.v1" or
            spec.get("project_id") != prepared_draft.get("core_project_id") or
            spec.get("objective") != prepared_draft.get("objective") or
            prepared_draft.get("model_preference") not in ("auto", spec.get("model")) or
            spec.get("approval_commit") != spec.get("source_sha") or
            not isinstance(spec.get("source_sha"), str) or
            not HEX40.fullmatch(spec["source_sha"]) or
            not isinstance(spec.get("source_sha256"), str) or
            not HEX64.fullmatch(spec["source_sha256"]) or
            type(spec.get("reserved_units")) is not int or
            not 1 <= spec["reserved_units"] <= 100000 or
            not isinstance(spec.get("target"), str) or
            not spec["target"].startswith(
                "bridge/neurofactory/development/core_owned/")):
        deny("Signed permit fails immutable project/model/source/target scope")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now <= 0:
        deny("Invalid signing time")
    body = {
        "schema": "nf.onepc.owner_core_admission.v1",
        "scope": _SCOPE,
        "draft": prepared_draft,
        "spec": spec,
        "nonce": secrets.token_hex(16),
        "issued_at": now,
        "expires_at": now + 120,
    }
    digest = hashlib.sha256(_canon(body)).hexdigest()
    phrase = "APPROVE " + digest[:16]
    summary = (
        f"OWNER SID {manifest['owner_sid']}\n"
        f"PROJECT {spec['project_id']} TASK {spec['task_id']}\n"
        f"MODEL {spec['model']} SOURCE {spec['source_sha']}\n"
        f"INPUT_SHA256 {spec['source_sha256']} TARGET {spec['target']}\n"
        f"OBJECTIVE {spec['objective']}\n"
        f"PERMIT_SHA256 {digest}\n{phrase}"
    )
    operator_confirm(
        lambda value: confirm(summary) if value == phrase else None,
        phrase, ci=ci)
    _, _, crypt, _ = windows()
    entropy = hashlib.sha256(
        DPAPI_CONTEXT + pub + manifest["owner_sid"].encode()).digest()
    try:
        _, private = crypt.CryptUnprotectData(
            read_file(root, PRIVATE_FILE), entropy, None, None,
            crypt.CRYPTPROTECT_UI_FORBIDDEN)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        key = Ed25519PrivateKey.from_private_bytes(private)
        if key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != pub:
            deny("Decrypted key does not equal independent pinned public key")
        sig = key.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00" + _canon(body))
    except (ValueError, TypeError) as exc:
        raise WindowsOwnerDenied("Owner DPAPI decrypt/sign failed") from exc
    permit = {**body, "owner_signature": base64.b64encode(sig).decode("ascii")}
    verify_owner_permit(
        permit, owner_public_raw=pinned_public,
        expected_draft=prepared_draft, now=now)
    return permit
