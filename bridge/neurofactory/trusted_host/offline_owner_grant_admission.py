"""Signer-UID protected cryptographic owner grant admission prototype.

Verifies real ED25519 signature over exact owner/repo/project/task/source/file
scope using out-of-band pre-pinned public owner key. Does NOT establish legal
identity or GitHub repo administration: that external enrollment is STILL
required. Never returns production or filesystem write authority.
"""
from __future__ import annotations
import base64,binascii,hashlib,json,re,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from offline_operator_anchor import _file,_guard,_canonical
from signed_effect_permit import _validated_payload,SignedEffectPermitError

class OwnerGrantDenied(ValueError): pass
_ALLOWLIST="pinned-project-owner-authority.json"
_SHA40=re.compile(r"[0-9a-f]{40}\Z")
_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_FIELDNAMES=frozenset(("owner_id","repository","project_id","task_id",
  "worker_id","source_sha40","target","operation_id",
  "lease_epoch","permit_sha256","expires_unix"))

def reject():raise OwnerGrantDenied("untrusted owner-scope assertion")

def check_owner_grant_under_signer_uid(home, signed_permit, signed_owner_grant, *,now_unix=None):
    root=_guard(home)
    if (type(signed_owner_grant) is not dict or
        set(signed_owner_grant)!={"statement","signature_base64"} or
        type(signed_owner_grant["statement"]) is not dict or
        set(signed_owner_grant["statement"])!=_FIELDNAMES or
        type(signed_owner_grant["signature_base64"]) is not str or
        type(signed_permit) is not dict or
        set(signed_permit)!={"payload","signature_base64"}):
        reject()
    try:
        enrolled=json.loads(_file(root,_ALLOWLIST).read_text("ascii"))
    except (OSError,ValueError,UnicodeError) as e:
        raise OwnerGrantDenied("protected owner enrollment absent or damaged") from e
    if (type(enrolled) is not dict or
        set(enrolled)!={"schema","owner_id","repository","project_id",
                         "owner_public_key_base64","operator_pinned_fingerprint"} or
        enrolled["schema"]!="neurofactory.owner.authority_pin_fixture.v1" or
        type(enrolled["owner_id"]) is not str or
        type(enrolled["repository"]) is not str or
        type(enrolled["project_id"]) is not str or
        type(enrolled["owner_public_key_base64"]) is not str or
        type(enrolled["operator_pinned_fingerprint"]) is not str or
        not _SHA64.fullmatch(enrolled["operator_pinned_fingerprint"])):
        reject()
    try:
        public=base64.b64decode(enrolled["owner_public_key_base64"],validate=True)
        signature=base64.b64decode(signed_owner_grant["signature_base64"],validate=True)
        if (len(public)!=32 or len(signature)!=64 or
            hashlib.sha256(public).hexdigest()!=enrolled["operator_pinned_fingerprint"]):
            reject()
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature,_canonical(signed_owner_grant["statement"]))
    except (InvalidSignature,binascii.Error,ValueError,TypeError) as e:
        raise OwnerGrantDenied("not signed by independently pre-pinned owner key") from e
    statement=signed_owner_grant["statement"]
    try:
        permit_raw=_validated_payload(signed_permit["payload"])
    except (SignedEffectPermitError,ValueError,TypeError,KeyError) as e:
        raise OwnerGrantDenied("invalid scoped effect permit") from e
    body=signed_permit["payload"]
    if (type(statement["lease_epoch"]) is not int or
        type(statement["expires_unix"]) is not int or
        type(statement["permit_sha256"]) is not str or
        not _SHA64.fullmatch(statement["permit_sha256"]) or
        statement["permit_sha256"]!=hashlib.sha256(permit_raw).hexdigest()):
        reject()
    if now_unix is None:now_unix=int(time.time())
    if type(now_unix) is not int or not 0<statement["expires_unix"]-now_unix<=600:
        reject()
    for field in ("owner_id","repository","project_id","task_id","worker_id",
                  "source_sha40","target","operation_id","lease_epoch"):
        if (type(statement[field])!=type(body[field]) or
            statement[field]!=body[field]):
            reject()
    for field in ("owner_id","repository","project_id"):
        if statement[field]!=enrolled[field]:reject()
    if statement["expires_unix"]>body["expires_unix"]:
        reject()
    return {"status":"PINNED_OWNER_KEY_SIGNED_EXACT_SCOPE_TEST_ONLY",
        "grant_sha256":hashlib.sha256(_canonical(statement)).hexdigest(),
        "operator_enrolled_owner_key":True,
        "human_legal_identity_independently_confirmed":False,
        "repository_admin_rights_live_confirmed":False,
        "production_execution_allowed":False,
        "filesystem_write_allowed":False}
