"""Non-live independent witness-side verification of actual signed effect scope.

TLS client identity alone must never authorize arbitrary witness reservations.
The separate witness UID revalidates BOTH effect issuer and owner signatures
from keys pinned in its own private store. All fields in the minimal witness
claim must agree with those signatures and operator-pinned owner/repo/project
policy. Still NOT a current central lease check or production authorization.

No writes, installation, networking or private-key generation in this module.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from signed_effect_permit import _validated_payload, SignedEffectPermitError
from offline_external_effect_witness import validate_claim, canon, pin_private_dir

class SignedWitnessScopeDenied(ValueError):
    pass

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_FIELDS = frozenset({
    "owner_id", "repository", "project_id", "task_id",
    "worker_id", "source_sha40", "target", "operation_id",
    "lease_epoch", "permit_sha256", "expires_unix",
})
_POLICY_FIELDS = frozenset({
    "schema", "owner_id", "github_owner_numeric_id", "repo_id", "repository",
    "project_id", "worker_id", "issuer_public_base64",
    "owner_public_base64", "issuer_sha256", "owner_sha256",
})
_POLICY_FILE = "signed-witness-authority-pin.json"

def reject():
    raise SignedWitnessScopeDenied("independent witness has not verified both owner and issuer scope")

def public(raw, fingerprint):
    if type(raw) is not str or type(fingerprint) is not str or not _HEX64.fullmatch(fingerprint):
        reject()
    try:
        key = base64.b64decode(raw,validate=True)
    except (binascii.Error,ValueError) as e:
        raise SignedWitnessScopeDenied("invalid pinned public key") from e
    if len(key)!=32 or hashlib.sha256(key).hexdigest()!=fingerprint:
        reject()
    return Ed25519PublicKey.from_public_bytes(key)

def verify(key, raw, signature):
    if type(signature) is not str:
        reject()
    try:
        sig=base64.b64decode(signature,validate=True)
        if len(sig)!=64:
            reject()
        key.verify(sig,raw)
    except (InvalidSignature,binascii.Error,ValueError) as e:
        raise SignedWitnessScopeDenied("untrusted effect scope signature") from e

def scope_verified_claim(envelope, policy, *, now_unix=None):
    if (type(envelope) is not dict or
        set(envelope)!={"claim","signed_packet","signed_owner_grant"} or
        type(policy) is not dict or set(policy)!=_POLICY_FIELDS or
        policy["schema"]!="nf.witness.pinned_scope.test.v1"):
        reject()
    if (type(policy["owner_id"]) is not str or
        type(policy["repo_id"]) is not str or
        type(policy["repository"]) is not str or
        type(policy["project_id"]) is not str or
        type(policy["worker_id"]) is not str or
        type(policy["github_owner_numeric_id"]) is not str or
        policy["github_owner_numeric_id"]!="151650108" or
        policy["repo_id"]!="723328237"):
        reject()
    issuer=public(policy["issuer_public_base64"],policy["issuer_sha256"])
    owner=public(policy["owner_public_base64"],policy["owner_sha256"])
    packet=envelope["signed_packet"]
    grant=envelope["signed_owner_grant"]
    if (type(packet) is not dict or set(packet)!={"payload","signature_base64"} or
        type(grant) is not dict or set(grant)!={"statement","signature_base64"} or
        type(grant["statement"]) is not dict or
        set(grant["statement"])!=_OWNER_FIELDS):
        reject()
    claim=envelope["claim"]
    try:
        validate_claim(claim)
        permit_bytes=_validated_payload(packet["payload"])
    except (ValueError,TypeError,KeyError,SignedEffectPermitError):
        reject()
    body=packet["payload"]
    statement=grant["statement"]
    verify(issuer,permit_bytes,packet["signature_base64"])
    verify(owner,canon(statement),grant["signature_base64"])
    now=int(time.time()) if now_unix is None else now_unix
    if (type(now) is not int or
        not body["issued_unix"]<=now<body["expires_unix"] or
        type(statement["expires_unix"]) is not int or
        not now<statement["expires_unix"]<=body["expires_unix"] or
        statement["expires_unix"]-now>300):
        reject()
    if (body["owner_id"]!=policy["owner_id"] or
        body["repository"]!=policy["repository"] or
        body["project_id"]!=policy["project_id"] or
        body["worker_id"]!=policy["worker_id"]):
        reject()
    for field in (
        "owner_id","repository","project_id","worker_id","task_id",
        "source_sha40","target","operation_id","lease_epoch"
    ):
        if (type(statement[field])!=type(body[field]) or
            statement[field]!=body[field]):
            reject()
    digest=hashlib.sha256(permit_bytes).hexdigest()
    if (statement["permit_sha256"]!=digest or
        claim["owner_id"]!=policy["github_owner_numeric_id"] or
        claim["repo_id"]!=policy["repo_id"] or
        claim["task_id"]!=body["task_id"] or
        claim["operation_id"]!=body["operation_id"] or
        claim["target"]!=body["target"] or
        type(claim["lease_epoch"]) is not int or
        claim["lease_epoch"]!=body["lease_epoch"] or
        claim["permit_sha256"]!=digest or
        claim["content_sha256"]!=body["proposed_content_sha256"]):
        reject()
    # Nonce in the request is transport entropy. It does not extend lease or
    # create a new write authority. Independent durable task+target journal
    # still handles replay and uncertainty.
    return {
        "status":"TWO_INDEPENDENT_SIGNED_SCOPES_MATCH_WITNESS_PIN_TEST_ONLY",
        "claim_sha256":hashlib.sha256(canon(claim)).hexdigest(),
        "signed_permit_sha256":digest,
        "current_central_lease_checked_here":False,
        "real_human_owner_enrolled":False,
        "production_execution_allowed":False,
    }

def verify_under_witness_uid(home,envelope,*,now_unix=None):
    root=pin_private_dir(home)  # nonroot nf_witness-owned 0700, explicit fixture
    pin=root/_POLICY_FILE
    try:
        info=pin.lstat()
        if (not stat.S_ISREG(info.st_mode) or
            info.st_uid!=os.geteuid() or info.st_mode & 0o077 or
            info.st_size>4096):
            reject()
        policy=json.loads(pin.read_text("ascii"))
    except (OSError,ValueError,UnicodeError) as e:
        raise SignedWitnessScopeDenied("independent witness policy absent") from e
    return scope_verified_claim(envelope,policy,now_unix=now_unix)
