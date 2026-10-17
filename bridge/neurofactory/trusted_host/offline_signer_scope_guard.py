"""Signer-owned externally provisioned scope fixture; NEVER production authorization.

The approved immutable scope is placed in a 0600 file owned by a separate
signer UID, outside the DB and worker accessible paths. This code does NOT
authenticate a human owner and has no power to write any project files.
It only verifies the exact Ed25519 permit payload and live signed monotonic
anchor witness against the separately provisioned fixture policy.
"""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import re
from signed_effect_permit import _validated_payload, SignedEffectPermitError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import binascii
from offline_operator_anchor import (
    _guard, _file, verify_current, OperatorAnchorDenied, _canonical
)

_POLICY_NAME="pinned-effect-scope.json"
_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_KEYS=frozenset({
    "issuer_id","key_id","owner_id","repository","project_id","task_id",
    "worker_id","source_sha40","source_file_sha256","input_task_sha256",
    "policy_sha256","target","proposed_content_sha256",
    "fencing_token_sha256","lease_epoch","idempotency_key","operation_id",
})

class OfflineScopeDenied(ValueError):pass

def _deny(message):raise OfflineScopeDenied(message)

def check_signer_owned_scope(home, *, signed_permit, witness,
                             current_key_fingerprint, current_public_b64):
    """No DB-controlled owner or caller-asserted policy becomes authority."""
    root=_guard(home)
    if (type(signed_permit) is not dict or
        set(signed_permit)!={"payload","signature_base64"} or
        type(witness) is not dict or
        type(current_key_fingerprint) is not str or
        not _SHA64.fullmatch(current_key_fingerprint) or
        type(current_public_b64) is not str):
        _deny("untrusted scope request")
    try:
        policy=json.loads(_file(root,_POLICY_NAME).read_text("ascii"))
    except (OSError,ValueError,UnicodeError) as e:
        raise OfflineScopeDenied("protected policy unavailable or damaged") from e
    if (type(policy) is not dict or
        set(policy)!={"schema","expected","pinned_public_sha256","allowed_claim_sha256","effect_issuer_public_b64"}
        or policy["schema"]!="neurofactory.operator.scope_fixture.v1"
        or policy["pinned_public_sha256"]!=current_key_fingerprint
        or type(policy["expected"]) is not dict or set(policy["expected"])!=_ALLOWED_KEYS
        or type(policy["allowed_claim_sha256"]) is not str or
        not _SHA64.fullmatch(policy["allowed_claim_sha256"])):
        _deny("missing independently owned exact owner and project policy")
    body=signed_permit["payload"]
    try:
        raw=_validated_payload(body)
    except (SignedEffectPermitError,ValueError,TypeError) as e:
        raise OfflineScopeDenied("invalid signed effect schema") from e
    # Unlike the DB, the separately protected signer policy pins the
    # independent effect-issuer public key. A caller cannot substitute it.
    try:
        effect_public=base64.b64decode(policy["effect_issuer_public_b64"],validate=True)
        sig=base64.b64decode(signed_permit["signature_base64"],validate=True)
        if len(effect_public)!=32 or len(sig)!=64:
            _deny("invalid independent effect signer or signature")
        Ed25519PublicKey.from_public_bytes(effect_public).verify(sig,raw)
    except (binascii.Error,InvalidSignature,ValueError,TypeError,KeyError) as e:
        raise OfflineScopeDenied("effect signature not verified by pinned issuer") from e
    if any(type(body[k])!=type(v) or body[k]!=v
           for k,v in policy["expected"].items()):
        _deny("owner/repo/project/worker/target/lease/operation not allowed")
    if body["purpose"]!="EFFECT_RESERVATION_SCOPE_ONLY":
        _deny("no live execute purpose accepted")
    # The owner fixture must bind the *entire canonical signed permit body*.
    digest=hashlib.sha256(raw).hexdigest()
    if policy["allowed_claim_sha256"]!=digest:
        _deny("scope does not match protected claim")
    # Must hold a current independently signed head attesting same digest.
    if (type(witness.get("certificate")) is not dict or
        witness["certificate"].get("claim_sha256")!=digest):
        _deny("signed monotonic claim differs from proposed effect")
    try:
        current=verify_current(
            root,witness,current_key_fingerprint,current_public_b64)
    except (OperatorAnchorDenied,ValueError) as e:
        raise OfflineScopeDenied("stale/forged/out-of-band signer state") from e
    if current["status"]!="CURRENT_SEPARATE_OS_UID_TIP_MATCHES":
        _deny("protected current tip unavailable")
    return {
        "schema":"neurofactory.operator.scope_verification_fixture.v1",
        "status":"OWNER_SCOPE_FIXTURE_MATCHED_NOT_AUTHORITY",
        "signed_permit_sha256":digest,
        "operation_id":body["operation_id"],
        "worker_id":body["worker_id"],
        "current_signer_sequence":current["sequence"],
        "operator_private_key_disclosed":False,
        "real_human_owner_authenticated":False,
        "production_execution_allowed":False,
        "filesystem_write_allowed":False,
        "auto_retry_allowed":False,
    }
