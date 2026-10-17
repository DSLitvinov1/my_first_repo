"""HOST-owned strict signed per-effect permit verifier (no signer, writer or API).

This is a reusable cryptographic contract verifier for a future separately
privileged HOST recipient. The return value NEVER permits filesystem effects.
Production additionally requires independently protected signer/key custody,
owner authorization, external antirollback pin, authenticated live lease/epoch
check, receiver-side atomic idempotency and OS isolation.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SignedEffectPermitError(ValueError):
    pass


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{3,72}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_TARGET = re.compile(
    r"bridge/neurofactory/development/core_owned/"
    r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:py|md|txt|json)\Z"
)
_FIELDS = frozenset({
    "schema", "purpose", "issuer_id", "key_id", "owner_id",
    "repository", "project_id", "task_id", "worker_id",
    "source_sha40", "source_file_sha256", "input_task_sha256",
    "policy_sha256", "target", "proposed_content_sha256",
    "fencing_token_sha256", "lease_epoch", "issued_unix", "expires_unix",
    "idempotency_key", "operation_id",
})
_STR_FIELDS = {
    "issuer_id": _IDENTIFIER, "key_id": _IDENTIFIER,
    "owner_id": _IDENTIFIER, "repository": _REPO,
    "project_id": _PROJECT, "task_id": _IDENTIFIER,
    "worker_id": _IDENTIFIER, "source_sha40": _SHA40,
    "source_file_sha256": _SHA64, "input_task_sha256": _SHA64,
    "policy_sha256": _SHA64, "target": _TARGET,
    "proposed_content_sha256": _SHA64,
    "fencing_token_sha256": _SHA64,
    "idempotency_key": _SHA64, "operation_id": _IDENTIFIER,
}


def _match(value, expression):
    return type(value) is str and expression.fullmatch(value) is not None


def _validated_payload(payload):
    if type(payload) is not dict or set(payload) != _FIELDS:
        raise SignedEffectPermitError("missing or extra signed fields")
    if (payload["schema"] != "neurofactory.trusted_host.signed_effect_permit.v1"
            or payload["purpose"] != "EFFECT_RESERVATION_SCOPE_ONLY"
            or any(not _match(payload[k],pat) for k,pat in _STR_FIELDS.items())
            or any(type(payload[k]) is not int for k in
                   ("lease_epoch","issued_unix","expires_unix"))
            or not 1 <= payload["lease_epoch"] < 2**63
            or not 1 <= payload["issued_unix"] < 2**63
            or not payload["issued_unix"] < payload["expires_unix"] < 2**63
            or payload["expires_unix"]-payload["issued_unix"] > 300):
        raise SignedEffectPermitError("invalid signed effect scope")
    parts=payload["target"].split("/")
    for item in parts:
        stem=item.split(".",1)[0].upper()
        if stem in {"CON","PRN","AUX","NUL"} or re.fullmatch(r"(COM|LPT)[1-9]",stem):
            raise SignedEffectPermitError("unsafe cross-platform signed target")
    return json.dumps(payload,sort_keys=True,ensure_ascii=True,
                      separators=(",",":"),allow_nan=False).encode("ascii")


def inspect_signed_effect_permit(
    signed_packet, *, externally_pinned_public_key,
    trusted_expected_scope, now_unix
):
    """Verify canonical Ed25519 and independently provided exact scope.

    NOTE: externally_pinned_public_key/expected_scope are ONLY truly trusted
    if sourced from separate protected operator control, not the packet or
    an API request. No replay protection, owner custody or live fence here.
    """
    if (type(signed_packet) is not dict
            or set(signed_packet) != {"payload","signature_base64"}
            or type(trusted_expected_scope) is not dict
            or set(trusted_expected_scope) != _FIELDS
            - {"schema","purpose","issued_unix","expires_unix"}
            or not isinstance(externally_pinned_public_key,Ed25519PublicKey)
            or type(now_unix) is not int or not 1 <= now_unix < 2**63):
        raise SignedEffectPermitError("invalid independent trust inputs")
    payload=signed_packet["payload"]
    signed_bytes=_validated_payload(payload)
    # Expected fields must come from an operator-approved source, not packet.
    for key,value in trusted_expected_scope.items():
        if type(value) not in (str,int) or payload[key] != value:
            raise SignedEffectPermitError("signed scope differs from trusted source")
    if not payload["issued_unix"] <= now_unix < payload["expires_unix"]:
        raise SignedEffectPermitError("expired or not yet valid signed permit")
    encoded=signed_packet["signature_base64"]
    if type(encoded) is not str or len(encoded) != 88:
        raise SignedEffectPermitError("invalid signature encoding")
    try:
        sig=base64.b64decode(encoded,validate=True)
        if len(sig)!=64:
            raise SignedEffectPermitError("invalid signature bytes")
        externally_pinned_public_key.verify(sig,signed_bytes)
    except (InvalidSignature,binascii.Error,ValueError) as exc:
        raise SignedEffectPermitError("untrusted effect signature") from exc
    return {
        "schema":"neurofactory.trusted_host.signed_effect_scope_report.v1",
        "status":"CRYPTO_SCOPE_MATCHES_NO_EXECUTION_AUTHORITY",
        "signed_permit_sha256":hashlib.sha256(signed_bytes).hexdigest(),
        "task_id":payload["task_id"],
        "operation_id":payload["operation_id"],
        "cryptographic_signature_verified":True,
        "exact_external_scope_compared":True,
        "protected_issuer_key_custody_attested":False,
        "real_owner_rights_authenticated":False,
        "independent_monotonic_epoch_protected":False,
        "live_lease_authenticated":False,
        "receiver_idempotency_enforced":False,
        "filesystem_execution_allowed":False,
        "publication_allowed":False,
        "automatic_retry_allowed":False,
    }
