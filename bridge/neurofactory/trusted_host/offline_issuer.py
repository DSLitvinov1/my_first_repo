"""Offline cryptographic event verifier candidate, NOT a deployed protected issuer.

An independent host must custody the private key and pin the public key and
monotonic last receipt *outside* CORE/PROVIDERS/central database. A locally
supplied self-signed event or checksum grants NO execution permission.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature


class IssuerBoundaryError(ValueError):
    pass


_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.-]{3,72}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_FIELDS = {"schema", "task_id", "project_id", "input_core_sha40",
           "source_file_sha256", "input_task_sha256", "event_kind",
           "event_sequence", "prior_event_digest_sha256",
           "core_checkpoint_digest_sha256", "issuer_identity",
           "issuer_key_id", "issued_at_utc"}
_KINDS = {"AUTHORIZE_TASK", "LEASE_CLAIM", "PRE_SIDE_EFFECT",
          "EFFECT_READBACK", "MANUAL_STOP"}


def _is_text(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _valid_payload(payload):
    if type(payload) is not dict or set(payload) != _FIELDS:
        raise IssuerBoundaryError("unknown or missing signed event field")
    if (payload["schema"] != "neurofactory.trusted_checkpoint_event.v1" or
        not _is_text(payload["task_id"], _TASK) or
        not _is_text(payload["project_id"], _ID) or
        not _is_text(payload["input_core_sha40"], _SHA40) or
        not _is_text(payload["source_file_sha256"], _SHA64) or
        not _is_text(payload["input_task_sha256"], _SHA64) or
        payload["event_kind"] not in _KINDS or
        type(payload["event_sequence"]) is not int or
        payload["event_sequence"] < 1 or
        not _is_text(payload["prior_event_digest_sha256"], _SHA64) or
        not _is_text(payload["core_checkpoint_digest_sha256"], _SHA64) or
        not _is_text(payload["issuer_identity"], _ID) or
        not _is_text(payload["issuer_key_id"], _ID) or
        not _is_text(payload["issued_at_utc"], _UTC)):
        raise IssuerBoundaryError("invalid signed event payload")


def _canonical(payload):
    _valid_payload(payload)
    return json.dumps(payload, sort_keys=True, separators=(",",":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sign_offline_fixture(private_key, payload):
    """For isolated tests only; never generates, persists or installs keys."""
    canonical = _canonical(payload)
    if not callable(getattr(private_key,"sign",None)):
        raise IssuerBoundaryError("no signer")
    signature = private_key.sign(canonical)
    if type(signature) is not bytes or len(signature) != 64:
        raise IssuerBoundaryError("unsupported signer output")
    return {"payload":dict(payload),
            "signature_base64":base64.b64encode(signature).decode("ascii")}


def verify_with_externally_pinned_state(
    trusted_public_key, signed_event, *,
    expected_task_id, expected_core_sha40,
    expected_issuer_identity, expected_key_id,
    externally_pinned_prev_digest, externally_pinned_next_sequence
):
    """Verify one link against externally pinned key+sequence+previous digest.

    The caller MUST source all expected values from a distinct trusted
    principal. This function does not provide that principal or antirollback
    storage and cannot authorize a real effect, even for a valid signature.
    """
    if (not callable(getattr(trusted_public_key,"verify",None)) or
        type(signed_event) is not dict or
        set(signed_event) != {"payload","signature_base64"} or
        not _is_text(expected_task_id,_TASK) or
        not _is_text(expected_core_sha40,_SHA40) or
        not _is_text(expected_issuer_identity,_ID) or
        not _is_text(expected_key_id,_ID) or
        not _is_text(externally_pinned_prev_digest,_SHA64) or
        type(externally_pinned_next_sequence) is not int or
        externally_pinned_next_sequence < 1):
        raise IssuerBoundaryError("untrusted verifier inputs")
    payload=signed_event["payload"]
    canonical=_canonical(payload)
    if (payload["task_id"] != expected_task_id or
        payload["input_core_sha40"] != expected_core_sha40 or
        payload["issuer_identity"] != expected_issuer_identity or
        payload["issuer_key_id"] != expected_key_id or
        payload["prior_event_digest_sha256"] != externally_pinned_prev_digest or
        payload["event_sequence"] != externally_pinned_next_sequence):
        raise IssuerBoundaryError("wrong external identity/source/sequence")
    encoded=signed_event["signature_base64"]
    if type(encoded) is not str or len(encoded)>128:
        raise IssuerBoundaryError("malformed detached signature")
    try:
        signature=base64.b64decode(encoded,validate=True)
        if len(signature)!=64:
            raise IssuerBoundaryError("wrong signature length")
        trusted_public_key.verify(signature,canonical)
    except (ValueError,InvalidSignature,binascii.Error) as error:
        raise IssuerBoundaryError("signature not independently verified") from error
    canonical_receipt=json.dumps(signed_event,sort_keys=True,
                                 separators=(",",":"),ensure_ascii=True).encode("ascii")
    return {
        "schema":"neurofactory.trusted_host.offline_verified_link.v1",
        "task_id":payload["task_id"],"event_sequence":payload["event_sequence"],
        "reported_receipt_digest_sha256":hashlib.sha256(canonical_receipt).hexdigest(),
        "matches_supplied_external_anchor":True,
        "external_anchor_provenance_supplied_by_host":False,
        "separate_signer_host_attested":False,
        "live_execution_allowed":False,"publication_allowed":False,
        "automatic_retry_allowed":False,"handoff":"PAUSED_BY_USER"
    }
