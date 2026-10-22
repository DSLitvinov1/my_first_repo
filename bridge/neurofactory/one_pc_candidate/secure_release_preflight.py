"""НЕЙРОЗАВОД: separately signed release preflight, read-only and fail-closed.

This is NOT a Windows service installer, a production authorization, a
hardware identity verifier, or an independent anti-rollback witness.
Only checks three external signatures over one exact install claim and
independently supplied (not request-controlled) expected values.

The reviewer, owner and remote witness keys MUST originate from three
separately provisioned trusted principals. CI may use disposable keys ONLY
for synthetic negative tests. The result NEVER enables effects or writes.
"""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPOSITORY = "DSLitvinov1/my_first_repo"
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{3,96}\Z")
_NONCE = re.compile(r"[a-f0-9]{32}\Z")
_CLAIM = frozenset((
    "schema", "repository", "candidate_sha", "installer_sha256",
    "components_manifest_sha256", "review_evidence_sha256",
    "owner_id", "reviewer_id", "witness_id", "machine_identity_sha256",
    "external_epoch", "nonce", "issued_unix", "expires_unix",
    "review_verdict", "scope", "service_name",
))
_EXPECTED = frozenset((
    "candidate_sha", "installer_sha256", "components_manifest_sha256",
    "review_evidence_sha256", "owner_id", "reviewer_id", "witness_id",
    "machine_identity_sha256", "minimum_external_epoch",
))
_DOMAIN = {
    "reviewer": b"NF_ONEPC_RELEASE_INDEPENDENT_REVIEW_V1\x00",
    "owner": b"NF_ONEPC_RELEASE_EXPLICIT_OWNER_V1\x00",
    "witness": b"NF_ONEPC_RELEASE_EXTERNAL_WITNESS_V1\x00",
}
_MAX_BYTES = 8192

class SecureReleaseDenied(ValueError):
    pass

def _deny(reason):
    raise SecureReleaseDenied("Release preflight refused: " + reason)

def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SecureReleaseDenied("Release preflight refused: noncanonical JSON") from exc

def _validate_claim(claim, now):
    if type(claim) is not dict or set(claim) != _CLAIM or len(_canonical(claim)) > 2500:
        _deny("claim fields")
    for key in ("candidate_sha", "installer_sha256",
                "components_manifest_sha256", "review_evidence_sha256",
                "machine_identity_sha256"):
        pattern = _SHA40 if key == "candidate_sha" else _SHA64
        if type(claim[key]) is not str or not pattern.fullmatch(claim[key]):
            _deny("invalid immutable release hash")
    for key in ("owner_id", "reviewer_id", "witness_id"):
        if type(claim[key]) is not str or not _ID.fullmatch(claim[key]):
            _deny("invalid independent identity")
    if (len({claim["owner_id"], claim["reviewer_id"], claim["witness_id"]}) != 3
            or type(claim["nonce"]) is not str or not _NONCE.fullmatch(claim["nonce"])
            or claim["schema"] != "neurofactory.onepc.release_claim.v1"
            or claim["repository"] != REPOSITORY
            or claim["review_verdict"] != "APPROVE"
            or claim["scope"] != "REVIEWED_INSTALL_ONLY_NO_AUTORUN"
            or claim["service_name"] != "NeurofactoryCoreHost"):
        _deny("authority scope or identities")
    if (type(now) is not int or now <= 0 or
            any(type(claim[x]) is not int for x in
                ("issued_unix","expires_unix","external_epoch")) or
            claim["external_epoch"] <= 0 or
            claim["issued_unix"] <= 0 or
            not claim["issued_unix"] <= now < claim["expires_unix"] or
            claim["expires_unix"]-claim["issued_unix"] > 3600):
        _deny("expired or out-of-bounds release")
    return _canonical(claim)

def _verify_signature(role, envelope, claim, key):
    if (type(envelope) is not dict or
            set(envelope) != {"role","claim","signature_base64"} or
            envelope["role"] != role or envelope["claim"] != claim or
            not isinstance(key, Ed25519PublicKey) or
            type(envelope["signature_base64"]) is not str or
            len(envelope["signature_base64"]) != 88):
        _deny("role signature envelope")
    try:
        raw = base64.b64decode(envelope["signature_base64"], validate=True)
        if len(raw) != 64:
            _deny("signature byte length")
        key.verify(raw, _DOMAIN[role] + _canonical(claim))
    except (binascii.Error, InvalidSignature, ValueError, TypeError) as exc:
        raise SecureReleaseDenied("Release preflight refused: untrusted role signature") from exc

def check_signed_release_preflight(*, signatures, pinned_keys, operator_expected,
                                   now_unix, observed_installer_sha256,
                                   observed_manifest_sha256):
    """Offline three-signer check. Does not enroll, start, install or approve.

    'operator_expected' and 'pinned_keys' must be supplied by a trusted
    operator-controlled OS boundary, never taken from UI, signed envelope,
    model response, Git repo, or environment variables. In particular,
    checking this function cannot establish physical device identity.
    """
    if (type(signatures) is not dict or set(signatures) != set(_DOMAIN)
            or type(pinned_keys) is not dict or set(pinned_keys) != set(_DOMAIN)
            or type(operator_expected) is not dict or set(operator_expected) != _EXPECTED
            or type(now_unix) is not int or
            type(observed_installer_sha256) is not str or
            not _SHA64.fullmatch(observed_installer_sha256) or
            type(observed_manifest_sha256) is not str or
            not _SHA64.fullmatch(observed_manifest_sha256)):
        _deny("untrusted trust inputs")
    key_bytes = []
    from cryptography.hazmat.primitives import serialization
    for role in _DOMAIN:
        key = pinned_keys[role]
        if not isinstance(key, Ed25519PublicKey):
            _deny("externally pinned public keys required")
        key_bytes.append(key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))
    if len(set(key_bytes)) != 3:
        _deny("owner reviewer and witness cannot share signing identity")
    reviewer = signatures["reviewer"]
    if type(reviewer) is not dict:
        _deny("missing review")
    claim = reviewer.get("claim")
    claim_bytes = _validate_claim(claim, now_unix)
    for key in _EXPECTED:
        if key == "minimum_external_epoch":
            if (type(operator_expected[key]) is not int or
                    operator_expected[key] < 1 or
                    claim["external_epoch"] < operator_expected[key]):
                _deny("outside independent anti-rollback policy")
        elif claim[key] != operator_expected[key]:
            _deny("not operator-pinned release target")
    if (claim["installer_sha256"] != observed_installer_sha256 or
            claim["components_manifest_sha256"] != observed_manifest_sha256):
        _deny("actual staged installer or manifest differs")
    if len(_canonical(signatures)) > _MAX_BYTES:
        _deny("oversized signature packet")
    for role in _DOMAIN:
        _verify_signature(role, signatures[role], claim, pinned_keys[role])
    return {
        "schema": "neurofactory.onepc.reviewed_preflight_report.v1",
        "status": "THREE_SIGNATURES_MATCH_NOT_INSTALL_AUTHORIZATION",
        "candidate_sha": claim["candidate_sha"],
        "installer_sha256": claim["installer_sha256"],
        "components_manifest_sha256": claim["components_manifest_sha256"],
        "signed_claim_sha256": sha256(claim_bytes).hexdigest(),
        "owner_signature_checked": True,
        "independent_reviewer_signature_checked": True,
        "independent_witness_signature_checked": True,
        "external_epoch_claim_checked_against_supplied_minimum": True,
        "physical_machine_identity_independently_attested": False,
        "witness_physically_independent_attested": False,
        "windows_service_acl_verified": False,
        "keys_independently_enrolled_on_owner_pc": False,
        "genuine_qwen_and_privileged_host_single_run_verified": False,
        "independent_review_provenance_verified_online": False,
        "release_authorized": False,
        "service_install_allowed": False,
        "owner_pc_edited": False,
        "automatic_code_effects_allowed": False,
        "auto_merge_allowed": False,
        "unapproved_skills_allowed": False,
    }
