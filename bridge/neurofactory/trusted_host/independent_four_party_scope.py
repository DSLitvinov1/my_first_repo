"""Independent 4-party signed-scope verification CANDIDATE for TRUSTED HOST.

This cryptographic layer has NO file/database/network operations, no key
generation, no fixture-mode env shortcuts and no permission to execute an
effect. Pinned public keys MUST be loaded out-of-band from independently
protected operator/signer/witness stores. The operator's ACL signature is
not a real-time GitHub API query. Neither this verifier nor signed messages
can prove durable witness storage, fresh lease linearisation, hardware
identity, OS-key custody, permission to run or REVIEW sign-off.

The returned result is intentionally NEVER a production execution permit.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ProductionScopeRejected(ValueError):
    pass


DOMAIN = b"NEUROFACTORY_INDEPENDENT_EFFECT_SCOPE_V1\x00"
ROLES = ("operator", "owner", "host", "witness")
EXP_FIELDS = frozenset((
    "owner_id", "repository", "github_user_id", "repository_id",
    "project_id", "task_id", "operation_id", "worker_id", "source_sha40",
    "source_file_sha256", "target", "content_sha256", "policy_sha256",
    "lease_epoch", "fencing_token_sha256", "idempotency_key",
    "challenge_sha256",
))
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
IDENT = re.compile(r"[A-Za-z0-9_.:-]{3,90}\Z")
NUMID = re.compile(r"[1-9][0-9]{0,19}\Z")
TARGET_PREFIX = "bridge/neurofactory/development/core_owned/"
SIGNED = frozenset(("body", "signature_base64"))
OPERATOR_FIELDS = frozenset((
    "schema", "scope_sha256", "owner_id", "repository", "github_user_id",
    "repository_id", "permission", "source", "checked_unix", "expires_unix",
))
OWNER_FIELDS = frozenset(("schema", "scope_sha256", "expires_unix"))
HOST_FIELDS = frozenset((
    "schema", "scope_sha256", "lease_epoch", "fencing_token_sha256",
    "state", "issued_unix", "expires_unix",
))
WITNESS_FIELDS = frozenset((
    "schema", "scope_sha256", "commit_sequence",
    "protected_journal_root_sha256", "reservation_status",
    "issued_unix", "expires_unix",
))


def _deny():
    raise ProductionScopeRejected("independent source, scope or signer not trusted")


def _canon(payload):
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             allow_nan=False, ensure_ascii=True).encode("ascii")
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        _deny()
    if not 1 <= len(encoded) <= 4096:
        _deny()
    return encoded


def _sha(x):
    return hashlib.sha256(x).hexdigest()


def _validate_scope(scope):
    if type(scope) is not dict or set(scope) != EXP_FIELDS:
        _deny()
    for name in EXP_FIELDS - {"lease_epoch"}:
        if type(scope[name]) is not str or not 1 <= len(scope[name]) <= 260:
            _deny()
    for k in ("source_file_sha256", "content_sha256", "policy_sha256",
              "fencing_token_sha256", "idempotency_key", "challenge_sha256"):
        if not SHA64.fullmatch(scope[k]):
            _deny()
    if not SHA40.fullmatch(scope["source_sha40"]):
        _deny()
    if not REPO.fullmatch(scope["repository"]):
        _deny()
    for k in ("owner_id", "project_id", "task_id", "operation_id", "worker_id"):
        if not IDENT.fullmatch(scope[k]):
            _deny()
    for k in ("github_user_id", "repository_id"):
        if not NUMID.fullmatch(scope[k]):
            _deny()
    if type(scope["lease_epoch"]) is not int or scope["lease_epoch"] < 1:
        _deny()
    target = scope["target"]
    if (not target.startswith(TARGET_PREFIX) or len(target) > 220 or
            any(x in ("", ".", "..") or x.startswith(".") for x in target.split("/")) or
            "\\" in target):
        _deny()
    return _sha(_canon(scope))


def _keys(pinned):
    if type(pinned) is not dict or set(pinned) != set(ROLES):
        _deny()
    hashes = []
    for name in ROLES:
        pub = pinned[name]
        if not isinstance(pub, Ed25519PublicKey):
            _deny()
        raw = pub.public_bytes(serialization.Encoding.Raw,
                               serialization.PublicFormat.Raw)
        if len(raw) != 32:
            _deny()
        hashes.append(raw)
    if len(set(hashes)) != len(ROLES):
        _deny()
    return {_role: _sha(raw) for _role, raw in zip(ROLES, hashes)}


def _signed(envelope, role, pub, expected_fields, scope_hash):
    if type(envelope) is not dict or set(envelope) != SIGNED:
        _deny()
    body = envelope["body"]
    if type(body) is not dict or set(body) != expected_fields:
        _deny()
    if (body.get("schema") != "neurofactory.attested." + role + ".v1" or
            type(body.get("scope_sha256")) is not str or
            body["scope_sha256"] != scope_hash):
        _deny()
    # Validate flat bounded types BEFORE canonical encoding to avoid huge
    # nested/oversize attacker objects consuming work or recursion budget.
    for value in body.values():
        if type(value) is str:
            if not 1 <= len(value) <= 350:
                _deny()
        elif type(value) is int:
            if not 0 <= value < 2**63:
                _deny()
        else:
            _deny()
    sig = envelope["signature_base64"]
    if type(sig) is not str or len(sig) != 88:
        _deny()
    try:
        signature = base64.b64decode(sig, validate=True)
        if len(signature) != 64:
            _deny()
        raw = _canon(body)
        pub.verify(signature, DOMAIN + role.encode("ascii") + b"\x00" + raw)
    except (InvalidSignature, ValueError, binascii.Error, TypeError):
        _deny()
    return body, _sha(raw)


def _valid_time(body, now, *, max_age, max_lifetime):
    issued = body["issued_unix"] if "issued_unix" in body else body["checked_unix"]
    expire = body["expires_unix"]
    if (type(issued) is not int or type(expire) is not int or
            not 1 <= issued <= now or not now < expire or
            now - issued > max_age or expire - issued > max_lifetime):
        _deny()


def inspect_signed_four_party_scope(*, pinned_public_keys,
                                    expected_effect,
                                    signed_operator_acl,
                                    signed_owner_grant,
                                    signed_host_lease,
                                    signed_external_witness,
                                    now_unix):
    """Verify signatures and scope; NEVER grant filesystem/queue authority.

    Actual effect additionally needs a separately privileged OS receiver,
    live PostgreSQL CAS row lock held through fsync/receipt, hardware-backed
    private keys, independent durable witness highwater checked after reboot,
    trusted repo ACL freshness and a separately authenticated human REVIEW.
    """
    if type(now_unix) is not int or not 1 <= now_unix < 2**63:
        _deny()
    scope_hash = _validate_scope(expected_effect)
    key_hashes = _keys(pinned_public_keys)
    op, op_hash = _signed(signed_operator_acl, "operator",
                          pinned_public_keys["operator"], OPERATOR_FIELDS, scope_hash)
    ow, ow_hash = _signed(signed_owner_grant, "owner",
                          pinned_public_keys["owner"], OWNER_FIELDS, scope_hash)
    host, host_hash = _signed(signed_host_lease, "host",
                              pinned_public_keys["host"], HOST_FIELDS, scope_hash)
    witness, witness_hash = _signed(signed_external_witness, "witness",
                                    pinned_public_keys["witness"], WITNESS_FIELDS, scope_hash)
    _valid_time(op, now_unix, max_age=300, max_lifetime=300)
    _valid_time(host, now_unix, max_age=30, max_lifetime=60)
    _valid_time(witness, now_unix, max_age=60, max_lifetime=120)
    if (type(ow["expires_unix"]) is not int or
            not now_unix < ow["expires_unix"] <= op["expires_unix"] or
            ow["expires_unix"] - now_unix > 300):
        _deny()
    if (op["source"] != "AUTHENTICATED_GITHUB_API_OBSERVED_BY_OPERATOR" or
            op["permission"] != "admin" or
            any(type(op[k]) is not str or op[k] != expected_effect[k] for k in
                ("owner_id", "repository", "github_user_id", "repository_id"))):
        _deny()
    if (host["state"] != "CLAIMED" or
            type(host["lease_epoch"]) is not int or
            host["lease_epoch"] != expected_effect["lease_epoch"] or
            type(host["fencing_token_sha256"]) is not str or
            host["fencing_token_sha256"] != expected_effect["fencing_token_sha256"]):
        _deny()
    if (witness["reservation_status"] !=
            "UNKNOWN_DURABLY_RESERVED_NO_AUTO_RETRY" or
            type(witness["commit_sequence"]) is not int or
            witness["commit_sequence"] < 1 or
            type(witness["protected_journal_root_sha256"]) is not str or
            not SHA64.fullmatch(witness["protected_journal_root_sha256"])):
        _deny()
    return {
        "schema": "neurofactory.four_party_scope_diagnostic.v1",
        "status": "FOUR_PINNED_SIGNATURES_SCOPE_MATCH_NO_EXECUTION_AUTHORITY",
        "scope_sha256": scope_hash,
        "pinned_public_key_sha256": key_hashes,
        "signed_document_sha256": {
            "operator": op_hash, "owner": ow_hash,
            "host": host_hash, "witness": witness_hash,
        },
        "signature_checks_passed": 4,
        "external_live_github_acl_rechecked_here": False,
        "external_witness_durable_storage_observed_here": False,
        "real_hardware_key_custody_attested_here": False,
        "live_lease_locked_to_effect_here": False,
        "idempotency_persisted_outside_db_here": False,
        "actual_kernel_reboot_recovery_verified_here": False,
        "two_distinct_physical_nodes_proven_here": False,
        "independent_reviewer_approval_received_here": False,
        "live_execution_allowed": False,
        "release_approved": False,
        "automatic_retry_allowed": False,
        "production_execution_authority": False,
        "handoff": "PAUSED_BY_USER",
    }
