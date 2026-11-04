"""Operator-pinned real Windows SCM remote witness admission (REVIEW CANDIDATE).

Called inside the restricted LocalService recipient, NEVER by a model, UI or
named-pipe client. The signed HOST scope is loaded from sealed OS-controlled
one-use operator files, not request fields. On an absent/malformed policy,
remote error, expired CORE lease, or lost ACK: deny file effect, NO RETRY.

This integrates the real OneShotScmRecipientFence with the actual SCM
receiver, but is NOT a production release: independent physical custodian,
remote irreversible anchor, owner/reviewer key custody and physical OS ACL
must be confirmed separately. No keys are created by this module.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from protected_host_remote_bridge import OneShotHostWitnessBridge
from scm_one_effect_witness_fence import OneShotScmRecipientFence

POLICY_FILE = "external-signed-witness-policy.json"
SCHEMA = "nf.windows.scm_external_signed_witness.review.v1"
FIELDS=frozenset((
    "schema", "pinned_owner_public_base64", "pinned_reviewer_public_base64",
    "pinned_witness_public_base64", "pinned_witness_id", "operator_expected",
    "trusted_minimum_remote_epoch", "tls_hostname", "tls_port", "tls_ca_path",
    "tls_client_cert_path", "tls_client_key_path", "tls_server_der_sha256",
    "operator_attempt_dir", "operator_fence_dir", "claim",
    "owner_signature", "reviewer_signature", "witness_claim",
))
_SHA64=re.compile(r"[a-f0-9]{64}\Z")


class ScmWitnessPolicyDenied(ValueError):
    pass


def _deny():
    raise ScmWitnessPolicyDenied("SCM REMOTE SIGNED WITNESS REQUIRED: bad/missing sealed operator policy; NO EFFECT")


def _unique(pairs):
    d={}
    for k,v in pairs:
        if k in d:
            _deny()
        d[k]=v
    return d


def _ed25519_pub(encoded):
    if type(encoded) is not str or len(encoded)!=44:
        _deny()
    try:
        data=base64.b64decode(encoded,validate=True)
        if len(data)!=32:
            _deny()
        return Ed25519PublicKey.from_public_bytes(data)
    except (ValueError,TypeError) as exc:
        raise ScmWitnessPolicyDenied("Invalid operator public key") from exc


def _sealed_existing(root, name):
    if (not isinstance(root,Path) or not root.is_absolute()
            or root.is_symlink() or not root.is_dir()):
        _deny()
    path=root/name
    if (path.is_symlink() or not path.is_file() or
            not 200 <= path.stat().st_size <= 16_384):
        _deny()
    return path


def load_scm_witness_guard(*, operator_service_root:Path, core_state:Path,
                           expected_spec_sha256:str,expected_payload_sha256:str,
                           expected_owner:str,actual_worker_sid:str,
                           actual_service_sid:str):
    """Load exactly one operator-pinned, signed witness permit for real SCM.

    The caller is responsible for verifying actual process token, service-SID
    restrictions, NTFS ACL of the trust root, and operator provisioning. This
    function never grants unrestricted/production execution and never signs.
    """
    import os
    if os.name!="nt":
        _deny()
    path=_sealed_existing(operator_service_root,POLICY_FILE)
    try:
        policy=json.loads(path.read_text("ascii"),object_pairs_hook=_unique)
    except (OSError,UnicodeError,ValueError,TypeError) as exc:
        raise ScmWitnessPolicyDenied("No valid operator witness policy") from exc
    if (type(policy) is not dict or set(policy)!=FIELDS
            or policy.get("schema")!=SCHEMA
            or type(policy.get("operator_expected")) is not dict
            or type(policy.get("claim")) is not dict
            or type(policy.get("owner_signature")) is not dict
            or type(policy.get("reviewer_signature")) is not dict
            or type(policy.get("witness_claim")) is not dict
            or type(policy.get("trusted_minimum_remote_epoch")) is not int
            or policy["trusted_minimum_remote_epoch"]<1
            or type(policy.get("tls_port")) is not int
            or not 1<=policy["tls_port"]<=65535
            or type(policy.get("tls_hostname")) is not str
            or type(policy.get("tls_server_der_sha256")) is not str
            or not _SHA64.fullmatch(policy["tls_server_der_sha256"])
            or type(expected_spec_sha256) is not str
            or not _SHA64.fullmatch(expected_spec_sha256)
            or type(expected_payload_sha256) is not str
            or not _SHA64.fullmatch(expected_payload_sha256)):
        _deny()
    expected=policy["operator_expected"]
    claim=policy["claim"]
    if (expected.get("worker_sid")!=actual_worker_sid
            or expected.get("service_sid")!=actual_service_sid
            or claim.get("worker_sid")!=actual_worker_sid
            or claim.get("service_sid")!=actual_service_sid
            or claim.get("payload_sha256")!=expected_payload_sha256
            or claim.get("external_epoch")!=
                   policy["trusted_minimum_remote_epoch"]
            or expected.get("minimum_external_epoch")!=
                   policy["trusted_minimum_remote_epoch"]):
        _deny()
    # Separate immutable paths must be fully provisioned by the operator,
    # not drawn from an untrusted model, named-pipe request or response.
    def protected_path(key):
        raw=policy.get(key)
        if type(raw) is not str or not 3<=len(raw)<=500:
            _deny()
        result=Path(raw)
        if not result.is_absolute() or result.is_symlink():
            _deny()
        return result
    owner=_ed25519_pub(policy["pinned_owner_public_base64"])
    reviewer=_ed25519_pub(policy["pinned_reviewer_public_base64"])
    witness=_ed25519_pub(policy["pinned_witness_public_base64"])
    bridge=OneShotHostWitnessBridge(
        pinned_owner_public=owner,pinned_reviewer_public=reviewer,
        pinned_witness_public=witness,
        pinned_witness_id=policy["pinned_witness_id"],
        operator_expected=expected,
        trusted_minimum_remote_epoch=policy["trusted_minimum_remote_epoch"],
        tls_hostname=policy["tls_hostname"],tls_port=policy["tls_port"],
        tls_ca=protected_path("tls_ca_path"),
        tls_client_cert=protected_path("tls_client_cert_path"),
        tls_client_key=protected_path("tls_client_key_path"),
        pinned_tls_server_der_sha256=policy["tls_server_der_sha256"],
        operator_protected_attempt_dir=protected_path("operator_attempt_dir"),
    )
    fence=OneShotScmRecipientFence(
        operator_fence_dir=protected_path("operator_fence_dir"),
        core_state=core_state,
        expected_spec_sha256=expected_spec_sha256,
        expected_payload_sha256=expected_payload_sha256,
        expected_owner=expected_owner,bridge=bridge,
    )
    # No path, trust key, claim or remote epoch is taken from the user request.
    # A single fixed claim burns the durable local fence BEFORE any TLS byte.
    def verify_before_fixed_effect(signed_pilot_body):
        if (type(signed_pilot_body) is not dict
                or signed_pilot_body.get("task_id")!=claim.get("task_id")
                or signed_pilot_body.get("project_id")!=claim.get("project_id")
                or signed_pilot_body.get("source_sha40")!=claim.get("source_sha40")
                or signed_pilot_body.get("content_sha256")!=claim.get("payload_sha256")):
            _deny()
        proof=fence.reserve_once(
            body=signed_pilot_body,claim=claim,
            owner_signature=policy["owner_signature"],
            reviewer_signature=policy["reviewer_signature"],
            witness_claim=policy["witness_claim"])
        if (proof.get("status")!="LOCAL_INTENT_AND_SIGNED_WITNESS_ACK_OBSERVED_LAB_ONLY"
                or proof.get("owner_reviewer_witness_verified_in_bridge") is not True
                or proof.get("recipient_file_effect_granted_for_production") is not False
                or proof.get("automatic_retry_allowed") is not False
                or proof.get("external_epoch")!=claim["external_epoch"]):
            _deny()
        return proof
    return verify_before_fixed_effect
