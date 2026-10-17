"""COORD read-only two-*claimed*-node cryptographic witness admission.

Never a release permit, machine hardware attestation, or true independence
certificate. Pinned keys and physical identity hashes MUST come from an
independently authorised operator, never from the signed reports or a model.
No secrets, network, filesystem effects, dispatch or deployments occur here.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class WitnessRejected(ValueError):
    pass


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{3,72}\Z")
_NODE = re.compile(r"node-[a-z0-9-]{1,36}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_ZERO = "0" * 64
_EXPECTED = frozenset({
    "challenge_sha256", "operation_id", "task_id", "project_id",
    "core_sha40", "host_sha40", "content_sha256"
})
_REPORT = frozenset({
    "schema", "node_id", "attempt_nonce", "challenge_sha256",
    "operation_id", "task_id", "project_id", "core_sha40",
    "host_sha40", "content_sha256", "physical_claim_sha256",
    "outcome", "effects_count", "receipt_sha256", "journal_sha256",
    "measured_unix", "live_execution_allowed"
})
_ENVELOPE = frozenset({"payload", "signature_base64"})
_OUTCOMES = {"ONE_SYNTHETIC_EFFECT", "DENIED_NO_EFFECT"}


def _valid(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _canonical(obj):
    try:
        out = json.dumps(obj, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, UnicodeError, ValueError, RecursionError) as exc:
        raise WitnessRejected("witness not canonicalizable") from exc
    if len(out) > 4096:
        raise WitnessRejected("witness too large")
    return out


def _report(envelope, key, *, now_unix, node_id, physical_claim_sha256, expected):
    if type(envelope) is not dict or set(envelope) != _ENVELOPE:
        raise WitnessRejected("invalid signed envelope")
    payload = envelope["payload"]
    if type(payload) is not dict or set(payload) != _REPORT:
        raise WitnessRejected("invalid or missing exact report fields")
    if (payload["schema"] != "neurofactory.two_node_witness.v1" or
            payload["node_id"] != node_id or
            not _valid(node_id, _NODE) or
            payload["physical_claim_sha256"] != physical_claim_sha256 or
            not _valid(payload["physical_claim_sha256"], _SHA64) or
            not _valid(payload["attempt_nonce"], _SHA64) or
            not _valid(payload["receipt_sha256"], _SHA64) or
            not _valid(payload["journal_sha256"], _SHA64) or
            type(payload["effects_count"]) is not int or
            type(payload["measured_unix"]) is not int or
            abs(now_unix - payload["measured_unix"]) > 300 or
            payload["live_execution_allowed"] is not False or
            type(payload["outcome"]) is not str or
            payload["outcome"] not in _OUTCOMES or
            any(payload[name] != expected[name] for name in _EXPECTED)):
        raise WitnessRejected("signed observation not bound to expected trial")
    if ((payload["outcome"] == "ONE_SYNTHETIC_EFFECT" and
            (payload["effects_count"] != 1 or
             payload["receipt_sha256"] == _ZERO)) or
            (payload["outcome"] == "DENIED_NO_EFFECT" and
             (payload["effects_count"] != 0 or
              payload["receipt_sha256"] != _ZERO))):
        raise WitnessRejected("effect count and outcome disagree")
    encoded = envelope["signature_base64"]
    if type(encoded) is not str or len(encoded) != 88:
        raise WitnessRejected("malformed signature string")
    raw = _canonical(payload)
    try:
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64:
            raise WitnessRejected("bad signature length")
        key.verify(signature, raw)
    except (InvalidSignature, binascii.Error, ValueError) as exc:
        raise WitnessRejected("cryptographic signature rejected") from exc
    return payload, hashlib.sha256(raw).hexdigest()


def inspect_two_node_witnesses(envelopes, *, operator_pinned_nodes,
                               expected_trial, now_unix):
    """Read-only validation; ALWAYS forbids release and real execution.

    Two independent *keys* cannot prove two physical machines or authentic
    owner's control. The operator must verify that separately out-of-band.
    This routine cannot promote even valid signed reports into release.
    """
    if (type(now_unix) is not int or not 1 <= now_unix < 2**63 or
            type(envelopes) is not list or len(envelopes) != 2 or
            type(operator_pinned_nodes) is not dict or
            type(expected_trial) is not dict or set(expected_trial) != _EXPECTED):
        raise WitnessRejected("missing trusted trial parameters")
    if (not _valid(expected_trial["challenge_sha256"], _SHA64) or
            not _valid(expected_trial["core_sha40"], _SHA40) or
            not _valid(expected_trial["host_sha40"], _SHA40) or
            not _valid(expected_trial["content_sha256"], _SHA64) or
            not _valid(expected_trial["operation_id"], _ID) or
            not _valid(expected_trial["task_id"], _ID) or
            not _valid(expected_trial["project_id"], _PROJECT)):
        raise WitnessRejected("invalid exact source or challenge pins")
    if len(operator_pinned_nodes) != 2:
        raise WitnessRejected("two externally pinned node keys required")
    for node_id, cfg in operator_pinned_nodes.items():
        if (not _valid(node_id, _NODE) or type(cfg) is not dict or
                set(cfg) != {"public_key", "physical_claim_sha256"} or
                not isinstance(cfg["public_key"], Ed25519PublicKey) or
                not _valid(cfg["physical_claim_sha256"], _SHA64)):
            raise WitnessRejected("invalid separate operator node pin")
    pins = list(operator_pinned_nodes.values())
    if pins[0]["physical_claim_sha256"] == pins[1]["physical_claim_sha256"]:
        raise WitnessRejected("same claimed machine alias reused")
    # Equality for public keys is defined over raw public bytes, not objects.
    from cryptography.hazmat.primitives import serialization
    identity = [
        p["public_key"].public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
        for p in pins
    ]
    if identity[0] == identity[1]:
        raise WitnessRejected("same cryptographic identity reused for both nodes")
    observations = []
    names = set()
    for env in envelopes:
        if type(env) is not dict or type(env.get("payload")) is not dict:
            raise WitnessRejected("unparseable node witness")
        node = env["payload"].get("node_id")
        if type(node) is not str or node not in operator_pinned_nodes or node in names:
            raise WitnessRejected("unknown or duplicated node")
        names.add(node)
        cfg = operator_pinned_nodes[node]
        p, digest = _report(env, cfg["public_key"], now_unix=now_unix,
                            node_id=node,
                            physical_claim_sha256=cfg["physical_claim_sha256"],
                            expected=expected_trial)
        observations.append((p, digest))
    a, b = observations[0][0], observations[1][0]
    if (a["attempt_nonce"] == b["attempt_nonce"] or
            abs(a["measured_unix"] - b["measured_unix"]) > 120 or
            {a["outcome"], b["outcome"]} != _OUTCOMES or
            a["effects_count"] + b["effects_count"] != 1):
        raise WitnessRejected("not one unique winner and one loser")
    return {
        "schema": "neurofactory.two_node_witness_diagnostic.v1",
        "status": "TWO_SIGNED_CLAIMS_PASS_NOT_PHYSICAL_ATTESTATION",
        "project": "НЕЙРОЗАВОД",
        "nodes_claimed": sorted(names),
        "one_reported_effect": True,
        "one_reported_denial": True,
        "report_sha256": sorted([observations[0][1], observations[1][1]]),
        "signature_checks_passed": 2,
        "source_commits_bound": True,
        "hardware_distinctness_independently_proven": False,
        "external_operator_authorization_proven": False,
        "machine_key_custody_attested": False,
        "protected_server_lease_readback_proven": False,
        "independent_review_signoff_authenticated": False,
        "actual_two_physical_hosts_tested_by_this_check": False,
        "live_execution_allowed": False,
        "release_approved": False,
        "publication_allowed": False,
        "automatic_retry_allowed": False,
        "handoff": "PAUSED_BY_USER",
    }
