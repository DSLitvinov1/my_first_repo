"""Offline structural checker for *externally collected* two-Windows-device evidence.

NO physical/hardware or key-custody attestation happens here. Signatures only
bind claims to previously and independently enrolled public keys. A passing
report NEVER authorizes production, installation, reboot, queue or HANDOFF.
No network, subprocess, file modifications, credentials or remote commands.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class EvidenceRejected(ValueError):
    pass

def reject():
    raise EvidenceRejected("missing, forged, stale or incomplete two-node evidence")

def canonical(o):
    try:
        return json.dumps(o, ensure_ascii=True, sort_keys=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        reject()

def sha(o):
    return hashlib.sha256(canonical(o)).hexdigest()

def exact(obj, fields):
    if type(obj) is not dict or set(obj) != set(fields):
        reject()

def hexcheck(x, n):
    if type(x) is not str or re.fullmatch("[0-9a-f]{" + str(n) + "}", x) is None:
        reject()

def utc(x):
    if type(x) is not str or len(x) != 20 or not x.endswith("Z"):
        reject()
    try:
        return datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        reject()

def public_pins(pins):
    exact(pins, {"operator", "a", "b", "reviewer"})
    decoded = {}
    for role, value in pins.items():
        if type(value) is not str:
            reject()
        try:
            raw = base64.b64decode(value, validate=True)
            if len(raw) != 32:
                reject()
            decoded[role] = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError):
            reject()
    if len({pins[r] for r in pins}) != 4:
        reject()
    return decoded

def verify(envelope, pub):
    exact(envelope, {"body", "signature_base64"})
    if type(envelope["body"]) is not dict or type(envelope["signature_base64"]) is not str:
        reject()
    if len(canonical(envelope["body"])) > 8192:
        reject()
    try:
        signature = base64.b64decode(envelope["signature_base64"], validate=True)
        if len(signature) != 64:
            reject()
        pub.verify(signature, b"NF_TWO_NODE_EVIDENCE_V1\x00" + canonical(envelope["body"]))
    except (InvalidSignature, ValueError, TypeError):
        reject()
    return envelope["body"]

CASES = (
    "FORGED_OWNER", "WRONG_PEER_IDENTITY", "EXPIRED_FENCE",
    "LOST_ACK", "ONE_SUCCESS", "DB_ROLLBACK_REPLAY",
)

def check(manifest, pins, expected_source_sha):
    """Only checks signed *claims* and internally consistent reboot/ledger order.

    Public keys must come from an independent operator trust store, not the
    supplied manifest. Even synthetic correctly signed evidence is NOT
    hardware proof; an independent REVIEW must inspect physical provenance.
    """
    if len(canonical(manifest)) > 65536:
        reject()
    trusted = public_pins(pins)
    exact(expected_source_sha, {"core", "host", "witness"})
    for value in expected_source_sha.values():
        hexcheck(value, 40)
    exact(manifest, {"schema", "scope", "operator", "a_before", "a_after",
                     "b_before", "b_after", "trials", "review"})
    if manifest["schema"] != "nf.windows.two_node_evidence.v1":
        reject()
    scope = manifest["scope"]
    exact(scope, {"core_sha", "host_sha", "witness_sha", "node_a", "node_b"})
    if any(scope[k + "_sha"] != expected_source_sha[k]
           for k in ("core", "host", "witness")):
        reject()
    if (type(scope["node_a"]) is not str or type(scope["node_b"]) is not str
            or len(scope["node_a"]) < 16 or len(scope["node_b"]) < 16
            or len(scope["node_a"]) > 128 or len(scope["node_b"]) > 128
            or scope["node_a"] == scope["node_b"]):
        reject()
    fingerprint = sha(scope)
    op = verify(manifest["operator"], trusted["operator"])
    exact(op, {"schema", "scope_sha256", "physical_test_authorized",
               "production_execution_authorized"})
    if (op["schema"] != "nf.two_node.operator.v1" or
            op["scope_sha256"] != fingerprint or
            op["physical_test_authorized"] is not True or
            op["production_execution_authorized"] is not False):
        reject()

    reports = {}
    for key, role, phase, device in (
        ("a_before", "a", "BEFORE", "node_a"),
        ("a_after", "a", "AFTER", "node_a"),
        ("b_before", "b", "BEFORE", "node_b"),
        ("b_after", "b", "AFTER", "node_b"),
    ):
        body = verify(manifest[key], trusted[role])
        required = {"schema", "scope_sha256", "device_id", "role",
                    "phase", "boot_marker", "observed_utc"}
        if role == "b":
            required |= {"ledger_sequence", "ledger_root_sha256"}
        exact(body, required)
        if (body["schema"] != "nf.two_node.device_report.v1" or
                body["scope_sha256"] != fingerprint or
                body["device_id"] != scope[device] or
                body["role"] != ("RECEIVER_A" if role == "a" else "WITNESS_B") or
                body["phase"] != phase or type(body["boot_marker"]) is not str or
                not 16 <= len(body["boot_marker"]) <= 128):
            reject()
        utc(body["observed_utc"])
        if role == "b":
            if (type(body["ledger_sequence"]) is not int or
                    body["ledger_sequence"] < 0):
                reject()
            hexcheck(body["ledger_root_sha256"], 64)
        reports[key] = body
    # Claims MUST indicate a real OS boot-ID change on BOTH distinct nodes.
    for node in ("a", "b"):
        before, after = reports[node + "_before"], reports[node + "_after"]
        if (before["boot_marker"] == after["boot_marker"] or
                utc(before["observed_utc"]) >= utc(after["observed_utc"])):
            reject()
    start = reports["b_before"]
    end = reports["b_after"]
    if end["ledger_sequence"] <= start["ledger_sequence"]:
        reject()
    if end["ledger_root_sha256"] == start["ledger_root_sha256"]:
        reject()

    trials = manifest["trials"]
    if type(trials) is not list or len(trials) != 6:
        reject()
    prior_seq, prior_root = start["ledger_sequence"], start["ledger_root_sha256"]
    for i, case in enumerate(CASES):
        trial = trials[i]
        exact(trial, {"body", "signature_a", "signature_b"})
        body = trial["body"]
        exact(body, {"schema", "scope_sha256", "case", "outcome",
                     "file_delta", "witness_sequence", "witness_root_sha256",
                     "auto_retry_allowed", "observed_utc"})
        if (body["schema"] != "nf.two_node.case.v1" or
                body["scope_sha256"] != fingerprint or
                body["case"] != case or
                type(body["file_delta"]) is not int or
                type(body["witness_sequence"]) is not int or
                body["auto_retry_allowed"] is not False):
            reject()
        utc(body["observed_utc"])
        hexcheck(body["witness_root_sha256"], 64)
        verify({"body": body, "signature_base64": trial["signature_a"]}, trusted["a"])
        verify({"body": body, "signature_base64": trial["signature_b"]}, trusted["b"])
        if case == "ONE_SUCCESS":
            if body["outcome"] != "COMPLETED_INERT_ONLY" or body["file_delta"] != 1:
                reject()
        else:
            if body["outcome"] not in ("DENIED", "UNKNOWN_NO_RETRY") or body["file_delta"] != 0:
                reject()
        seq, root = body["witness_sequence"], body["witness_root_sha256"]
        if case in ("LOST_ACK", "ONE_SUCCESS"):
            if seq <= prior_seq or root == prior_root:
                reject()
        elif seq != prior_seq or root != prior_root:
            reject()
        prior_seq, prior_root = seq, root

    if (end["ledger_sequence"] != prior_seq or
            end["ledger_root_sha256"] != prior_root):
        reject()
    review = verify(manifest["review"], trusted["reviewer"])
    exact(review, {"schema", "scope_sha256", "decision", "reviewed_utc",
                   "reviewed_core_sha", "reviewed_host_sha", "reviewed_witness_sha"})
    if (review["schema"] != "nf.two_node.independent_review.v1" or
            review["scope_sha256"] != fingerprint or
            review["decision"] not in ("APPROVE_SANDBOX_ONLY", "REJECT_LIVE", "INCONCLUSIVE") or
            any(review["reviewed_" + k + "_sha"] != expected_source_sha[k]
                for k in ("core", "host", "witness"))):
        reject()
    utc(review["reviewed_utc"])
    return {
        "schema": "nf.two_node.evidence_check_result.v1",
        "signed_claims_structurally_consistent": True,
        "physical_devices_independently_attested": False,
        "protected_key_custody_independently_attested": False,
        "actual_os_reboots_independently_attested": False,
        "independent_reviewer_decision_claimed": review["decision"],
        "can_install_services": False,
        "can_reboot_devices": False,
        "can_enable_production_queue": False,
        "can_resume_handoff": False,
        "production_release_allowed": False,
        "status": "DOCUMENTARY_CONSISTENCY_ONLY_NOT_RELEASE_AUTHORITY",
    }

def _no_duplicate_json_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            reject()
        result[k] = v
    return result

def main():
    # Explicit utility, NEVER a deployment gate. Caller supplies separately
    # enrolled public pins and independently selected exact source SHAs.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--trusted-pins", required=True, type=Path)
    parser.add_argument("--expected-sources", required=True, type=Path)
    args = parser.parse_args()
    try:
        def read(path):
            if path.stat().st_size > 65536:
                reject()
            return json.loads(path.read_text(encoding="utf-8"),
                              object_pairs_hook=_no_duplicate_json_pairs)
        result = check(read(args.manifest), read(args.trusted_pins),
                       read(args.expected_sources))
        print(json.dumps(result, sort_keys=True))
    except (EvidenceRejected, OSError, UnicodeError, ValueError):
        print('{"status":"REJECT_INCOMPLETE_EVIDENCE","production_release_allowed":false}')
    # By design NO CLI invocation can ever be mistaken for CI release PASS.
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
