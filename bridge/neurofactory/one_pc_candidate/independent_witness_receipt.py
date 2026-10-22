"""Verify a strictly pinned, separately signed external high-water observation.

This module parses signed witness evidence but does NOT contact the witness,
verify physical separation, install keys, advance remote counters, or permit
Windows SCM installation. A witness on the same revertible disk is insufficient.

External trust inputs MUST arrive from an independently authenticated owner /
operator boundary; never use witness public keys or minimum epochs sourced
from an arbitrary receipt, UI, Git repo, or model output.
"""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_IDENT = re.compile(r"[a-zA-Z0-9_.:-]{3,96}\Z")
_CLAIM_FIELDS = frozenset({
    "schema", "source_sha40", "package_sha256", "machine_identity_sha256",
    "review_evidence_sha256", "operation_sha256", "external_epoch", "nonce",
})
_EVIDENCE_FIELDS = frozenset({
    "schema", "claim_sha256", "source_sha40", "machine_identity_sha256",
    "witness_id", "highest_committed_epoch", "previous_accepted_epoch",
    "recorded_unix", "expires_unix", "decision", "separate_device_claimed",
})
_RECEIPT_FIELDS = frozenset({"evidence", "signature_base64"})
_DOMAIN = b"NF_ONEPC_EXTERNAL_WITNESS_HIGHWATER_V1\x00"


class IndependentWitnessDenied(ValueError):
    pass


def _deny(reason):
    raise IndependentWitnessDenied("Untrusted external witness: " + reason)


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise IndependentWitnessDenied("Untrusted external witness: invalid canonical packet") from exc


def parse_bounded_witness_reply(raw: bytes):
    """Parse untrusted network JSON without accepting duplicate keys or NaN.

    A verified signed reply remains evidence only; parsing never grants rights.
    """
    if type(raw) is not bytes or not 80 <= len(raw) <= 3500:
        _deny("network reply size")
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:
                _deny("duplicate reply property")
            out[key]=value
        return out
    def reject_constant(value):
        _deny("nonfinite witness JSON")
    try:
        return json.loads(raw.decode("ascii"),object_pairs_hook=unique,
                          parse_constant=reject_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise IndependentWitnessDenied("Untrusted external witness: malformed wire encoding") from exc


def _claim(claim):
    if type(claim) is not dict or set(claim) != _CLAIM_FIELDS:
        _deny("claim fields mismatch")
    if (claim.get("schema") != "nf.onepc.highwater.claim.v1" or
            type(claim.get("source_sha40")) is not str or
            not _HEX40.fullmatch(claim["source_sha40"]) or
            any(type(claim.get(k)) is not str or not _HEX64.fullmatch(claim[k])
                for k in ("package_sha256","machine_identity_sha256",
                          "review_evidence_sha256","operation_sha256")) or
            type(claim.get("external_epoch")) is not int or
            claim["external_epoch"] < 1 or claim["external_epoch"] >= 2**63 or
            type(claim.get("nonce")) is not str or
            not _HEX64.fullmatch(claim["nonce"]) or
            len(_canonical(claim)) > 1500):
        _deny("claim is not immutable or complete")
    return _canonical(claim)


def verify_external_witness_receipt(
        *, claim, receipt, pinned_witness_public,
        independently_pinned_witness_id, independently_observed_minimum_epoch,
        now_unix):
    """Compare an independently *read* remote high-water receipt to a claim.

    No signature checked here can establish actual remote hardware custody or
    establish rollback protection without fresh authenticated remote querying
    and externally protected high-water storage. Callers MUST NOT store their
    own minimum alongside the rollback-prone Windows SQLite database.
    """
    raw_claim = _claim(claim)
    if (type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS or
            type(receipt.get("evidence")) is not dict or
            set(receipt["evidence"]) != _EVIDENCE_FIELDS or
            type(receipt.get("signature_base64")) is not str or
            len(receipt["signature_base64"]) != 88 or
            not isinstance(pinned_witness_public, Ed25519PublicKey) or
            type(independently_pinned_witness_id) is not str or
            not _IDENT.fullmatch(independently_pinned_witness_id) or
            type(independently_observed_minimum_epoch) is not int or
            independently_observed_minimum_epoch <= 0 or
            type(now_unix) is not int or now_unix <= 0):
        _deny("untrusted authority input or receipt shape")
    evidence = receipt["evidence"]
    raw = _canonical(evidence)
    if len(raw) > 2000 or len(_canonical(receipt)) > 3500:
        _deny("oversized witness receipt")
    if (evidence["schema"] != "nf.onepc.external_witness.highwater.v1" or
            evidence["decision"] != "RECORDED_EXTERNALLY_NO_AUTO_RETRY" or
            evidence["separate_device_claimed"] is not True or
            evidence["witness_id"] != independently_pinned_witness_id or
            evidence["claim_sha256"] != sha256(raw_claim).hexdigest() or
            evidence["source_sha40"] != claim["source_sha40"] or
            evidence["machine_identity_sha256"] != claim["machine_identity_sha256"]):
        _deny("witness identity, scope, or claim mismatch")
    for field in ("claim_sha256", "machine_identity_sha256"):
        if type(evidence[field]) is not str or not _HEX64.fullmatch(evidence[field]):
            _deny("untrusted cryptographic binding")
    if type(evidence["source_sha40"]) is not str or not _HEX40.fullmatch(evidence["source_sha40"]):
        _deny("untrusted source binding")
    epoch=evidence["highest_committed_epoch"]
    prev=evidence["previous_accepted_epoch"]
    if (type(epoch) is not int or type(prev) is not int or
            prev < 0 or epoch < 1 or epoch >= 2**63 or
            epoch != claim["external_epoch"] or
            epoch <= prev or epoch < independently_observed_minimum_epoch):
        _deny("external monotonic high-water does not advance")
    recorded=evidence["recorded_unix"]
    expires=evidence["expires_unix"]
    if (type(recorded) is not int or type(expires) is not int or
            not recorded <= now_unix < expires or recorded < 1 or
            expires-recorded > 300):
        _deny("stale or future witness evidence")
    try:
        sig=base64.b64decode(receipt["signature_base64"],validate=True)
        if len(sig)!=64:
            _deny("signature bytes invalid")
        pinned_witness_public.verify(sig, _DOMAIN + raw)
    except (InvalidSignature,TypeError,ValueError,binascii.Error) as exc:
        raise IndependentWitnessDenied("Untrusted external witness: signature invalid") from exc
    return {
        "schema":"nf.onepc.external_witness.observed.v1",
        "status":"SIGNED_HIGHWATER_EVIDENCE_ONLY_NOT_PHYSICAL_ATTESTATION",
        "witness_id":evidence["witness_id"],
        "claim_sha256":evidence["claim_sha256"],
        "highest_committed_epoch":epoch,
        "signature_verified":True,
        "device_separation_independently_attested":False,
        "remote_state_independently_queried":False,
        "receipt_replay_resistant_without_remote_query":False,
        "physical_machine_release_authorized":False,
        "production_install_authorized":False,
        "automatic_task_effects_authorized":False,
    }
