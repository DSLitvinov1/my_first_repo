"""Production-oriented four-party signed SINGLE-TASK HOST permit preflight.

This deliberately provides real Ed25519 authorization verification, not
synthetic counters or passwords. Owner and independent reviewer sign the
EXACT SAME one-effect claim; separate remote witness attests a monotonic
reservation bound to the same release, task hash, epoch and nonce.

Important: cryptographic verification alone is not execution permission.
The caller must additionally establish real non-exportable key custody,
immutable OS-installed public pins, current reviewer appointment, physical
Windows SCM token/SID, machine identity, a remote *independent* live node,
and CORE's current leased exact task. NO effects in this module.

Never accept public roots, expected epoch, actual SIDs or machine identity
from Qwen, IPC packets, GitHub repo, or claims as their source of truth.
"""
from __future__ import annotations
import base64
import binascii
from hashlib import sha256
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from independent_witness_receipt import (
    verify_external_witness_receipt, IndependentWitnessDenied,
)

_SHA40=re.compile(r"[0-9a-f]{40}\Z")
_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_SID=re.compile(r"S-1-(?:[0-9]+-){2,14}[0-9]+\Z")
_ID=re.compile(r"[A-Za-z0-9_.:-]{3,90}\Z")
_FIELDS=frozenset({
    "schema","repository","task_id","project_id","source_sha40",
    "package_sha256","machine_identity_sha256","review_evidence_sha256",
    "operation_sha256","payload_sha256","worker_sid","service_sid",
    "operation_type","external_epoch","nonce","issued_unix","expires_unix",
})
_DOMAIN={
    "owner":b"NF_WINDOWS_PROTECTED_HOST_OWNER_TASK_V1\x00",
    "reviewer":b"NF_WINDOWS_PROTECTED_HOST_INDEPENDENT_TASK_REVIEW_V1\x00",
}
_SIGNATURE_FIELDS=frozenset(("role","claim","signature_base64"))

class ProtectedHostTaskDenied(ValueError): pass
def _deny(msg):
    raise ProtectedHostTaskDenied("Protected HOST single-task authority refused: "+msg)

def _canon(data):
    try:
        return json.dumps(data,sort_keys=True,separators=(",",":"),
                          ensure_ascii=True,allow_nan=False).encode("ascii")
    except (ValueError,TypeError,RecursionError,OverflowError) as e:
        raise ProtectedHostTaskDenied("Protected HOST invalid canonical data") from e

def _validate_claim(c,now):
    if type(c) is not dict or set(c)!=_FIELDS:
        _deny("exact claim schema")
    raw=_canon(c)
    if len(raw)>2500 or c["schema"]!="nf.host.one_effect_scope.v1" or \
            c["repository"]!="DSLitvinov1/my_first_repo" or \
            c["operation_type"]!="OWNER_REVIEWED_FIXED_SAFE_FILE_V1":
        _deny("unknown operation type or repository")
    for k in ("task_id","project_id"):
        if type(c[k]) is not str or not _ID.fullmatch(c[k]):_deny("invalid task identity")
    for k in ("source_sha40","package_sha256","machine_identity_sha256",
              "review_evidence_sha256","operation_sha256","payload_sha256","nonce"):
        rgx=_SHA40 if k=="source_sha40" else _SHA64
        if type(c[k]) is not str or not rgx.fullmatch(c[k]):_deny("bad immutable identity")
    for k in ("worker_sid","service_sid"):
        if type(c[k]) is not str or not _SID.fullmatch(c[k]):_deny("untrusted SID")
    if c["worker_sid"]==c["service_sid"]:_deny("worker must have separate principal")
    if (type(now) is not int or now<1
        or any(type(c[k]) is not int for k in ("issued_unix","expires_unix","external_epoch"))
        or c["external_epoch"]<1 or not 0<c["issued_unix"]<=now<c["expires_unix"]
        or c["expires_unix"]-c["issued_unix"]>300):
        _deny("expired, long-lived or invalid external epoch")
    return raw

def _signer(signed,role,claim,key):
    if (type(signed) is not dict or set(signed)!=_SIGNATURE_FIELDS or
        signed["role"]!=role or signed["claim"]!=claim or
        type(signed["signature_base64"]) is not str or
        len(signed["signature_base64"])!=88 or
        not isinstance(key,Ed25519PublicKey)):
        _deny("role-scope envelope or pinned Ed25519 signer")
    try:
        sig=base64.b64decode(signed["signature_base64"],validate=True)
        if len(sig)!=64:_deny("malformed Ed25519 signature")
        key.verify(sig,_DOMAIN[role]+_canon(claim))
    except (InvalidSignature,binascii.Error,TypeError,ValueError) as e:
        raise ProtectedHostTaskDenied("Protected HOST signed role scope invalid") from e

def verify_one_host_operation(*,claim,owner_signature,reviewer_signature,
    witness_claim,witness_receipt,
    independently_pinned_owner_key,independently_pinned_reviewer_key,
    independently_pinned_witness_key,independently_pinned_witness_id,
    operator_expected,independently_observed_remote_epoch,now_unix):
    """Cryptographically verify exact task, separate roles and remote ACK.

    This is a VERIFY-ONLY building block: production authorization remains
    FALSE until other physical independent trust/OS checks are proved.
    """
    raw=_validate_claim(claim,now_unix)
    required=frozenset((
        "source_sha40","package_sha256","machine_identity_sha256",
        "review_evidence_sha256","operation_sha256","payload_sha256",
        "worker_sid","service_sid","task_id","project_id",
        "minimum_external_epoch",
    ))
    if (type(operator_expected) is not dict or set(operator_expected)!=required or
        type(independently_observed_remote_epoch) is not int or
        independently_observed_remote_epoch<1):
        _deny("independent operator-pinned OS input missing")
    for field in required-{"minimum_external_epoch"}:
        if claim[field]!=operator_expected[field]:_deny("not operator-pinned exact task or identity")
    if (type(operator_expected["minimum_external_epoch"]) is not int or
        operator_expected["minimum_external_epoch"]<1 or
        claim["external_epoch"]<operator_expected["minimum_external_epoch"]):
        _deny("operator's remote highwater floor not met")
    a,b,c=independently_pinned_owner_key,independently_pinned_reviewer_key,independently_pinned_witness_key
    if not all(isinstance(x,Ed25519PublicKey) for x in (a,b,c)):_deny("missing distinct signers")
    from cryptography.hazmat.primitives import serialization
    raw_keys=[x.public_bytes(encoding=serialization.Encoding.Raw,
                             format=serialization.PublicFormat.Raw)
              for x in (a,b,c)]
    if len(set(raw_keys))!=3:_deny("review, owner and witness identities shared")
    _signer(owner_signature,"owner",claim,a)
    _signer(reviewer_signature,"reviewer",claim,b)
    if type(witness_claim) is not dict:
        _deny("missing independent external witness claim")
    expected_witness={
        "source_sha40":claim["source_sha40"],
        "package_sha256":claim["package_sha256"],
        "machine_identity_sha256":claim["machine_identity_sha256"],
        "review_evidence_sha256":claim["review_evidence_sha256"],
        "operation_sha256":claim["operation_sha256"],
        "external_epoch":claim["external_epoch"],
        "nonce":claim["nonce"],
    }
    if any(witness_claim.get(k)!=value for k,value in expected_witness.items()):
        _deny("external reservation does not cover exact task and machine")
    try:
        w=verify_external_witness_receipt(
            claim=witness_claim,receipt=witness_receipt,
            pinned_witness_public=c,
            independently_pinned_witness_id=independently_pinned_witness_id,
            independently_observed_minimum_epoch=independently_observed_remote_epoch,
            now_unix=now_unix)
    except IndependentWitnessDenied as exc:
        raise ProtectedHostTaskDenied("Protected HOST remote receipt refused") from exc
    if w["highest_committed_epoch"]!=claim["external_epoch"] or \
            w["production_install_authorized"] is not False:
        _deny("remote reservation epoch or authority wrong")
    return {
        "schema":"nf.host.cryptographic_task_preflight.v1",
        "status":"SIGNED_OWNER_REVIEWER_REMOTE_RESERVATION_MATCH_NO_EFFECT",
        "claim_sha256":sha256(raw).hexdigest(),
        "operation_sha256":claim["operation_sha256"],
        "task_id":claim["task_id"],
        "source_sha40":claim["source_sha40"],
        "remote_epoch":w["highest_committed_epoch"],
        "owner_valid_signature":True,
        "independent_reviewer_valid_signature":True,
        "separate_remote_witness_signature_valid":True,
        "signed_task_is_exact_operator_pinned_scope":True,
        "external_remote_epoch_minimum_observed_from_trusted_node":False,
        "real_windows_worker_sid_checked_by_os":False,
        "real_windows_service_sid_checked_by_os":False,
        "independent_signer_private_key_custody_proven":False,
        "physical_reviewer_reviewed_this_release":False,
        "actual_core_queue_lease_verified":False,
        "untrusted_model_has_execution_permission":False,
        "production_task_effect_allowed":False,
        "automatic_replay_allowed":False,
    }
