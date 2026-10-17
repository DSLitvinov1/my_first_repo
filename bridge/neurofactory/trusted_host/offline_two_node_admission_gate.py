"""Strict pre-install two-node manifest gate. NEVER deploys/reboots a machine.

An out-of-band trusted operator must physically ascertain TWO DIFFERENT
machines, their current hardware identifiers, network certificate identities,
public keys and approved reboot/restore window. The connected owner must
sign the exact approved operations with their real pre-enrolled private key.
This verifier checks signatures/shape only, NOT the factual physical truth
of the signed statements. It never grants deployment/production authority.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class TwoNodeAdmissionDenied(ValueError):
    pass

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_NODE = re.compile(r"nf-node-[a-z0-9-]{8,64}\Z")
_PAYLOAD_KEYS = frozenset(("schema","host","witness","repo_id",
    "operator_id","observed_unix","expires_unix","test_scope_sha256"))
_NODE_KEYS = frozenset(("role","node_id","hardware_fingerprint_sha256",
    "operator_attestation_sha256","tls_certificate_sha256","source_sha40"))
_OWNER_KEYS = frozenset(("schema","operator_payload_sha256",
    "owner_id","repo_id","host_node_id","witness_node_id",
    "approve_reboot_host","approve_restore_host_db",
    "approve_reboot_witness","approved_test_scope_sha256",
    "expires_unix","nonce_sha256"))
_BUNDLE_KEYS = frozenset(("operator_payload","operator_signature_base64",
    "owner_approval","owner_signature_base64"))

def _deny():
    raise TwoNodeAdmissionDenied("two independently authorized physical hosts not demonstrated")

def _canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def _sha(raw):
    return hashlib.sha256(raw).hexdigest()

def _decode(raw,n):
    if type(raw) is not str:
        _deny()
    try:
        decoded=base64.b64decode(raw,validate=True)
    except (ValueError,binascii.Error) as exc:
        raise TwoNodeAdmissionDenied("invalid signature/key encoding") from exc
    if len(decoded)!=n:
        _deny()
    return decoded

def _verify(public,signature,payload):
    try:
        Ed25519PublicKey.from_public_bytes(_decode(public,32)).verify(
            _decode(signature,64),payload)
    except (ValueError,InvalidSignature) as exc:
        raise TwoNodeAdmissionDenied("signature not from pinned authority") from exc

def check_two_node_bundle(bundle,*,operator_public_b64,owner_public_b64,
                          expected_operator_public_sha256,
                          expected_owner_public_sha256,now_unix,
                          consumed_nonce_sha256s=()):
    if type(bundle) is not dict or set(bundle)!=_BUNDLE_KEYS:
        _deny()
    if (type(now_unix) is not int or
        type(expected_operator_public_sha256) is not str or
        type(expected_owner_public_sha256) is not str or
        not _SHA256.fullmatch(expected_operator_public_sha256) or
        not _SHA256.fullmatch(expected_owner_public_sha256)):
        _deny()
    if (_sha(_decode(operator_public_b64,32))!=expected_operator_public_sha256
        or _sha(_decode(owner_public_b64,32))!=expected_owner_public_sha256):
        _deny()
    payload=bundle["operator_payload"]
    approval=bundle["owner_approval"]
    if (type(payload) is not dict or set(payload)!=_PAYLOAD_KEYS or
        type(approval) is not dict or set(approval)!=_OWNER_KEYS):
        _deny()
    if (payload["schema"]!="nf.two_physical_operator_attestation.test.v1"
        or approval["schema"]!="nf.two_physical_owner_consent.test.v1"
        or type(payload["repo_id"]) is not str
        or payload["repo_id"]!="723328237"
        or type(payload["operator_id"]) is not str
        or not 5<=len(payload["operator_id"])<=96
        or type(payload["observed_unix"]) is not int
        or type(payload["expires_unix"]) is not int
        or not now_unix-180<=payload["observed_unix"]<=now_unix
        or not now_unix<payload["expires_unix"]<=now_unix+600
        or type(payload["test_scope_sha256"]) is not str
        or not _SHA256.fullmatch(payload["test_scope_sha256"])):
        _deny()
    host=payload["host"]
    witness=payload["witness"]
    for entry,role in ((host,"HOST"),(witness,"WITNESS")):
        if (type(entry) is not dict or set(entry)!=_NODE_KEYS or
            entry["role"]!=role or
            type(entry["node_id"]) is not str or
            not _NODE.fullmatch(entry["node_id"]) or
            type(entry["source_sha40"]) is not str or
            not _SHA40.fullmatch(entry["source_sha40"])):
            _deny()
        for field in ("hardware_fingerprint_sha256",
                      "operator_attestation_sha256","tls_certificate_sha256"):
            if type(entry[field]) is not str or not _SHA256.fullmatch(entry[field]):
                _deny()
    if (host["node_id"]==witness["node_id"] or
        host["hardware_fingerprint_sha256"]==witness["hardware_fingerprint_sha256"]
        or host["tls_certificate_sha256"]==witness["tls_certificate_sha256"]):
        _deny()
    if (type(approval["owner_id"]) is not str
        or approval["owner_id"]!="151650108"
        or approval["repo_id"]!=payload["repo_id"]
        or approval["host_node_id"]!=host["node_id"]
        or approval["witness_node_id"]!=witness["node_id"]
        or approval["approved_test_scope_sha256"]!=payload["test_scope_sha256"]
        or type(approval["approve_reboot_host"]) is not bool
        or type(approval["approve_restore_host_db"]) is not bool
        or type(approval["approve_reboot_witness"]) is not bool
        or approval["approve_reboot_host"] is not True
        or approval["approve_restore_host_db"] is not True
        or approval["approve_reboot_witness"] is not False
        or type(approval["expires_unix"]) is not int
        or not now_unix<approval["expires_unix"]<=payload["expires_unix"]
        or type(approval["nonce_sha256"]) is not str
        or not _SHA256.fullmatch(approval["nonce_sha256"])
        or approval["nonce_sha256"] in consumed_nonce_sha256s
        or approval["operator_payload_sha256"]!=_sha(_canonical(payload))):
        _deny()
    operator_payload=_canonical(payload)
    owner_payload=_canonical(approval)
    _verify(operator_public_b64,bundle["operator_signature_base64"],
            b"NF-TWO-NODE-OPERATOR-TEST\0"+operator_payload)
    _verify(owner_public_b64,bundle["owner_signature_base64"],
            b"NF-TWO-NODE-OWNER-TEST\0"+owner_payload)
    # This result is not a physical observation or a release ticket.
    # A real independent operator must supply an external hardware/physical
    # witness and sealed replay-resistant nonce storage before deployment.
    return {
        "status":"SIGNED_TWO_NODE_MANIFEST_FORMAT_VALID_TEST_ONLY",
        "operator_payload_sha256":_sha(operator_payload),
        "owner_approval_sha256":_sha(owner_payload),
        "distinct_id_claims_valid":True,
        "physical_distinctness_independently_observed":False,
        "actual_owner_keys_enrolled":False,
        "nonce_consumed_in_durable_external_store":False,
        "installation_permitted":False,
        "reboot_permitted":False,
        "production_authority":False,
    }
