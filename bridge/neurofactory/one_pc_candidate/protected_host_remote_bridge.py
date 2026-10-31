"""One-shot Windows HOST signed-task -> real independently pinned mTLS witness bridge.

Makes a real TLS request only after validating OWNER and REVIEWER signatures,
trusted operator exact task scope and distinct witness public key.
The signed remote ACK is verified by existing protected_host_task_authority.
It never installs/starts a service, creates a file or permits a production task.

IMPORTANT: operator_expected, pinned public keys, TLS files and epoch floor
MUST be read by an independently provisioned protected OS trust boundary.
This module CANNOT independently attest those origins, machine physical
identity, actual CORE lease or revocation; a successful result is READ ONLY.
"""
from __future__ import annotations

import hmac
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from independent_witness_receipt import _claim, IndependentWitnessDenied
from protected_host_task_authority import (
    _validate_claim, _signer, ProtectedHostTaskDenied,
    verify_one_host_operation,
)
from remote_highwater_client import _wire_exchange, RemoteHighwaterDenied
from protected_host_attempt_ledger import reserve_attempt_once, AttemptLedgerDenied


class BridgeDenied(ValueError):
    pass


class BridgeUnknown(RuntimeError):
    pass


def _deny():
    raise BridgeDenied("HOST signed witness scope refused; no network reservation")


def _same_keys_distinct(*keys):
    if not all(isinstance(k, Ed25519PublicKey) for k in keys):
        _deny()
    raw=[k.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) for k in keys]
    if len(set(raw))!=len(raw):
        _deny()


class OneShotHostWitnessBridge:
    """No auto-retry on any remote uncertainty, even if signed reply is lost."""

    def __init__(self, *, pinned_owner_public, pinned_reviewer_public,
                 pinned_witness_public, pinned_witness_id,
                 operator_expected, trusted_minimum_remote_epoch,
                 tls_hostname, tls_port, tls_ca, tls_client_cert,
                 tls_client_key, pinned_tls_server_der_sha256,
                 operator_protected_attempt_dir: Path):
        _same_keys_distinct(
            pinned_owner_public,pinned_reviewer_public,pinned_witness_public)
        if (type(operator_expected) is not dict or
                type(trusted_minimum_remote_epoch) is not int or
                trusted_minimum_remote_epoch<1 or
                type(pinned_witness_id) is not str or
                not 3<=len(pinned_witness_id)<=96 or
                not all(c.isalnum() or c in "_-.:" for c in pinned_witness_id) or
                type(tls_hostname) is not str or
                type(tls_port) is not int or
                not all(isinstance(x,Path) for x in
                        (tls_ca,tls_client_cert,tls_client_key)) or
                type(pinned_tls_server_der_sha256) is not str):
            _deny()
        self._owner=pinned_owner_public
        self._reviewer=pinned_reviewer_public
        self._witness=pinned_witness_public
        self._witness_id=pinned_witness_id
        self._operator_expected=dict(operator_expected)
        self._floor=trusted_minimum_remote_epoch
        self._hostname=tls_hostname
        self._port=tls_port
        self._ca=tls_ca
        self._cert=tls_client_cert
        self._key=tls_client_key
        self._tls_pin=pinned_tls_server_der_sha256
        if (not isinstance(operator_protected_attempt_dir, Path) or
                not operator_protected_attempt_dir.is_absolute()):
            _deny()
        self._attempt_dir=operator_protected_attempt_dir
        self._spent=False

    def reserve_and_verify_once(self, *, claim, owner_signature,
                                reviewer_signature, witness_claim, now_unix):
        if self._spent:
            raise BridgeUnknown("HOST witness reservation may have occurred; NO REPLAY")
        # Authenticated owner/reviewer + separately pinned exact operation
        # MUST be checked before calling the irreversible external witness.
        try:
            _validate_claim(claim,now_unix)
            _signer(owner_signature,"owner",claim,self._owner)
            _signer(reviewer_signature,"reviewer",claim,self._reviewer)
            operator_fields={
                "source_sha40","package_sha256","machine_identity_sha256",
                "review_evidence_sha256","operation_sha256","payload_sha256",
                "worker_sid","service_sid","task_id","project_id",
                "minimum_external_epoch",
            }
            expected=self._operator_expected
            if set(expected)!=operator_fields:
                _deny()
            if (type(expected["minimum_external_epoch"]) is not int or
                    expected["minimum_external_epoch"]<1 or
                    claim["external_epoch"]<expected["minimum_external_epoch"] or
                    claim["external_epoch"]<self._floor):
                _deny()
            if any(claim[field]!=expected[field]
                   for field in operator_fields-{"minimum_external_epoch"}):
                _deny()
            raw=_claim(witness_claim)
            if not raw:
                _deny()
            for k in ("source_sha40","package_sha256",
                      "machine_identity_sha256","review_evidence_sha256",
                      "operation_sha256","external_epoch","nonce"):
                if witness_claim[k]!=claim[k]:
                    _deny()
        except (ProtectedHostTaskDenied, IndependentWitnessDenied) as exc:
            raise BridgeDenied("HOST signed task / witness scope invalid") from exc
        # Mark the caller spent first. A FULL-synced reservation must persist
        # across process/SCM restart BEFORE the network can reserve remotely.
        # Uncertain local SQLite COMMIT also means UNKNOWN, never retry.
        self._spent=True
        try:
            durable=reserve_attempt_once(self._attempt_dir,claim=claim)
            if durable["status"]!="DURABLY_MARKED_UNKNOWN_NO_AUTO_RETRY":
                raise BridgeUnknown("unexpected durable status; NO RETRY")
        except AttemptLedgerDenied as exc:
            raise BridgeUnknown("durable state missing or replayed; NO RETRY") from exc
        try:
            receipt=_wire_exchange(
                hostname=self._hostname,port=self._port,claim=witness_claim,
                ca_path=self._ca,client_cert_path=self._cert,
                client_key_path=self._key,
                independently_pinned_server_der_sha256=self._tls_pin,
            )
            checked=verify_one_host_operation(
                claim=claim,owner_signature=owner_signature,
                reviewer_signature=reviewer_signature,
                witness_claim=witness_claim,witness_receipt=receipt,
                independently_pinned_owner_key=self._owner,
                independently_pinned_reviewer_key=self._reviewer,
                independently_pinned_witness_key=self._witness,
                independently_pinned_witness_id=self._witness_id,
                operator_expected=dict(self._operator_expected),
                independently_observed_remote_epoch=self._floor,
                now_unix=now_unix,
            )
        except (RemoteHighwaterDenied, ProtectedHostTaskDenied,
                IndependentWitnessDenied, OSError, ValueError) as exc:
            # Remote endpoint may have reserved the epoch before ACK failure.
            raise BridgeUnknown("remote witness UNKNOWN; NO AUTO RETRY") from exc
        if (checked.get("status") !=
                "SIGNED_OWNER_REVIEWER_REMOTE_RESERVATION_MATCH_NO_EFFECT" or
                checked.get("production_task_effect_allowed") is not False or
                checked.get("actual_core_queue_lease_verified") is not False):
            raise BridgeUnknown("unexpected signed task result; NO EFFECT")
        return {
            "schema":"nf.windows.host_remote_signed_bridge.v1",
            "status":"SIGNED_TASK_AND_REMOTE_ACK_VERIFIED_TEST_NO_EFFECT",
            "task_id":claim["task_id"],
            "operation_sha256":claim["operation_sha256"],
            "external_epoch":claim["external_epoch"],
            "owner_signature_verified":True,
            "reviewer_signature_verified":True,
            "witness_signature_verified":True,
            "tls_exact_certificate_pin_checked":True,
            "physical_independence_attested":False,
            "trusted_os_service_identity_attested":False,
            "actual_core_lease_attested":False,
            "production_service_install_allowed":False,
            "production_task_effect_allowed":False,
            "automatic_retry_allowed":False,
            "production_release_approved":False,
        }
