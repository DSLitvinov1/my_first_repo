"""Remote high-water witness wire client; NEVER grants HOST execution.

For an operator-authorized reservation request only. One TLS 1.3 session,
pinned CA/hostname AND exact server DER certificate SHA-256, fixed-size
request/response, independently pinned Ed25519 verifier and monotonic floor.

A timeout has UNKNOWN outcome: remote state may have committed already.
The caller must not retry automatically or issue an effect on failure.

No remote server/owner credentials are provisioned by this module. Do not
take pins, client key paths, machine identity or minimum epoch from Qwen,
web UI, signed reply or writable workspace. An actual independent node and
client-certificate OS access controls require separate physical acceptance.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import time

from independent_witness_receipt import (
    IndependentWitnessDenied, _claim, _canonical,
    parse_bounded_witness_reply, verify_external_witness_receipt,
)

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_HOSTNAME = re.compile(r"[a-zA-Z0-9.-]{4,250}\Z")


class RemoteHighwaterDenied(ValueError):
    pass


def _deny(message):
    raise RemoteHighwaterDenied("External monotonic witness UNKNOWN / NO AUTO RETRY: " + message)


def _operator_file(path: Path, *, private=False):
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _deny("independent operator certificate/key path invalid")
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 32768:
            _deny("operator certificate/key file invalid")
        if os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            _deny("Windows reparse point in operator material")
        if private and os.name == "posix" and info.st_mode & 0o077:
            _deny("private TLS client key can be read outside owner")
    except OSError as exc:
        raise RemoteHighwaterDenied("External monotonic witness: missing protected operator file") from exc


def _verified_public_peer(peer: tuple):
    try:
        addr = ipaddress.ip_address(peer[0].split("%")[0])
    except (ValueError,TypeError,IndexError) as exc:
        raise RemoteHighwaterDenied("External monotonic witness: unverified remote IP") from exc
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        _deny("no localhost, multicast or link-local witness")
    if getattr(addr,"ipv4_mapped",None) and addr.ipv4_mapped.is_loopback:
        _deny("IPv4-mapped localhost witness forbidden")


def _recv_exact(sock,n):
    out=bytearray()
    while len(out)<n:
        bit=sock.recv(n-len(out))
        if not bit:
            _deny("response truncated; remote reservation outcome unknown")
        out.extend(bit)
    return bytes(out)


def _wire_exchange(*, hostname: str, port: int, claim: dict,
                   ca_path: Path, client_cert_path: Path, client_key_path: Path,
                   independently_pinned_server_der_sha256: str):
    if (type(hostname) is not str or not _HOSTNAME.fullmatch(hostname)
        or hostname.lower() in ("localhost","localhost.localdomain")
        or type(port) is not int or not 1 <= port <= 65535
        or type(independently_pinned_server_der_sha256) is not str
        or not _HASH.fullmatch(independently_pinned_server_der_sha256)):
        _deny("untrusted remote endpoint or certificate fingerprint")
    for file,private in ((ca_path,False),(client_cert_path,False),(client_key_path,True)):
        _operator_file(file,private=private)
    data=_claim(claim)
    if len(data)>3500:
        _deny("request too large")
    context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=str(ca_path))
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.check_hostname=True
    context.verify_mode=ssl.CERT_REQUIRED
    context.load_cert_chain(str(client_cert_path),str(client_key_path))
    # Deliberate single attempt: unknown result must NOT be auto-retried.
    try:
        with socket.create_connection((hostname,port),timeout=5) as raw:
            raw.settimeout(5)
            _verified_public_peer(raw.getpeername())
            with context.wrap_socket(raw,server_hostname=hostname) as tls:
                if tls.version() != "TLSv1.3":
                    _deny("TLS downgraded")
                der=tls.getpeercert(binary_form=True)
                if type(der) is not bytes or (
                    hashlib.sha256(der).hexdigest() !=
                    independently_pinned_server_der_sha256):
                    _deny("remote server certificate identity mismatch")
                tls.sendall(struct.pack("!I",len(data))+data)
                size=struct.unpack("!I",_recv_exact(tls,4))[0]
                if size<80 or size>3500:
                    _deny("response frame size rejected")
                return parse_bounded_witness_reply(_recv_exact(tls,size))
    except (socket.timeout,ConnectionError,OSError,ssl.SSLError,ValueError,struct.error) as exc:
        raise RemoteHighwaterDenied(
            "External monotonic witness UNKNOWN / NO AUTO RETRY: TLS request not verified") from exc


def observe_remote_reservation(*, hostname: str, port: int, claim: dict,
                               ca_path: Path, client_cert_path: Path,
                               client_key_path: Path,
                               independently_pinned_server_der_sha256: str,
                               independently_pinned_witness_public,
                               independently_pinned_witness_id: str,
                               independently_observed_minimum_epoch: int,
                               now_unix: int):
    """Reserve once with live remote witness; no authority/side effect granted."""
    try:
        _claim(claim)
        receipt=_wire_exchange(
            hostname=hostname,port=port,claim=claim,
            ca_path=ca_path,client_cert_path=client_cert_path,
            client_key_path=client_key_path,
            independently_pinned_server_der_sha256=independently_pinned_server_der_sha256)
        checked=verify_external_witness_receipt(
            claim=claim,receipt=receipt,
            pinned_witness_public=independently_pinned_witness_public,
            independently_pinned_witness_id=independently_pinned_witness_id,
            independently_observed_minimum_epoch=independently_observed_minimum_epoch,
            now_unix=now_unix)
    except (IndependentWitnessDenied,RemoteHighwaterDenied) as exc:
        raise RemoteHighwaterDenied(
            "External monotonic witness UNKNOWN / NO AUTO RETRY: verification denied") from exc
    # A verified signed remote ACK alone cannot establish independent
    # hardware/storage custody or authorize a task. That remains a separate
    # operator/physical acceptance gate.
    return {
        "schema":"nf.onepc.remote_highwater_wire_observation.v1",
        "status":"REMOTE_SIGNED_RESERVATION_OBSERVED_NOT_EFFECT_AUTHORIZED",
        "source_sha40":claim["source_sha40"],
        "package_sha256":claim["package_sha256"],
        "witness_id":checked["witness_id"],
        "witness_claim_sha256":checked["claim_sha256"],
        "highwater_epoch":checked["highest_committed_epoch"],
        "tls_authenticated_with_pinned_certificate":True,
        "signed_receipt_verified":True,
        "remote_storage_is_physically_independent_attested":False,
        "external_rollback_protection_proven":False,
        "production_service_install_allowed":False,
        "host_effect_allowed":False,
        "retry_after_unknown_allowed":False,
    }
