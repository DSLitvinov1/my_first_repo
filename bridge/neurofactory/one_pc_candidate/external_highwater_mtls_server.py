"""Reference independent Linux-node mTLS witness server (no key provisioning).

An independent operator MUST first provision isolated persistent storage,
pin owner-approved exact client DER identity/release/machine hashes and
install distinct TLS/Ed25519 private keys outside CORE/Windows/ChatGPT.
This module never generates keys, chooses a publisher, deploys a service,
or permits host effects. For ACCEPTANCE, use a physically distinct node.

One authenticated client at a time. The signed ACK is returned ONLY AFTER
SQLite committed the epoch and operation; lost reply remains UNKNOWN and
client MUST NOT retry that operation. No rollback, delete, reset endpoint.

Networking runs only when an external operator invokes serve_once/serve_loop
with independently pinned parameters; this file has NO autorun CLI.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import ssl
import stat
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from independent_witness_receipt import _canonical, _claim, parse_bounded_witness_reply
from external_highwater_store import reserve_external_epoch, _file, _parent, HighwaterStoreDenied
from remote_highwater_client import _recv_exact, _operator_file

class MTLSServerDenied(ValueError):
    pass

def _deny(message):
    raise MTLSServerDenied("Independent mTLS witness not provisioned: "+message)

def _operator_tls_server_context(server_cert:Path,server_key:Path,
                                 trusted_clients_ca:Path):
    for path,private in ((server_cert,False),(server_key,True),(trusted_clients_ca,False)):
        _operator_file(path,private=private)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(server_cert),str(server_key))
    context.verify_mode=ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(trusted_clients_ca))
    return context

def _load_private_witness_signer(path:Path):
    _operator_file(path,private=True)
    if os.name!="posix" or os.geteuid()==0:
        _deny("non-root separate Linux service principal required")
    try:
        st=path.stat()
        if st.st_uid!=os.geteuid() or st.st_mode&0o077:
            _deny("witness private key not isolated")
        raw=path.read_bytes()
        if len(raw)!=32:
            _deny("operator Ed25519 signer must be exactly 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (OSError,ValueError) as exc:
        raise MTLSServerDenied("Untrusted independent witness signing key") from exc

def exchange_one_connected(*,tls,client_der_sha256:str,
                           operator_pinned_client_der_sha256:str,
                           database:Path, signer,
                           witness_id:str,machine_sha256:str,
                           package_sha256:str,source_sha40:str,
                           now_unix:int):
    """Handle one already mutually authenticated TLS1.3 session, no retries."""
    if (tls.version()!="TLSv1.3" or
        type(client_der_sha256) is not str or
        client_der_sha256!=operator_pinned_client_der_sha256 or
        len(client_der_sha256)!=64):
        _deny("client certificate not independently pinned")
    n=struct.unpack("!I",_recv_exact(tls,4))[0]
    if n<250 or n>1500:
        _deny("oversized/undersized witness request")
    raw=_recv_exact(tls,n)
    claim=parse_bounded_witness_reply(raw)
    _claim(claim)
    # This request is from a mutually authenticated, pinned client.
    # Independently provisioned server metadata is not client-controlled.
    ack=reserve_external_epoch(
        database=database,claim=claim,
        private_witness_signer=signer,
        operator_pinned_witness_id=witness_id,
        operator_pinned_machine_identity_sha256=machine_sha256,
        operator_pinned_package_sha256=package_sha256,
        operator_pinned_source_sha40=source_sha40,
        now_unix=now_unix)
    reply=_canonical(ack)
    if not 80<=len(reply)<=3500:
        _deny("signed ACK unexpectedly outside bounded format")
    tls.sendall(struct.pack("!I",len(reply))+reply)
    return {"status":"DURABLY_RESERVED_AND_SIGNED_NO_TASK_EXECUTION",
            "epoch":claim["external_epoch"],"client_pin_valid":True,
            "host_effect_allowed":False}

def serve_once(*,listen_address:str,port:int,
               server_cert:Path,server_key:Path,trusted_clients_ca:Path,
               pinned_client_der_sha256:str,db:Path,witness_private_key:Path,
               witness_id:str,machine_sha256:str,
               package_sha256:str,source_sha40:str,
               ready_callback=None):
    if (os.name!="posix" or os.geteuid()==0 or
        type(listen_address) is not str or type(port) is not int or
        not 1024<=port<=65535 or
        listen_address in ("0.0.0.0","::","localhost","127.0.0.1") and
        os.getenv("NF_EXTERNAL_WITNESS_EPHEMERAL_CI")!="1"):
        _deny("separate unprivileged Linux operator and explicitly scoped endpoint required")
    _file(db);_parent(db)
    signer=_load_private_witness_signer(witness_private_key)
    ctx=_operator_tls_server_context(server_cert,server_key,trusted_clients_ca)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((listen_address,port))
        listener.listen(1)
        listener.settimeout(8)
        if ready_callback is not None:
            ready_callback()
        conn,_=listener.accept()
        with conn:
            conn.settimeout(5)
            with ctx.wrap_socket(conn,server_side=True) as tls:
                der=tls.getpeercert(binary_form=True)
                if type(der) is not bytes:
                    _deny("client mTLS peer certificate unavailable")
                return exchange_one_connected(
                    tls=tls,client_der_sha256=hashlib.sha256(der).hexdigest(),
                    operator_pinned_client_der_sha256=pinned_client_der_sha256,
                    database=db,signer=signer,witness_id=witness_id,
                    machine_sha256=machine_sha256,package_sha256=package_sha256,
                    source_sha40=source_sha40,now_unix=int(time.time()))
