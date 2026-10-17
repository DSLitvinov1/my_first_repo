"""Explicit TEST ONLY mutual-TLS transport for a separately owned effect witness.

This is an isolated loopback protocol test and reusable protocol candidate,
NOT authorization to expose a socket to a network or provision real machines.
Both parties verify a pre-pinned exact peer DER certificate fingerprint,
certificate CA chain/EKU and TLS 1.3; witness independently signs receipts.
No signer key is transmitted to CORE, model or receiver.
"""
from __future__ import annotations
import base64,hashlib,json,os,socket,ssl,struct,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from offline_external_effect_witness import (
    WitnessDenied,canon,sha,validate_claim,reserve,keypair,pin_private_dir)

_MAX=8192
_NAME="nf-witness.test"
_HOST="127.0.0.1"
def _deny():raise WitnessDenied("mutual TLS witness unavailable or unauthenticated")
def _gate():
    if os.getenv("NF_MTLS_WITNESS_TEST_ONLY")!="1":_deny()
def _fingerprint(cert):
    if type(cert) is not bytes or len(cert)<128:_deny()
    return hashlib.sha256(cert).hexdigest()
def _require_fp(p):
    if type(p) is not str or len(p)!=64 or any(c not in "0123456789abcdef" for c in p):
        _deny()
def _read_exact(sock,count):
    result=bytearray()
    while len(result)<count:
        bit=sock.recv(count-len(result))
        if not bit:_deny()
        result.extend(bit)
    return bytes(result)
def _recv(sock):
    count=struct.unpack("!I",_read_exact(sock,4))[0]
    if not 2<=count<=_MAX:_deny()
    value=json.loads(_read_exact(sock,count).decode("ascii"))
    if type(value) is not dict:_deny()
    return value
def _send(sock,value):
    raw=canon(value)
    if not 2<=len(raw)<=_MAX:_deny()
    sock.sendall(struct.pack("!I",len(raw))+raw)
def _owned_key(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file():_deny()
    st=p.stat()
    if st.st_uid!=os.geteuid() or st.st_mode&0o077:_deny()
def _server_context(cert,key,ca):
    _owned_key(key)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert),keyfile=str(key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode=ssl.CERT_REQUIRED
    return ctx
def _client_context(cert,key,ca):
    _owned_key(key)
    ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=str(ca))
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.check_hostname=True
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=str(cert),keyfile=str(key))
    return ctx
def _ack_from_claim(claim):
    return {"schema":"nf.remote_witness.ack.v1",
        "status":"UNKNOWN_DURABLY_RESERVED_NO_AUTO_RETRY",
        "claim_sha256":sha(canon(claim)),
        "target_sha256":sha(claim["target"].encode()),
        "task_sha256":sha((claim["repo_id"]+"|"+claim["task_id"]).encode()),
        "nonce":claim["nonce"],"live_allowed":False}
def serve_test_once(root,port,server_cert,server_key,ca_cert,*,
                    client_cert_sha256,require_signed_scope=False):
    _gate()
    if os.geteuid()==0 or type(port) is not int or not 1024<=port<=65535:_deny()
    _require_fp(client_cert_sha256)
    root=pin_private_dir(root)
    signer=keypair(root)
    ctx=_server_context(server_cert,server_key,ca_cert)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            srv.bind((_HOST,port)) # always loopback, NEVER a public listener
            srv.listen(1);srv.settimeout(8)
            raw,_=srv.accept()
            with raw:
                raw.settimeout(5)
                with ctx.wrap_socket(raw,server_side=True) as tls:
                    if _fingerprint(tls.getpeercert(binary_form=True))!=client_cert_sha256:
                        _deny()
                    request=_recv(tls)
                    if require_signed_scope:
                        from offline_witness_signed_scope_gate import verify_under_witness_uid
                        verified=verify_under_witness_uid(root,request)
                        if verified["status"]!="TWO_INDEPENDENT_SIGNED_SCOPES_MATCH_WITNESS_PIN_TEST_ONLY":
                            _deny()
                        claim=request["claim"]
                    else:
                        claim=request
                        validate_claim(claim)
                    reserve(root,claim) # fsync UNKNOWN only AFTER both signatures in scoped mode
                    ack=_ack_from_claim(claim)
                    if os.getenv("NF_WITNESS_SIMULATE_CRASH_BEFORE_ACK")=="1":
                        return
                    _send(tls,{"ack":ack,"signature_base64":
                          base64.b64encode(signer.sign(canon(ack))).decode("ascii")})
    except (ssl.SSLError,socket.timeout,OSError,ValueError,UnicodeError) as e:
        raise WitnessDenied("fail closed on TLS or witness transport") from e
def request_test_once(host,port,claim,*,client_cert,client_key,ca_cert,
                      pinned_server_cert_sha256,pinned_witness_public_b64,
                      signed_packet=None,signed_owner_grant=None):
    _gate()
    if host!=_HOST or type(port) is not int or not 1024<=port<=65535:_deny()
    validate_claim(claim)
    if (signed_packet is None) != (signed_owner_grant is None):
        _deny()
    wire=(claim if signed_packet is None else {
        "claim":claim,"signed_packet":signed_packet,
        "signed_owner_grant":signed_owner_grant})
    _require_fp(pinned_server_cert_sha256)
    try:
        public=base64.b64decode(pinned_witness_public_b64,validate=True)
        if len(public)!=32:_deny()
        ctx=_client_context(client_cert,client_key,ca_cert)
        with socket.create_connection((host,port),timeout=5) as conn:
            conn.settimeout(5)
            with ctx.wrap_socket(conn,server_hostname=_NAME) as tls:
                if _fingerprint(tls.getpeercert(binary_form=True))!=pinned_server_cert_sha256:
                    _deny()
                _send(tls,wire)
                response=_recv(tls)
        if type(response) is not dict or set(response)!={"ack","signature_base64"}:_deny()
        ack=response["ack"]
        if (type(ack) is not dict or ack!=_ack_from_claim(claim)
            or type(response["signature_base64"]) is not str):_deny()
        signature=base64.b64decode(response["signature_base64"],validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(signature,canon(ack))
        return {"status":"MUTUAL_TLS_REMOTE_WITNESS_DURABLE_TEST_ONLY",
                "claim_sha256":ack["claim_sha256"],
                "auto_retry_allowed":False,"production_authority":False}
    except (ssl.SSLError,OSError,ValueError,UnicodeError,InvalidSignature) as e:
        raise WitnessDenied("fail closed on missing/wrong TLS peer, signed ACK or connection") from e

if __name__=="__main__":
    # No interactive/listening production daemon: at most ONE loopback request.
    if len(sys.argv)!=8 or sys.argv[1] not in (
        "test-serve-once","test-serve-scoped-once"):sys.exit(3)
    try:
        serve_test_once(sys.argv[2],int(sys.argv[3]),sys.argv[4],
                        sys.argv[5],sys.argv[6],client_cert_sha256=sys.argv[7],
                        require_signed_scope=(sys.argv[1]=="test-serve-scoped-once"))
    except Exception:sys.exit(3)
