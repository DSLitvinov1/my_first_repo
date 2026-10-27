"""Operator-controlled persistent witness service on an INDEPENDENT Linux VPS.

This program has no key generation, production-approval, model or Windows
deployment capability. It uses exact OS-provisioned trust anchors from
/etc/neurofactory/witness/production.json; private signer and TLS key must be
separately provisioned in /var/lib/neurofactory-witness, not in GitHub.
The sole allowed effect is irreversible reservation of an external epoch.

No production service is considered trustworthy until a separate human
operator provisions physical independence, private VPN networking, exact
client identity, immutable reviewed binary and signed reviewer approval.
"""
from __future__ import annotations
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import struct
import sys
import time
import threading

from external_highwater_store import _file, _parent, inspect_external_highwater
from external_highwater_mtls_server import (
    _operator_tls_server_context, _load_private_witness_signer,
    exchange_one_connected,
)

CONF_DIR=Path("/etc/neurofactory/witness")
CONF=CONF_DIR/"production.json"
STATE=Path("/var/lib/neurofactory-witness")
DB=STATE/"remote-ledger.sqlite3"
TLS_CERT=CONF_DIR/"server.pem"
TLS_CA=CONF_DIR/"clients-ca.pem"
TLS_KEY=STATE/"server.key"
SIGNER=STATE/"witness-private.key"

HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
ID=re.compile(r"[A-Za-z0-9_.:-]{3,96}\Z")
FIELDS=frozenset((
    "schema","listen_address","port","witness_id",
    "client_der_sha256","machine_sha256","package_sha256","source_sha40",
))
class DaemonDenied(ValueError): pass
def _deny(why): raise DaemonDenied("NF independent witness NOT READY: "+why)

def parse_operator_config(raw:bytes,*,enforce_private_bind:bool=True):
    if type(raw) is not bytes or not 200<=len(raw)<=3500:
        _deny("missing, oversized or nonbytes operator configuration")
    def distinct(items):
        d={}
        for k,v in items:
            if k in d: _deny("duplicate trust pin")
            d[k]=v
        return d
    try:
        info=json.loads(raw.decode("ascii"),object_pairs_hook=distinct,
                        parse_constant=lambda _: _deny("invalid JSON constant"))
    except (UnicodeError,TypeError,ValueError,RecursionError) as e:
        raise DaemonDenied("NF independent witness NOT READY: malformed config") from e
    if type(info) is not dict or set(info)!=FIELDS or info["schema"]!="nf.witness.vps.operator_config.v1":
        _deny("operator-owned config schema not exact")
    if (type(info["port"]) is not int or not 1024<=info["port"]<=65535
        or type(info["witness_id"]) is not str or not ID.fullmatch(info["witness_id"])
        or any(type(info[k]) is not str or not (HEX40 if k=="source_sha40" else HEX64).fullmatch(info[k])
                for k in ("client_der_sha256","machine_sha256","package_sha256","source_sha40"))):
        _deny("invalid pinned identities, port or release")
    try:
        if type(info["listen_address"]) is not str: _deny("IP literal required")
        addr=ipaddress.ip_address(info["listen_address"])
    except ValueError as e:
        raise DaemonDenied("NF independent witness NOT READY: numeric IPv4 bind required") from e
    # Default production policy: explicit RFC1918 VPN subnet, not public IP,
    # Tailscale magic address, localhost or wildcard. Port firewall mandatory.
    if enforce_private_bind and (
        addr.version!=4 or not any(addr in ipaddress.ip_network(s) for s in
            ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))):
        _deny("witness must bind a specifically approved private IPv4 interface")
    return info

def read_locked_operator_config():
    if os.name!="posix" or os.geteuid()==0:
        _deny("must run as its own non-root Linux service identity")
    try:
        root=CONF_DIR.lstat();st=CONF.lstat()
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid!=0 or root.st_mode&0o022 or
            not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or
            st.st_size>3500 or st.st_size<200 or
            CONF_DIR.is_symlink() or CONF.is_symlink()):
            _deny("operator trust root must be owned by root, non-writable to service")
        raw=CONF.read_bytes()
    except OSError as e:
        raise DaemonDenied("NF independent witness NOT READY: protected operator pins absent") from e
    return parse_operator_config(raw)

def check_witness_files():
    _file(DB);_parent(DB)
    for p in (TLS_KEY,SIGNER):
        if p.is_symlink() or not p.is_file(): _deny("operator secret missing or linked")
        st=p.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077:
            _deny("private key readable by other principal")
    for p in (TLS_CERT,TLS_CA):
        if p.is_symlink() or not p.is_file() or p.lstat().st_uid!=0:
            _deny("root-owned pinned TLS certificate/CA absent")

def serve_bound_service(*,settings,db:Path,signer,ssl_context,
                        stop_event=None,ready_callback=None):
    # Caller must already have verified protected configuration, TLS material,
    # independent witness signing key and existing durable ledger.
    info=parse_operator_config(json.dumps(settings).encode("ascii"),
                                enforce_private_bind=True)
    stop=stop_event if stop_event is not None else threading.Event()
    processed=0
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((info["listen_address"],info["port"]))
        listener.listen(4)
        listener.settimeout(0.5)
        if ready_callback:ready_callback()
        while not stop.is_set():
            try:
                raw,_=listener.accept()
            except socket.timeout:
                continue
            with raw:
                raw.settimeout(5)
                try:
                    with ssl_context.wrap_socket(raw,server_side=True) as tls:
                        der=tls.getpeercert(binary_form=True)
                        if not isinstance(der,bytes):
                            _deny("client TLS peer identity absent")
                        exchange_one_connected(
                            tls=tls,client_der_sha256=sha256(der).hexdigest(),
                            operator_pinned_client_der_sha256=info["client_der_sha256"],
                            database=db,signer=signer,witness_id=info["witness_id"],
                            machine_sha256=info["machine_sha256"],
                            package_sha256=info["package_sha256"],
                            source_sha40=info["source_sha40"],
                            now_unix=int(time.time()),
                        )
                        processed+=1
                except (ssl.SSLError,TimeoutError,OSError,ValueError,struct.error):
                    # Request refused with no ACK: if the durable write already
                    # occurred, the remote operation is irreversibly UNKNOWN.
                    # Never auto-retry for the caller, NEVER create a new epoch.
                    # Do not log client body, keys, or model data.
                    continue
    return {"status":"STOPPED_BY_OPERATOR","accepted":processed,
            "execution_authority":False}

def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    if argv not in (["--serve"],["--audit"]):
        _deny("only operator-provisioned serve or read-only audit accepted")
    info=read_locked_operator_config()
    check_witness_files()
    signer=_load_private_witness_signer(SIGNER)
    observation=inspect_external_highwater(DB)
    if observation["highest_committed_epoch"]<0: _deny("invalid durable highwater")
    if argv==["--audit"]:
        print(json.dumps({
          "schema":"nf.witness.vps.readonly_audit.v1",
          "status":"OPERATOR_PINS_AND_LOCAL_LEDGER_OBSERVED_NO_PHYSICAL_ATTESTATION",
          "epoch":observation["highest_committed_epoch"],
          "accepted_operations":observation["reserved_operations"],
          "production_host_effects":False,"node_physical_independence_verified":False,
        },sort_keys=True),flush=True)
        return
    context=_operator_tls_server_context(TLS_CERT,TLS_KEY,TLS_CA)
    stop=threading.Event()
    def handle_signal(_signal,_frame): stop.set()
    signal.signal(signal.SIGTERM,handle_signal)
    signal.signal(signal.SIGINT,handle_signal)
    print("NF_WITNESS_VPS_MTLS_ON_PRIVATE_INTERFACE=ACTIVE_NO_HOST_AUTHORITY",flush=True)
    serve_bound_service(settings=info,db=DB,signer=signer,
                        ssl_context=context,stop_event=stop)

if __name__=="__main__":
    main()
