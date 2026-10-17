"""Outside-worker monotonic effect witness, TEST ONLY on independent Linux UID.

Witness service is a DIFFERENT OS principal from CORE, DB, and effect receiver.
It fsyncs the irreversible target reservation BEFORE signed ACK. Restoring
the whole receiver+PostgreSQL state WITHOUT also rolling this witness back
leaves a durable target marker and denies re-use. A witness on THE SAME
PHYSICAL MACHINE does not resist a whole-machine snapshot rollback. Production
requires separate authorized physical trust domain and authenticated transport.
"""
from __future__ import annotations
import base64,hashlib,json,os,secrets,socket,stat,struct,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class WitnessDenied(ValueError):pass
def deny(reason="witness not trusted"):raise WitnessDenied(reason)
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def pin_private_dir(root):
    p=Path(root)
    if (os.name!="posix" or os.getenv("NF_WITNESS_ISOLATED_TEST_ONLY")!="1"
        or not p.is_absolute() or p.is_symlink() or not p.is_dir()
        or p.name!="nf-witness-store" or os.geteuid()==0):deny()
    st=p.lstat()
    if st.st_uid!=os.geteuid() or st.st_mode&0o077:deny()
    return p
def persist(root,name,raw):
    p=root/name
    fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        os.write(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dirfd)
    finally:os.close(dirfd)
def keypair(root):
    p=root/"witness-key.raw"
    if not p.exists():
        secret=Ed25519PrivateKey.generate()
        data=secret.private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        persist(root,p.name,data)
    st=p.lstat()
    if st.st_uid!=os.geteuid() or st.st_mode&0o077 or not stat.S_ISREG(st.st_mode):deny()
    data=p.read_bytes()
    if len(data)!=32:deny()
    return Ed25519PrivateKey.from_private_bytes(data)
def validate_claim(claim):
    keys={"schema","owner_id","repo_id","task_id","operation_id","target",
          "lease_epoch","permit_sha256","content_sha256","nonce"}
    if type(claim) is not dict or set(claim)!=keys or claim.get("schema")!="nf.remote_witness.claim.v1":deny()
    if claim.get("repo_id")!="723328237" or claim.get("owner_id")!="151650108":deny()
    if (type(claim.get("lease_epoch")) is not int or claim["lease_epoch"]<1
        or any(type(claim.get(k)) is not str for k in keys-{"lease_epoch"})):
        deny()
    for k in ("permit_sha256","content_sha256","nonce"):
        if len(claim[k])!=64 or any(c not in "0123456789abcdef" for c in claim[k]):deny()
    if not claim["task_id"].startswith("NF-DEV-05-Q"):deny()
    if (not claim["target"].startswith("bridge/neurofactory/development/core_owned/")
        or "/../" in claim["target"] or not claim["target"].endswith((".py",".txt"))):deny()
    if not 1<=len(claim["operation_id"])<=96:deny()
    return claim
def reserve(root,claim):
    p=pin_private_dir(root)
    validate_claim(claim)
    target_hash=sha(claim["target"].encode())
    task_hash=sha((claim["repo_id"]+"|"+claim["task_id"]).encode())
    # Single one-shot witness Unix server/process serializes requests via lock.
    import fcntl
    lock=os.open(p/"witness.lock",os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX)
        marker=p/("target-"+target_hash+".json")
        task=p/("task-"+task_hash+".json")
        if marker.exists() or task.exists():deny("effect already reserved remotely")
        record={"schema":"nf.remote_witness.highwater.v1",
                "claim":claim,"result":"EFFECT_RESERVED_REMOTE_UNKNOWN",
                "target_sha256":target_hash,"task_sha256":task_hash}
        raw=canon(record)
        # Unknown even if crash between task and target marker: both block.
        persist(p,task.name,raw)
        persist(p,marker.name,raw)
        return record
    finally:
        fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
def serve_once(root,sockpath,*,pinned_receiver_uid):
    root=pin_private_dir(root)
    if type(pinned_receiver_uid) is not int or pinned_receiver_uid<=0 or pinned_receiver_uid==os.geteuid():deny()
    parent=Path(sockpath).parent
    if (not Path(sockpath).is_absolute() or Path(sockpath).name!="nf-witness.sock"
        or parent.name!="nf-witness-ipc" or parent.is_symlink() or not parent.is_dir()):deny()
    st=parent.lstat()
    if st.st_uid!=os.geteuid() or st.st_mode&0o027:deny()
    if Path(sockpath).exists() or Path(sockpath).is_symlink():deny()
    signer=keypair(root)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as srv:
        srv.settimeout(9);srv.bind(sockpath);os.chmod(sockpath,0o660);srv.listen(1)
        try:
            conn,_=srv.accept()
            with conn:
                conn.settimeout(5)
                pid,uid,gid=struct.unpack("3i",conn.getsockopt(
                    socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
                if pid<=0 or uid!=pinned_receiver_uid:
                    conn.sendall(b'{"status":"DENIED_PEER"}');return
                try:
                    raw=conn.recv(8001)
                    if not raw or len(raw)>8000:deny()
                    claim=json.loads(raw.decode("ascii"))
                    record=reserve(root,claim)
                    ack={"schema":"nf.remote_witness.ack.v1",
                         "status":"UNKNOWN_DURABLY_RESERVED_NO_AUTO_RETRY",
                         "claim_sha256":sha(canon(claim)),"target_sha256":record["target_sha256"],
                         "task_sha256":record["task_sha256"],"nonce":claim["nonce"],
                         "live_allowed":False}
                    signature=signer.sign(canon(ack))
                    response={"ack":ack,"signature_base64":base64.b64encode(signature).decode()}
                    if os.getenv("NF_WITNESS_SIMULATE_CRASH_BEFORE_ACK")=="1":
                        return  # durable marker survived; retry must be denied
                    conn.sendall(canon(response))
                except Exception:
                    conn.sendall(b'{"status":"DENIED_OR_UNKNOWN_MANUAL_STOP"}')
        finally:Path(sockpath).unlink(missing_ok=True)
def request_once(sockpath,claim,*,expected_witness_uid,pinned_witness_public_b64):
    validate_claim(claim)
    pub=base64.b64decode(pinned_witness_public_b64,validate=True)
    if len(pub)!=32 or type(expected_witness_uid) is not int:deny()
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(5);sock.connect(sockpath)
            pid,uid,gid=struct.unpack("3i",sock.getsockopt(
                socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
            if uid!=expected_witness_uid or pid<=0:deny()
            sock.sendall(canon(claim))
            resp=sock.recv(8192)
        data=json.loads(resp.decode("ascii"))
        if type(data) is not dict or set(data)!={"ack","signature_base64"}:deny()
        ack=data["ack"]
        if (type(ack) is not dict or
            ack.get("schema")!="nf.remote_witness.ack.v1" or
            ack.get("status")!="UNKNOWN_DURABLY_RESERVED_NO_AUTO_RETRY" or
            ack.get("claim_sha256")!=sha(canon(claim)) or
            ack.get("nonce")!=claim["nonce"] or
            ack.get("live_allowed") is not False):deny()
        Ed25519PublicKey.from_public_bytes(pub).verify(
            base64.b64decode(data["signature_base64"],validate=True),canon(ack))
        return {"status":"REMOTE_UID_WITNESS_PRECOMMIT_TEST_ONLY",
                "claim_sha256":ack["claim_sha256"],"auto_retry_allowed":False,
                "production_authority":False}
    except (OSError,ValueError,UnicodeError,InvalidSignature) as e:
        raise WitnessDenied("unavailable, stale or forged independent witness") from e

if __name__=="__main__":
    if len(sys.argv)!=4 or sys.argv[1]!="serve":sys.exit(3)
    try:serve_once(sys.argv[2],sys.argv[3],
                    pinned_receiver_uid=int(os.environ["NF_WITNESS_RECEIVER_UID"]))
    except Exception:sys.exit(3)
