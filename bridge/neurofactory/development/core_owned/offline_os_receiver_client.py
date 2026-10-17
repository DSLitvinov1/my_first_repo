"""CORE-owned one-operation fixture client for OS-separated HOST Unix receiver.

Does NOT write local files or trust model output. Checks local CORE claim,
source scope, proposal digest, and server SO_PEERCRED pinned from operator
config BEFORE asking HOST; HOST alone owns disposable target. Test only.
"""
from __future__ import annotations
import base64,hashlib,hmac,json,os,socket,struct,time

class CoreOSRouteDenied(ValueError):pass

def _deny():raise CoreOSRouteDenied("protected HOST recipient unavailable or unauthorised")

class CoreProtectedUnixReceiverClient:
    def __init__(self,core,*,socket_path,pinned_receiver_uid):
        if (os.name!="posix" or
            os.environ.get("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY")!="1" or
            os.environ.get("NF_RECEIVER_OS_FIXTURE_ONLY")!="1" or
            core is None or type(socket_path) is not str or
            not socket_path.endswith("/nf-recipient-ipc/nf-recipient.sock") or
            type(pinned_receiver_uid) is not int or pinned_receiver_uid<=0):
            _deny()
        self.core=core
        self.socket_path=socket_path
        self.receiver_uid=pinned_receiver_uid
    def propose_once(self,*,task_id,worker_id,core_token,proposal,signed_packet,witness,signed_owner_grant):
        if (type(task_id) is not str or type(worker_id) is not str or
            type(core_token) is not str or type(proposal) is not dict or
            set(proposal)!={"schema","target","content","content_sha256","mode"} or
            proposal.get("schema")!="neurofactory.core.proposal.v1" or
            proposal.get("mode")!="OFFLINE_TEST" or
            type(proposal.get("target")) is not str or
            type(proposal.get("content")) is not str or
            type(proposal.get("content_sha256")) is not str or
            type(signed_packet) is not dict or
            set(signed_packet)!={"payload","signature_base64"} or
            type(witness) is not dict or
            type(signed_owner_grant) is not dict or
            set(signed_owner_grant)!={"statement","signature_base64"} or
            type(signed_owner_grant.get("statement")) is not dict or
            type(signed_owner_grant.get("signature_base64")) is not str):
            _deny()
        content=proposal["content"].encode("utf8")
        if not content or len(content)>65536:
            _deny()
        digest=hashlib.sha256(content).hexdigest()
        if digest!=proposal["content_sha256"]:
            _deny()
        now=int(time.time())
        try:
            with self.core._connect() as conn:
                conn.execute("BEGIN")
                row=self.core._row(conn)
                if (row is None or row["state"]!="CLAIMED" or
                    row["spec"]["task_id"]!=task_id or
                    row["owner"]!=worker_id or row["lease_until"]<=now or
                    not hmac.compare_digest(
                        hashlib.sha256(core_token.encode()).hexdigest(),
                        row["token"]) or
                    row["spec"]["target"]!=proposal["target"]):
                    _deny()
                spec=dict(row["spec"])
        except (OSError,KeyError,TypeError,ValueError):
            _deny()
        payload=signed_packet.get("payload")
        if type(payload) is not dict:
            _deny()
        expected={
          "task_id":task_id,"project_id":spec["project_id"],
          "source_sha40":spec["source_sha"],
          "source_file_sha256":spec["source_sha256"],
          "target":proposal["target"],"worker_id":worker_id,
          "proposed_content_sha256":digest}
        if any(type(payload.get(k))!=type(v) or payload.get(k)!=v
               for k,v in expected.items()):
            _deny()
        statement=signed_owner_grant["statement"]
        required=("owner_id","repository","project_id","task_id",
                  "worker_id","source_sha40","target","operation_id","lease_epoch")
        if (any(type(statement.get(k))!=type(payload.get(k)) or
                statement.get(k)!=payload.get(k) for k in required) or
            type(statement.get("permit_sha256")) is not str or
            statement["permit_sha256"]!=hashlib.sha256(json.dumps(
                 payload,sort_keys=True,separators=(",",":"),ensure_ascii=True
            ).encode("ascii")).hexdigest() or
            type(statement.get("expires_unix")) is not int or
            statement["expires_unix"]<=now or
            statement["expires_unix"]>payload.get("expires_unix",0)):
            _deny()
        packet={"schema":"neurofactory.recipient.request.fixture.v1",
           "signed_packet":signed_packet,
           "witness":witness,
           "signed_owner_grant":signed_owner_grant,
           "content_base64":base64.b64encode(content).decode("ascii")}
        raw=json.dumps(packet,sort_keys=True,separators=(",",":")).encode("ascii")
        if len(raw)>110000:_deny()
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
                conn.settimeout(7)
                conn.connect(self.socket_path)
                pid,uid,gid=struct.unpack("3i",conn.getsockopt(
                    socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
                if pid<=0 or uid!=self.receiver_uid:_deny()
                conn.sendall(raw)
                answer=conn.recv(4097)
            if not answer or len(answer)>4096:_deny()
            response=json.loads(answer.decode("ascii"))
        except (OSError,ValueError,UnicodeError,TypeError):
            _deny()
        if (type(response) is not dict or
            set(response)!={"status","file_sha256","live_execution_allowed"} or
            response["status"]!="ONE_OS_RECIPIENT_TEST_EFFECT_ONLY" or
            response["file_sha256"]!=digest or
            response["live_execution_allowed"] is not False):
            _deny()
        return {"status":"CORE_TO_SEPARATE_UID_HOST_ONE_TEST_EFFECT_ONLY",
                "task_id":task_id,"content_sha256":digest,
                "core_wrote_local_file":False,"live_execution_allowed":False,
                "auto_retry_allowed":False,"independent_review_approved":False}
