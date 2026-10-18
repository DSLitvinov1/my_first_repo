"""Windows CORE -> SID-restricted HOST named-pipe client, CI sandbox ONLY.

Imports the real OneTaskCore state/claim, which must already be admitted
against the pinned Git source. Never writes local files or trusts an
unverified response as production authorization. The signing private key
lives outside CORE: this client receives ONLY signed bytes.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import PurePosixPath
import re
import time

class WindowsCoreRouteDenied(ValueError):
    pass

def _deny():
    raise WindowsCoreRouteDenied("Windows protected receiver not authorized, live queue unchanged")

class CoreProtectedWindowsReceiverClient:
    def __init__(self,core,*,pipe_name):
        if (os.name!="nt" or os.getenv("NF_WINDOWS_RECEIVER_CI_ONLY")!="1"
            or os.getenv("GITHUB_ACTIONS")!="true"
            or os.getenv("RUNNER_ENVIRONMENT")!="github-hosted"
            or core is None or type(pipe_name) is not str
            or not re.fullmatch(r"nf-ci-[0-9a-f]{16}",pipe_name)):
            _deny()
        self.core=core
        self.address=r"\\.\pipe\\".rstrip("\\")+ "\\" + pipe_name

    def propose_once(self,*,task_id,worker_id,core_token,proposal,
                     signed_body_bytes,owner_signature_base64):
        if (type(task_id) is not str or type(worker_id) is not str
            or type(core_token) is not str or type(proposal) is not dict
            or set(proposal)!={"schema","target","content","content_sha256","mode"}
            or proposal.get("schema")!="neurofactory.core.proposal.v1"
            or proposal.get("mode")!="OFFLINE_TEST"
            or type(proposal.get("target")) is not str
            or type(proposal.get("content")) is not str
            or type(proposal.get("content_sha256")) is not str
            or type(signed_body_bytes) is not bytes
            or not 1<=len(signed_body_bytes)<=4096
            or type(owner_signature_base64) is not str
            or len(owner_signature_base64)>120):
            _deny()
        content=proposal["content"].encode("utf-8")
        digest=hashlib.sha256(content).hexdigest()
        if not 1<=len(content)<=512 or digest!=proposal["content_sha256"]:
            _deny()
        try:
            with self.core._connect() as conn:
                conn.execute("BEGIN")
                row=self.core._row(conn)
                if (row is None or row["state"]!="CLAIMED"
                    or row["spec"]["task_id"]!=task_id
                    or row["owner"]!=worker_id
                    or row["lease_until"]<=int(time.time())
                    or not hmac.compare_digest(
                        hashlib.sha256(core_token.encode("ascii")).hexdigest(),
                        row["token"])
                    or row["spec"]["target"]!=proposal["target"]):
                    _deny()
                spec=dict(row["spec"])
        except (ValueError,TypeError,KeyError,OverflowError,UnicodeError):
            _deny()
        try:
            body=json.loads(signed_body_bytes.decode("ascii"))
        except (UnicodeError,ValueError):
            _deny()
        if (type(body) is not dict or len(body)!=12
            or body.get("schema")!="neurofactory.windows.core_signed_scratch.v1"
            or body.get("task_id")!=task_id
            or body.get("project_id")!=spec["project_id"]
            or body.get("source_sha40")!=spec["source_sha"]
            or body.get("target")!=PurePosixPath(spec["target"]).name
            or body.get("target")!="core-e2e-proof.txt"
            or body.get("content_sha256")!=digest
            or body.get("worker_id")!=worker_id
            or body.get("mode")!="CORE_SIGNED_SCRATCH_TEST_ONLY"
            or body.get("owner_confirmed") is not True
            or body.get("model_invoked") is not False
            or type(body.get("expires_unix")) is not int
            or body["expires_unix"]<=int(time.time())):
            _deny()
        request={
            "schema":"nf.windows.receiver.request.v1",
            "body_base64":base64.b64encode(signed_body_bytes).decode("ascii"),
            "owner_signature_base64":owner_signature_base64,
            "content_base64":base64.b64encode(content).decode("ascii")}
        raw=json.dumps(request,sort_keys=True,separators=(",",":")).encode("ascii")
        if len(raw)>16384:_deny()
        try:
            from multiprocessing.connection import Client
            with Client(self.address,family="AF_PIPE") as pipe:
                pipe.send_bytes(raw)
                answer=pipe.recv_bytes(4096)
            response=json.loads(answer.decode("ascii"))
        except (OSError,ValueError,UnicodeError,EOFError,ConnectionError):
            _deny()
        if (type(response) is not dict
            or response.get("status")!="WIN_CORE_TO_PROTECTED_SCRATCH_ONE_FILE_TEST_ONLY"
            or response.get("file_sha256")!=digest
            or response.get("live_execution_allowed") is not False
            or response.get("automatic_retry_allowed") is not False):
            _deny()
        return {
            "status":"CORE_WINDOWS_PROTECTED_SCRATCH_ONE_EFFECT_TEST_ONLY",
            "task_id":task_id,"content_sha256":digest,
            "core_wrote_local_file":False,
            "live_execution_allowed":False,
            "automatic_retry_allowed":False,
            "independent_review_approved":False,
        }
