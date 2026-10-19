"""Real installed-source UI HTTP draft -> pinned provider -> genuine local Ollama Qwen.

DISPOSABLE Windows GitHub-hosted only. No mocks, no SCM, no CORE queue or
side-effect approval. Model identity is Ollama-reported, not independently
attested. Requires preinstalled Ollama model by workflow.
"""
from __future__ import annotations
from hashlib import sha256
import http.client
from http.server import HTTPServer
import json
import os
from pathlib import Path
from threading import Thread
import tempfile

from local_workspace import WorkspaceStore, handler

def request(port,method,path,payload=None,token=None):
    conn=http.client.HTTPConnection("127.0.0.1",port,timeout=100)
    body=json.dumps(payload).encode("utf-8") if payload is not None else None
    headers={"Content-Type":"application/json"}
    if token:
        headers["X-NF-Local-Token"]=token
    try:
        conn.request(method,path,body=body,headers=headers)
        response=conn.getresponse()
        raw=response.read(20000)
        if len(raw)>=20000:
            raise RuntimeError("Response too large")
        parsed=json.loads(raw.decode("utf-8"))
        return response.status,parsed
    finally:
        conn.close()

def main():
    if (os.name!="nt" or os.environ.get("GITHUB_ACTIONS")!="true" or
        os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted" or
        os.environ.get("NF_REAL_QWEN_DISPOSABLE_TEST")!="1"):
        raise RuntimeError("Temporary Windows GitHub runner only")
    root=Path(os.environ["NF_REAL_QWEN_COMPONENTS"])
    ui=Path(__file__).resolve().parent.parent/"control_ui"
    if not root.is_absolute():
        raise RuntimeError("Explicit installed-source components required")
    with tempfile.TemporaryDirectory(prefix="nf-real-user-proposal-") as tmp:
        store=WorkspaceStore(Path(tmp)/"workspace")
        server=HTTPServer(("127.0.0.1",0),handler(
            store,ui,"ephemeral-ci-only-token",0,components_dir=root))
        # Host validation uses port, so rebuild using actual ephemeral assigned port.
        port=server.server_address[1]
        server.server_close()
        server=HTTPServer(("127.0.0.1",port),handler(
            store,ui,"ephemeral-ci-only-token",port,components_dir=root))
        thread=Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            code,proj=request(port,"POST","/api/projects",
                {"name":"CI genuine Qwen preview","description":"Disposable local example"},
                token="ephemeral-ci-only-token")
            if code!=201:
                raise RuntimeError("Real local project creation failed")
            objective=("Create a harmless plain text sample consisting of the one line "
                "NEUROFACTORY_REAL_QWEN_DRAFT_PREVIEW. Return only the required JSON "
                "with path and content; do not write files or execute commands.")
            code,task=request(port,"POST","/api/tasks",
                {"project_id":proj["id"],"objective":objective,
                 "model_preference":"qwen2.5-coder:1.5b"},
                token="ephemeral-ci-only-token")
            if code!=201 or task.get("state")!="DRAFT_PENDING_OWNER_AUTH":
                raise RuntimeError("UI draft not persisted")
            code,proposal=request(port,"POST","/api/draft-propose",
                {"task_id":task["id"]},token="ephemeral-ci-only-token")
            if code!=201 or proposal.get("status")!="PROPOSED_UNVERIFIED":
                print("NF_REAL_PROVIDER_DRAFT_HTTP_STATUS="+str(code))
                print("NF_REAL_PROVIDER_DRAFT_RESULT="+str(proposal.get("status","INVALID")))
                raise RuntimeError("Genuine model did not produce a validated inert proposal")
            response=proposal.get("text")
            if (type(response) is not str or
                not 1<=len(response.encode("utf-8"))<=12000 or
                sha256(response.encode("utf-8")).hexdigest()!=proposal["content_sha256"]):
                raise RuntimeError("Unsafe Qwen draft fingerprint")
            if proposal.get("model")!="qwen2.5-coder:1.5b" or any(
                proposal.get(name) is not False for name in
                ("core_enqueued","host_write_allowed","review_approved")):
                raise RuntimeError("Unexpected provider authority")
            code,repeated=request(port,"POST","/api/draft-propose",
                {"task_id":task["id"]},token="ephemeral-ci-only-token")
            if code==201:
                raise RuntimeError("Duplicate real model call admitted")
            print("NF_REAL_QWEN_USER_HTTP_PROPOSAL_HASH="+proposal["content_sha256"])
            code,proposals=request(port,"GET","/api/task-proposals")
            if code!=200 or len(proposals["proposals"])!=1:
                raise RuntimeError("Qwen proposal not visible in local UI API")
            reopened=WorkspaceStore(store.directory)
            if (len(reopened.list_task_proposals())!=1 or
                reopened.list_tasks()[0]["state"]!="DRAFT_PENDING_OWNER_AUTH" or
                reopened.diag()["real_core_dispatch_enabled"] is not False):
                raise RuntimeError("No-replay durable state invalid")
            print("NF_REAL_QWEN_USER_TASK_TO_DURABLE_PROPOSAL=PASS_UNATTESTED")
            print("NF_REAL_QWEN_PROVIDER_SINGLE_CALL_NO_REPLAY=PASS")
            print("NF_REAL_QWEN_TO_CORE_HOST_EFFECT=NOT_EXECUTED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=4)

if __name__=="__main__":
    main()
