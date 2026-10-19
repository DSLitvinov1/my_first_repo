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

import importlib.util
def installed_app_module():
    app_dir=Path(os.environ["NF_REAL_QWEN_INSTALLED_APP"])
    module_path=app_dir/"local_workspace.py"
    if (not app_dir.is_absolute() or app_dir.is_symlink() or
        module_path.is_symlink() or not module_path.is_file()):
        raise RuntimeError("Genuine installed app module missing or unsafe")
    spec=importlib.util.spec_from_file_location("_nf_real_installed_workspace",module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load installed application")
    instance=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance


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
    installed=installed_app_module()
    WorkspaceStore,handler=installed.WorkspaceStore,installed.handler
    app=Path(os.environ["NF_REAL_QWEN_INSTALLED_APP"])
    root=app.parent/"components"
    ui=app.parent/"ui"
    if (not root.is_absolute() or root.is_symlink() or not ui.is_dir() or
        not (app.parent/"runtime"/"python.exe").is_file()):
        raise RuntimeError("Real installed app and pinned provider components required")
    print("NF_REAL_QWEN_EXECUTING_FROM_INSTALLED_APP=PASS")
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
            objective=("Create a harmless one-line text file containing exactly "
                "NEUROFACTORY_REAL_QWEN_DRAFT_PREVIEW. Your entire reply MUST be one "
                "strict JSON object with exactly two keys named path and content. "
                "Copy the target path character for character from the instruction "
                "above into the path key. Do not use markdown, backticks, code fences, "
                "analysis, comments or explanations. Do not execute anything.")
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
