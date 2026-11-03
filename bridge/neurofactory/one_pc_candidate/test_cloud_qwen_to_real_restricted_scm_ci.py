"""Real cloud-origin Qwen draft -> owner signed CORE -> actual Windows SCM.

The model inference ran on the already connected Linux cloudagent before this
workflow. The exact untrusted text/hash are transferred as read-only source
data to a disposable GitHub-hosted Windows runner. No cloud model ever holds
an owner/host key, selects a path, or obtains Windows execution permission.
Separate owner test keys only exist in disposable CI memory.
"""
from __future__ import annotations
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time

if os.name != "nt":
    raise RuntimeError("Cloud-to-real-SCM acceptance requires hosted Windows")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LOCAL=Path(__file__).resolve().parent
TRUSTED=LOCAL.parent/"trusted_host"
sys.path.insert(0,str(TRUSTED))
import test_windows_scm_two_user_recovery as host_fixture
from windows_named_pipe_pilot_receiver import _ALLOWED_TARGET,canon

from cloud_untrusted_proposal import read_cloud_untrusted_proposal,CloudProposalDenied
from local_workspace import WorkspaceStore, WorkspaceDenied
from signed_owner_admission import prepare_draft_request,admit_signed_draft,AdmissionDenied,_canon
from one_task_core import OneTaskCore,EMPTY_SHA,provision_empty_core_queue_offline

MODEL_SHA="cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046"
CLOUD_EVIDENCE=LOCAL/"cloud_qwen_draft_ci_evidence_20261103.json"

def _owner_pub(owner):
    return owner.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def main():
    if (os.environ.get("GITHUB_ACTIONS")!="true" or
            os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted" or
            os.environ.get("RUNNER_OS")!="Windows" or
            os.environ.get("NF_WINDOWS_SCM_DISPOSABLE_ONLY")!="1" or
            os.environ.get("NF_WINDOWS_REQUIRE_RESTRICTED_SERVICE_SID")!="1" or
            os.environ.get("NF_WINDOWS_CROSS_BRANCH_ACL_VERIFY")!="1" or
            os.environ.get("NF_ONEPC_FINAL_SIGNED_CI")!="1"):
        raise RuntimeError("Real SCM execution confined to disposable hosted Windows")
    runner=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    source,evidence=read_cloud_untrusted_proposal(
        CLOUD_EVIDENCE.resolve(strict=True),pinned_model_sha256=MODEL_SHA)
    model_output=source["output_text"]
    proposal_sha=evidence["proposal_sha256"]
    # Positive data origin is the prior cloudagent's actual local GGUF
    # inference recorded in this fixed Git SHA; it is NOT attested proof that
    # the process is a separate independent witness or signing authority.
    assert source["independent_provenance_attested"] is False
    assert evidence["scm_file_allowed"] is False
    with tempfile.TemporaryDirectory(prefix="nf-cloud-to-scm-",dir=runner) as tmp:
        workspace=WorkspaceStore(Path(tmp)/"workspace")
        project=workspace.create_project({
            "name":"CI cloud Qwen operator-gated handoff",
            "description":"Separate Linux model -> bounded untrusted draft -> Windows gate"})
        task=workspace.create_task({
            "project_id":project["id"],
            "objective":"Inspect this harmless cloud Qwen explanation as DATA ONLY; "+
                "never execute model text, modify source or authorize effects.",
            "model_preference":"qwen2.5-coder:1.5b"})
        workspace.reserve_task_proposal(task["id"],"qwen2.5-coder:1.5b")
        result=workspace.finalize_task_proposal(task["id"],{
            "status":"PROPOSED_UNVERIFIED",
            "model":"qwen2.5-coder:1.5b",
            "text":model_output,
            "response_sha256":proposal_sha,
            "content_sha256":proposal_sha})
        assert result["core_enqueued"] is False
        assert result["host_write_allowed"] is False
        assert result["review_approved"] is False
        before=workspace.list_task_proposals()
        unsigned=prepare_draft_request(workspace,task["id"])
        assert unsigned["owner_signed"] is False
        assert unsigned["execution_allowed"] is False
        assert unsigned["queue_mutation_allowed"] is False
        # All service effects are explicitly confined to one static
        # harmless fingerprint report, NOT instructions from the model.
        fixed=(
            "NF_REAL_CLOUD_QWEN_TO_SIGNED_CORE_RESTRICTED_SCM_CI_ONLY\n"
            "DRAFT_SHA256="+unsigned["draft_sha256"]+"\n"
            "CLOUD_MODEL_OUTPUT_SHA256="+proposal_sha+"\n"
        )
        assert model_output not in fixed
        approved={"signed_admission":False,"actual_claim":False,"fixed_file":False}
        def prepare_cloud_core(directory,owner):
            repo=directory/"git"
            repo.mkdir()
            host_fixture.call(["git","-C",str(repo),"init","-q"])
            host_fixture.call(["git","-C",str(repo),"config","user.name","CI-Cloud-Qwen-SCM"])
            host_fixture.call(["git","-C",str(repo),"config","user.email","cloud-scm@example.invalid"])
            (repo/"README.md").write_text("temporary hosted Windows CI fixture\n",encoding="utf8")
            host_fixture.call(["git","-C",str(repo),"add","README.md"])
            host_fixture.call(["git","-C",str(repo),"commit","-qm","temporary fixture"])
            commit=host_fixture.call(["git","-C",str(repo),"rev-parse","HEAD"]).stdout.strip()
            root=directory/"core"
            root.mkdir()
            provision_empty_core_queue_offline(root)
            core=OneTaskCore(root,repo)
            spec={
                "schema":"neurofactory.core.task.v1",
                "task_id":"NF-DEV-05-Q976",
                "project_id":unsigned["core_project_id"],
                "target":_ALLOWED_TARGET,
                "objective":unsigned["objective"],
                "source_sha":commit,
                "source_sha256":EMPTY_SHA,
                "approval_commit":commit,
                "model":"qwen2.5-coder:1.5b",
                "reserved_units":10,
            }
            now=int(time.time())
            permit={
                "schema":"nf.onepc.owner_core_admission.v1",
                "scope":"OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
                "draft":unsigned,"spec":spec,
                "nonce":secrets.token_hex(16),
                "issued_at":now-1,"expires_at":now+120,
            }
            forged={**permit,"owner_signature":base64.b64encode(b"\0"*64).decode("ascii")}
            try:
                admit_signed_draft(workspace,core,forged,owner_public_raw=_owner_pub(owner),now=now)
            except AdmissionDenied:
                pass
            else:
                raise AssertionError("Forged model-to-CORE owner approval accepted")
            actual={**permit,"owner_signature":base64.b64encode(
                owner.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00"+_canon(permit))).decode("ascii")}
            admitted=admit_signed_draft(
                workspace,core,actual,owner_public_raw=_owner_pub(owner),now=now)
            assert admitted["core_reported_state"]=="QUEUED"
            assert admitted["host_execution_allowed"] is False
            assert admitted["operator_verified_signed_permit"] is True
            approved["signed_admission"]=True
            claim=core.claim("isolated-qwen-scm-worker",now=int(time.time()),lease_seconds=180)
            assert core.snapshot()["state"]=="CLAIMED"
            approved["actual_claim"]=True
            raw=fixed.encode("ascii")
            body={
                "schema":"neurofactory.windows.single_file_pilot.v1",
                "task_id":spec["task_id"],
                "project_id":spec["project_id"],
                "source_sha40":spec["source_sha"],
                "operation_id":"pilot-"+spec["task_id"],
                "target":spec["target"],
                "content_base64":base64.b64encode(raw).decode("ascii"),
                "content_sha256":sha256(raw).hexdigest(),
            }
            packet={**body,"approved_owner_signature":base64.b64encode(
                owner.sign(b"NF_WINDOWS_PILOT_V1\x00"+canon(body))
            ).decode("ascii")}
            approved["fixed_file"]=True
            return core,spec,claim,packet,fixed

        orig=host_fixture.prepare_core_fixture
        argv=sys.argv[:]
        try:
            host_fixture.prepare_core_fixture=prepare_cloud_core
            sys.argv=["test_windows_scm_two_user_recovery.py","normal"]
            host_fixture.main()
        finally:
            host_fixture.prepare_core_fixture=orig
            sys.argv=argv
        assert all(approved.values())
        # The low-priv worker, LOCAL SERVICE and no-retry replay have already
        # been exercised with a REAL SCM process. The original Qwen proposal
        # stays a read-only DRAFT, not silently marked completed.
        reopened=WorkspaceStore(workspace.directory)
        after=reopened.list_task_proposals()
        assert len(before)==len(after)==1
        assert after[0]["text"]==model_output
        assert after[0]["content_sha256"]==proposal_sha
        assert reopened.list_tasks()[0]["state"]=="DRAFT_PENDING_OWNER_AUTH"
        print("NF_CLOUD_LINUX_QWEN_UNTRUSTED_DRAFT_TO_OWNER_SIGNED_CORE=PASS_CI_ONLY")
        print("NF_CLOUD_QWEN_DIGEST_TO_ACTUAL_RESTRICTED_WINDOWS_SCM=PASS_CI_ONLY")
        print("NF_CLOUD_MODEL_TEXT_NEVER_EXECUTED_NO_WORKER_KEYS=PASS_CI_ONLY")
        print("NF_OWNER_PC_WINDOWS_SERVICE_INSTALL=NOT_PERFORMED")
        print("NF_EXTERNAL_INDEPENDENT_WITNESS=NOT_CONNECTED")

if __name__=="__main__":
    main()
