"""One real installed-Qwen draft -> signed CORE -> actual restricted Windows SCM HOST.

Uses the genuine Qwen SQLite backup created earlier in the SAME hosted Windows
job. Runs the real pinned CORE admission and actual distinct Windows-account
worker through actual LocalService per-service-RESTRICTED-SID HOST pipe, with
signed readback receipt and SQLite restart/replay check.

One inert, ephemeral receipt containing the Qwen proposal fingerprint is
explicitly approved by an in-memory synthetic CI owner; Qwen's freeform
output is NEVER interpreted as an action or applied to source. The separate
real SCM HOST receiver is a CI pilot, NOT permanently installed production.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys
import time

if os.name != "nt":
    raise RuntimeError("NEUROFACTORY_GENUINE_QWEN_RESTRICTED_SCM_WINDOWS_ONLY")

from cryptography.hazmat.primitives import serialization
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "trusted_host"))
from windows_named_pipe_pilot_receiver import _ALLOWED_TARGET, canon
import test_windows_scm_two_user_recovery as host_fixture
from local_workspace import WorkspaceStore
from signed_owner_admission import (
    prepare_draft_request, admit_signed_draft, AdmissionDenied, _canon,
)
from one_task_core import OneTaskCore, EMPTY_SHA

def _public(owner):
    return owner.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def run():
    required = (
        "NF_REAL_QWEN_DISPOSABLE_TEST",
        "NF_WINDOWS_SCM_DISPOSABLE_ONLY",
        "NF_WINDOWS_CROSS_BRANCH_ACL_VERIFY",
        "NF_WINDOWS_REQUIRE_RESTRICTED_SERVICE_SID",
        "NF_ONEPC_FINAL_SIGNED_CI",
    )
    if (os.name != "nt" or os.getenv("GITHUB_ACTIONS") != "true"
            or os.getenv("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.getenv("RUNNER_OS") != "Windows"
            or any(os.getenv(k) != "1" for k in required)):
        raise RuntimeError("Protected SCM + genuine Qwen only on disposable hosted Windows")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    export = Path(os.environ["NF_REAL_QWEN_E2E_EXPORT"])
    if (not export.is_absolute() or export.is_symlink() or
            export.parent.resolve(strict=True) != runner or
            not (export / "workspace.sqlite3").is_file() or
            (export / "workspace.sqlite3").is_symlink()):
        raise RuntimeError("Verified installed-Qwen SQLite export unavailable")
    preimage = sha256((export / "workspace.sqlite3").read_bytes()).hexdigest()
    store = WorkspaceStore(export)
    projects, tasks, proposals = (
        store.list_projects(), store.list_tasks(), store.list_task_proposals())
    if (len(tasks) != 1 or len(proposals) != 1 or len(projects) != 1):
        raise RuntimeError("Expected precisely one genuine Qwen draft and proposal")
    task, proposal = tasks[0], proposals[0]
    unsigned = prepare_draft_request(store, task["id"])
    model_output = proposal.get("text")
    if (task["project_id"] != projects[0]["id"] or
            task["state"] != "DRAFT_PENDING_OWNER_AUTH" or
            task["model_preference"] != "qwen2.5-coder:1.5b" or
            unsigned["model_preference"] != task["model_preference"] or
            unsigned["owner_signed"] is not False or
            unsigned["execution_allowed"] is not False or
            proposal.get("status") != "PROPOSED_UNVERIFIED" or
            proposal.get("model") != task["model_preference"] or
            type(model_output) is not str or
            not 1 <= len(model_output.encode("utf-8")) <= 12000 or
            sha256(model_output.encode("utf-8")).hexdigest() !=
                proposal["content_sha256"]):
        raise RuntimeError("Untrusted, mismatched or non-durable actual Qwen proposal")
    proposal_sha = proposal["content_sha256"]
    draft_sha = unsigned["draft_sha256"]
    # No model text in logs, privileged config, HOST request, or executable.
    # A synthetic separate owner chooses to sign ONLY these two digests.
    safe_content = (
        "NF_GENUINE_QWEN_OWNER_REVIEWED_PROPOSAL_FINGERPRINT_CI_ONLY\n"
        "DRAFT_SHA256=" + draft_sha + "\n"
        "MODEL_OUTPUT_SHA256=" + proposal_sha + "\n"
    )
    if len(safe_content.encode("ascii")) > 2048:
        raise RuntimeError("Host proposal digest report exceeds receiver bound")
    call = host_fixture.call
    original = host_fixture.prepare_core_fixture
    observed = {"signed_admitted":False, "claimed":False}
    def from_real_qwen(directory, owner):
        repo = directory / "git"
        repo.mkdir()
        call(["git", "-C", str(repo), "init", "-q"])
        call(["git", "-C", str(repo), "config", "user.name", "CI-Qwen-Real-SCM"])
        call(["git", "-C", str(repo), "config", "user.email", "ci@example.invalid"])
        (repo / "README.md").write_text("one harmless temporary test\n", encoding="utf-8")
        call(["git", "-C", str(repo), "add", "README.md"])
        call(["git", "-C", str(repo), "commit", "-qm", "source fixture"])
        source_sha = call(["git","-C",str(repo),"rev-parse","HEAD"]).stdout.strip()
        core_root = directory / "core"
        core_root.mkdir()
        core = OneTaskCore(core_root,repo)
        spec = {
            "schema":"neurofactory.core.task.v1",
            "task_id":"NF-DEV-05-Q976",
            "project_id":unsigned["core_project_id"],
            "target":_ALLOWED_TARGET,
            "objective":unsigned["objective"],
            "source_sha":source_sha,
            "source_sha256":EMPTY_SHA,
            "approval_commit":source_sha,
            "model":task["model_preference"],
            "reserved_units":10,
        }
        now = int(time.time())
        body = {
            "schema":"nf.onepc.owner_core_admission.v1",
            "scope":"OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
            "draft":unsigned,
            "spec":spec,
            "nonce":secrets.token_hex(16),
            "issued_at":now-1,
            "expires_at":now+120,
        }
        raw=_canon(body)
        signed = {**body, "owner_signature":base64.b64encode(
            owner.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00"+raw)).decode("ascii")}
        forged = dict(signed)
        forged["owner_signature"] = base64.b64encode(b"\0"*64).decode("ascii")
        try:
            admit_signed_draft(store,core,forged,owner_public_raw=_public(owner),now=now)
        except AdmissionDenied:
            pass
        else:
            raise RuntimeError("Qwen CORE admission accepted forged signature")
        admitted = admit_signed_draft(
            store,core,signed,owner_public_raw=_public(owner),now=now)
        if (admitted["core_reported_state"] != "QUEUED" or
                admitted["host_execution_allowed"] is not False or
                admitted["operator_verified_signed_permit"] is not True):
            raise RuntimeError("Real Qwen draft bypassed signed CORE admission gate")
        observed["signed_admitted"]=True
        claim = core.claim("isolated-qwen-scm-worker", now=int(time.time()),
                           lease_seconds=180)
        if core.snapshot()["state"] != "CLAIMED":
            raise RuntimeError("Pinned CORE queue did not atomically claim")
        observed["claimed"]=True
        raw_safe = safe_content.encode("ascii")
        pilot_body = {
            "schema":"neurofactory.windows.single_file_pilot.v1",
            "task_id":spec["task_id"],
            "project_id":spec["project_id"],
            "source_sha40":spec["source_sha"],
            "operation_id":"pilot-"+spec["task_id"],
            "target":spec["target"],
            "content_base64":base64.b64encode(raw_safe).decode("ascii"),
            "content_sha256":sha256(raw_safe).hexdigest(),
        }
        packet = {**pilot_body,"approved_owner_signature":base64.b64encode(
            owner.sign(b"NF_WINDOWS_PILOT_V1\x00"+canon(pilot_body))
        ).decode("ascii")}
        # The model cannot select paths, service identities or grant privileges.
        return core,spec,claim,packet,safe_content

    try:
        host_fixture.prepare_core_fixture=from_real_qwen
        old_argv=sys.argv[:]
        try:
            sys.argv=["test_windows_scm_two_user_recovery.py","normal"]
            host_fixture.main()
        finally:
            sys.argv=old_argv
    finally:
        host_fixture.prepare_core_fixture=original
    if not all(observed.values()):
        raise RuntimeError("Genuine Qwen SQLite was not linked to signed CORE")
    reloaded = WorkspaceStore(export)
    after_tasks,after_proposals=reloaded.list_tasks(),reloaded.list_task_proposals()
    if (len(after_tasks)!=1 or
            after_tasks[0]["state"]!="DRAFT_PENDING_OWNER_AUTH" or
            len(after_proposals)!=1 or
            after_proposals[0]["content_sha256"]!=proposal_sha or
            after_proposals[0]["text"]!=model_output):
        raise RuntimeError("Privileged Windows service mutated actual Qwen workspace")
    if sha256((export/"workspace.sqlite3").read_bytes()).hexdigest()!=preimage:
        raise RuntimeError("Actual Qwen SQLite export changed after SCM execution")
    print("NF_GENUINE_QWEN_SQLITE_TO_OWNER_SIGNED_CORE_AND_REAL_SCM_HOST=PASS_CI_ONLY")
    print("NF_GENUINE_MODEL_TEXT_NEVER_EXECUTED_ONLY_FINGERPRINT_RECEIPT=PASS")
    print("NF_GENUINE_QWEN_CORE_AND_RESTRICTED_SCM_SAME_WINDOWS_RUN=PASS_CI_ONLY")
    print("NF_OWNER_WINDOWS_PRODUCTION_RELEASE_NOT_GRANTED=TRUE")
    print("NF_EXTERNAL_WITNESS_AND_PRODUCTION_KEYS=NOT_CONFIGURED")

if __name__ == "__main__":
    run()
