"""CI-only continuation of the SAME genuine Qwen-installed-app SQLite draft.

Reads a verified disposable backup produced by test_real_user_qwen_proposal_windows.py,
never executes Qwen text and never exposes signing keys to UI or Ollama.
Exercises a synthetic independent owner signature -> actual CORE Git/SQLite ->
synthetic independent signed HOST test receipt in ONE runner, not a three-SID
production SCM deployment. Strictly fail-closed on anything unexpected.
"""
from __future__ import annotations
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "development" / "core_owned"))
from one_task_core import OneTaskCore, CoreSafetyError, EMPTY_SHA
from local_workspace import WorkspaceStore
from signed_owner_admission import prepare_draft_request, admit_signed_draft, AdmissionDenied, _canon


def _git(path, *parts):
    return subprocess.run(["git", "-C", str(path), *parts],
                          capture_output=True, text=True, check=True, timeout=15).stdout.strip()


def _public(private):
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def main():
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "Windows"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("NF_REAL_QWEN_DISPOSABLE_TEST") != "1"):
        raise RuntimeError("CI-only: disposable GitHub-hosted Windows required")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    named = Path(os.environ["NF_REAL_QWEN_E2E_EXPORT"])
    if (not named.is_absolute() or named.is_symlink()
            or named.parent.resolve(strict=True) != runner
            or not named.is_dir() or (named / "workspace.sqlite3").is_symlink()):
        raise RuntimeError("Untrusted or missing disposable Qwen SQLite export")
    store = WorkspaceStore(named)
    tasks, projects, proposals = (
        store.list_tasks(), store.list_projects(), store.list_task_proposals())
    if (len(tasks) != 1 or len(projects) != 1 or len(proposals) != 1
            or tasks[0]["project_id"] != projects[0]["id"]
            or tasks[0]["state"] != "DRAFT_PENDING_OWNER_AUTH"
            or tasks[0]["model_preference"] != "qwen2.5-coder:1.5b"):
        raise RuntimeError("Expected exactly one unchanged real Qwen user draft")
    draft = tasks[0]
    proposal = proposals[0]
    raw_text = proposal.get("text")
    if (proposal.get("status") != "PROPOSED_UNVERIFIED"
            or proposal.get("model") != "qwen2.5-coder:1.5b"
            or type(raw_text) is not str
            or not 1 <= len(raw_text.encode("utf-8")) <= 12000
            or sha256(raw_text.encode("utf-8")).hexdigest() != proposal.get("content_sha256")):
        raise RuntimeError("Persisted genuine Qwen proposal corrupted")
    unsigned = prepare_draft_request(store, draft["id"])
    if unsigned.get("owner_signed") is not False or unsigned["objective"] != draft["objective"]:
        raise RuntimeError("Qwen promoted browser draft into an owner permission")
    owner = Ed25519PrivateKey.generate()
    host_signer = Ed25519PrivateKey.generate()
    if _public(owner) == _public(host_signer):
        raise RuntimeError("Owner and HOST keys not separated")
    with tempfile.TemporaryDirectory(prefix="nf-real-qwen-to-core-test-", dir=runner) as tmp:
        root = Path(tmp)
        source = root / "repo"
        source.mkdir(mode=0o700)
        _git(source, "init", "-q")
        _git(source, "config", "user.name", "Disposable Qwen integration")
        _git(source, "config", "user.email", "ci@example.invalid")
        (source / "README.md").write_text("Test-only immutable source\n", encoding="utf-8")
        _git(source, "add", "README.md")
        _git(source, "commit", "-qm", "immutable test commit")
        commit = _git(source, "rev-parse", "HEAD")
        state = root / "state"
        state.mkdir(mode=0o700)
        host_files = root / "host"
        host_files.mkdir(mode=0o700)
        core = OneTaskCore(state, source, host_output_dir=host_files,
                           host_receipt_public_raw=_public(host_signer))
        spec = {
            "schema": "neurofactory.core.task.v1",
            "task_id": "NF-DEV-05-Q955",
            "project_id": unsigned["core_project_id"],
            "target": "bridge/neurofactory/development/core_owned/windows_pilot.txt",
            "objective": unsigned["objective"],
            "source_sha": commit,
            "source_sha256": EMPTY_SHA,
            "approval_commit": commit,
            "model": draft["model_preference"],
            "reserved_units": 10,
        }
        now = int(time.time())
        owner_body = {
            "schema": "nf.onepc.owner_core_admission.v1",
            "scope": "OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
            "draft": unsigned, "spec": spec,
            "nonce": secrets.token_hex(16),
            "issued_at": now - 1, "expires_at": now + 120,
        }
        owner_signature = owner.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00" + _canon(owner_body))
        permit = {**owner_body, "owner_signature": base64.b64encode(owner_signature).decode()}
        fake = dict(permit)
        fake["owner_signature"] = base64.b64encode(
            Ed25519PrivateKey.generate().sign(
                b"NF_OWNER_CORE_ADMISSION_V1\x00" + _canon(owner_body))).decode()
        try:
            admit_signed_draft(store, core, fake, owner_public_raw=_public(owner), now=now)
        except AdmissionDenied:
            pass
        else:
            raise RuntimeError("Forged signer was accepted before genuine Qwen CORE admission")
        result = admit_signed_draft(store, core, permit, owner_public_raw=_public(owner), now=now)
        if (result["core_reported_state"] != "QUEUED"
                or result["host_execution_allowed"] is not False
                or result["production_release"] is not False):
            raise RuntimeError("Real Qwen draft bypassed owner-signature execution boundary")
        claim = core.claim("isolated-qwen-host-ci", now=1000, lease_seconds=100)
        text_bytes = b"NF_SIGNED_CI_HOST_RECEIPT_REQUIRES_REAL_PROTECTED_RELEASE\n"
        digest = sha256(text_bytes).hexdigest()
        (host_files / "windows_pilot.txt").write_bytes(text_bytes)
        host_body = {
            "schema": "neurofactory.windows.host_signed_test_receipt.v1",
            "task_id": spec["task_id"], "project_id": spec["project_id"],
            "source_sha40": commit, "target": spec["target"],
            "operation_id": "pilot-" + spec["task_id"],
            "content_sha256": digest, "status": "HOST_FILE_WRITTEN_TEST_ONLY",
        }
        signed_raw = json.dumps(host_body, sort_keys=True, ensure_ascii=False,
                                separators=(",", ":"), allow_nan=False).encode()
        host_sig = host_signer.sign(b"NF_WINDOWS_HOST_RECEIPT_TEST_V1\x00" + signed_raw)
        receipt = {
            "schema": "neurofactory.core.host_checkpoint_test.v1",
            "signed": host_body,
            "signature_base64": base64.b64encode(host_sig).decode(),
            "host_key_sha256": sha256(_public(host_signer)).hexdigest(),
        }
        done = core.finalize_signed_host_test(
            spec["task_id"], claim["token"], receipt, now=1001)
        if done["state"] != "HOST_CHECKPOINTED_TEST" or done["result_sha256"] != digest:
            raise RuntimeError("Signed HOST readback not checkpointed in actual SQLite")
        reopened = OneTaskCore(state, source, host_output_dir=host_files,
                               host_receipt_public_raw=_public(host_signer))
        if (reopened.snapshot()["state"] != "HOST_CHECKPOINTED_TEST"
                or reopened.snapshot()["attempts"] != 1
                or reopened.recover(now=9999)["state"] != "HOST_CHECKPOINTED_TEST"):
            raise RuntimeError("Post-Qwen CORE result lost on restart")
        try:
            admit_signed_draft(store, reopened, permit,
                               owner_public_raw=_public(owner), now=now)
        except AdmissionDenied:
            pass
        else:
            raise RuntimeError("Signed owner permit replay accepted after HOST result")
        if store.list_tasks()[0]["state"] != "DRAFT_PENDING_OWNER_AUTH":
            raise RuntimeError("Qwen UI draft incorrectly marked authorized/completed")
        if store.list_task_proposals()[0]["content_sha256"] != proposal["content_sha256"]:
            raise RuntimeError("Protected signed CORE test mutated real Qwen model proposal")
        print("NF_GENUINE_QWEN_DURABLE_DRAFT_TO_SIGNED_CORE_HOST=PASS_DISPOSABLE_TEST_ONLY")
        print("NF_GENUINE_QWEN_OWNER_AND_HOST_KEYS_DISTINCT=PASS_TEST_ONLY")
        print("NF_GENUINE_QWEN_CORE_RESTART_AND_SIGNED_REPLAY_DENIAL=PASS_TEST_ONLY")
        print("NF_REAL_QWEN_SCM_HOST_PRIVILEGED_INSTALLED_RELEASE=NOT_PROVEN")


if __name__ == "__main__":
    main()
