"""One disposable Windows CI end-to-end: owner-signed UI draft -> real CORE
SQLite -> real pinned PROVIDERS -> REAL Ollama Qwen code-review suggestion.

Runs only on hosted ephemeral runner with an explicit one-shot gate. The CI
owner key is ephemeral and NEVER persisted. No claims/SCM/write/merge/retry.
The generated text is an unreviewed proposal, not a validated fix.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

if (
    os.name != "nt"
    or os.environ.get("GITHUB_ACTIONS") != "true"
    or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    or os.environ.get("NF_SIGNED_QWEN_CI_ONLY") != "1"
):
    raise RuntimeError("Only one explicitly gated disposable GitHub Windows CI runner")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
INSTALLED = Path(os.environ["NF_SIGNED_QWEN_STAGED_COMPONENTS"]).resolve(strict=True)
OUT = Path(os.environ["NF_SIGNED_QWEN_ARTIFACT_DIR"]).resolve(strict=True)
EVIDENCE = Path(os.environ["NF_SIGNED_QWEN_EVIDENCE_DIR"]).resolve(strict=True)
MODEL = "qwen2.5-coder:1.5b"
EXPECTED_SCOPE = "OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION"
OBJECTIVE = (
    "Review our signed_owner_admission.py _one_draft: it joins projects but never "
    "validates row[1] as 32 lowercase hex before 'p-' + row[1]. Propose one "
    "precise validation guard and one negative regression test. Do NOT apply code."
)
TARGET = "bridge/neurofactory/development/core_owned/review.md"
TASK_ID = "NF-DEV-05-Q951"


def check(condition, message):
    if not condition:
        raise RuntimeError("NF_SIGNED_QWEN_DENIED: " + message)


def run_git(repo, *args):
    r = subprocess.run(
        ["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=15, check=False,
    )
    check(r.returncode == 0, "pinned Git operation rejected")
    return r.stdout.decode("utf-8").strip()


def import_code(path, name):
    check(path.is_file() and not path.is_symlink(), "trusted app Python module absent")
    spec = importlib.util.spec_from_file_location(name, path)
    check(spec is not None and spec.loader is not None, "cannot load trusted module")
    instance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance


def main():
    check(len(OBJECTIVE) >= 25 and len(OBJECTIVE) <= 320, "invalid objective length")
    check(OUT.is_dir() and EVIDENCE.is_dir() and INSTALLED.is_dir(),
          "expected disposable output and source directories")
    check(not any(p.is_symlink() for p in (OUT, EVIDENCE, INSTALLED)),
          "symlinked evidence or pinned runtime")
    verifier = import_code(HERE / "installed_integrity.py", "_nf_selfdev_integrity")
    manifest = verifier.verify(INSTALLED)
    check(manifest["files_verified"] == 16
          and manifest["live_execution_allowed"] is False,
          "immutable provider code origin not proven")
    sys.path.insert(0, str(INSTALLED / "core"))
    sys.path.insert(0, str(INSTALLED / "providers"))
    from one_task_core import OneTaskCore, EMPTY_SHA
    import ollama_worker
    import evidence_receipt
    from local_workspace import WorkspaceStore
    from signed_owner_admission import (
        _canon, prepare_draft_request, admit_signed_draft,
    )

    source = (HERE / "signed_owner_admission.py").resolve(strict=True)
    source_bytes = source.read_bytes()
    check(0 < len(source_bytes) <= 20000, "oversized source review")
    source_digest = sha256(source_bytes).hexdigest()

    with TemporaryDirectory(prefix="nf-real-signed-selfdev-") as tmp:
        root = Path(tmp)
        repo = root / "source"
        repo.mkdir(mode=0o700)
        run_git(repo, "init", "-q")
        run_git(repo, "config", "user.name", "CI Disposable Signature Reviewer")
        run_git(repo, "config", "user.email", "ci@example.invalid")
        # The exact code being reviewed comes from the checked-out PR branch,
        # and is preserved unchanged in a new disposable Git commit.
        dest = repo / "bridge/neurofactory/one_pc_candidate/signed_owner_admission.py"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        check(sha256(dest.read_bytes()).hexdigest() == source_digest,
              "review source changed during staging")
        run_git(repo, "add", dest.relative_to(repo).as_posix())
        run_git(repo, "commit", "-qm", "Immutable self-development source evidence")
        source_sha = run_git(repo, "rev-parse", "HEAD")
        check(len(source_sha) == 40, "source commit not pinned")
        workspace = WorkspaceStore(root / "workspace")
        project = workspace.create_project({
            "name": "Self-development isolated signed CI",
            "description": "Review PR 43 code; no mutation authority.",
        })
        draft = workspace.create_task({
            "project_id": project["id"], "objective": OBJECTIVE,
            "model_preference": MODEL,
        })
        unsigned = prepare_draft_request(workspace, draft["id"])
        check(unsigned["owner_signed"] is False
              and unsigned["queue_mutation_allowed"] is False,
              "browser request cannot be trusted as an approval")

        core_root = root / "core"
        core_root.mkdir(mode=0o700)
        core = OneTaskCore(core_root, repo)
        spec = {
            "schema": "neurofactory.core.task.v1",
            "task_id": TASK_ID,
            "project_id": "p-" + project["id"],
            "target": TARGET,
            "objective": OBJECTIVE,
            "source_sha": source_sha,
            "source_sha256": EMPTY_SHA,
            "approval_commit": source_sha,
            "model": MODEL,
            "reserved_units": 3000,
        }
        now = int(time.time())
        body = {
            "schema": "nf.onepc.owner_core_admission.v1",
            "scope": EXPECTED_SCOPE,
            "draft": unsigned,
            "spec": spec,
            "nonce": os.urandom(16).hex(),
            "issued_at": now - 1,
            "expires_at": now + 120,
        }
        secret = Ed25519PrivateKey.generate()
        public_raw = secret.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw)
        signature = secret.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00" + _canon(body))
        permit = {**body, "owner_signature": base64.b64encode(signature).decode("ascii")}
        # No keys written to disk, stdout, artifact or model.
        admitted = admit_signed_draft(
            workspace, core, permit, owner_public_raw=public_raw, now=now)
        del secret, public_raw, signature, permit, body
        check(admitted["core_reported_state"] == "QUEUED"
              and admitted["host_execution_allowed"] is False
              and admitted["queue_claim_allowed"] is False,
              "CI signed admission unexpectedly granted execution")
        check(core.snapshot()["state"] == "QUEUED", "real SQLite CORE admission absent")
        preview = core.provider_preview(TASK_ID)
        check(preview["schema"] == "neurofactory.coordination.provider_bridge.v1",
              "genuine CORE preview absent")
        check(preview["permissions"] == {
            "execution": False, "retry": False, "publication": False, "paid_api": False,
        }, "CORE preview supplied an execution privilege")
        b = preview["binding"]
        check(b["model"] == MODEL and b["project_id"] == spec["project_id"]
              and b["core_target"] == TARGET
              and b["source_sha"] == source_sha
              and b["source_sha256"] == EMPTY_SHA
              and b["provider_target"] == "docs/review.md"
              and b["input_sha256"] == preview["request"]["input_sha256"],
              "provider mapping differs from signed admitted CORE spec")
        task = ollama_worker.ProviderTask.from_json(preview["request"])
        budget_dir = root / "durable_model_attempt"
        budget_dir.mkdir(mode=0o700)

        # Inference is authorized ONLY by this disposable CI job's explicit
        # separate user-requested gate, NOT by the enqueue-only owner signature.
        # Qwen has no access to signing key, CORE handle, working Git repo or HOST.
        print("NF_SIGNED_CORE_MODEL_PREVIEW=REAL_QUEUED_INERT")
        answer = ollama_worker.execute_one(
            task, model=MODEL, ledger_dir=budget_dir,
            max_output_tokens=420, evidence_dir=EVIDENCE)
        check(answer["schema"] == ollama_worker.SCHEMA_RESULT
              and answer["task_id"] == TASK_ID
              and answer["project_id"] == spec["project_id"]
              and answer["input_sha256"] == b["input_sha256"]
              and answer["model"] == MODEL
              and answer["api_cost_usd"] == 0
              and answer["offline_mock"] is False
              and answer["published"] is False
              and answer["review_approved"] is False,
              "real provider violated immutable/safe input contract")

        # Sealed evidence must be readable even if Qwen failed the strict
        # JSON proposal schema. Such failures are NOT silently retried.
        has_reply = answer.get("observed_local_reply") is True
        record = None
        if has_reply:
            record = evidence_receipt.verify_model_evidence(EVIDENCE, TASK_ID)
            check(record["response_sha256"] == answer["response_sha256"],
                  "real response and seal hashes differ")
        check(answer["status"] == "PROPOSED_UNVERIFIED",
              "Qwen reply was not a valid inert proposal: " + answer["status"]
              + " / " + str(answer.get("error_code")))
        files = answer["proposed_files"]
        check(len(files) == 1, "expected exactly one untrusted proposal")
        proposed = files[0]
        text = proposed["content"]
        check(proposed["relative_path"] == "docs/review.md"
              and proposed["applied"] is False
              and proposed["verified_by_core"] is False
              and sha256(text.encode("utf-8")).hexdigest()
              == proposed["content_sha256"]
              and 10 <= len(text) <= 9000,
              "model reply failed exact-path, bounded-content, or SHA checks")
        check(core.snapshot()["state"] == "QUEUED",
              "model unexpectedly advanced true CORE queue state")
        check(workspace.list_tasks()[0]["state"] == "DRAFT_PENDING_OWNER_AUTH",
              "model mutated durable original UI draft")
        reservation = ollama_worker.DurableBudget(
            budget_dir, max_attempts=1, max_reserved_units=50000).snapshot()
        check(reservation["attempts"] == 1, "real model attempt not durably reserved")
        # Attempting the SAME Qwen task again must fail BEFORE second HTTP.
        second = ollama_worker.execute_one(
            task, model=MODEL, ledger_dir=budget_dir,
            max_output_tokens=420, evidence_dir=EVIDENCE)
        check(second["status"] == "BLOCKED"
              and second["error_code"] == "BLOCKED_DUPLICATE_OR_LEDGER",
              "durable model reservation failed to block replay")

        candidate = OUT / "proposal_for_independent_review.md"
        with candidate.open("xb") as out:
            out.write(text.encode("utf-8"))
            out.flush()
            os.fsync(out.fileno())
        check(sha256(candidate.read_bytes()).hexdigest()
              == proposed["content_sha256"],
              "untrusted proposal file readback mismatch")

        report = {
            "schema": "nf.ci.signed_real_qwen_selfdev.v1",
            "status": "PROPOSED_UNVERIFIED",
            "disposable_test_only": True,
            "source_branch": "neurofactory-onepc-signed-core-real-qwen-selfdev-20261019",
            "source_reviewed": source.relative_to(HERE.parent.parent.parent).as_posix(),
            "source_sha256": source_digest,
            "source_commit": source_sha,
            "draft_id": draft["id"],
            "draft_sha256": unsigned["draft_sha256"],
            "core_task_id": TASK_ID,
            "core_project_id": spec["project_id"],
            "signed_admission_accepted": True,
            "core_state_after_proposal": core.snapshot()["state"],
            "provider_preview_input_sha256": b["input_sha256"],
            "requested_model": MODEL,
            "ollama_model_weights_independently_attested": False,
            "http_fake_model_used": False,
            "model_attempt_consumed": True,
            "model_second_attempt": "BLOCKED",
            "proposal_relative_path": proposed["relative_path"],
            "proposal_sha256": proposed["content_sha256"],
            "provider_evidence_sha256": record["evidence_sha256"],
            "provider_observed_response_sha256": answer["response_sha256"],
            "review_approved": False,
            "source_applied": False,
            "host_effect_performed": False,
            "production_queue_enabled": False,
            "independent_review_complete": False,
        }
        artifact = OUT / "evidence_summary.json"
        raw = (json.dumps(report, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
        with artifact.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        check(artifact.read_bytes() == raw, "signed real Qwen report readback mismatch")
        print("NF_SELFDEV_GENUINE_SIGNED_CORE_TO_REAL_QWEN=PASS_UNVERIFIED")
        print("NF_SELFDEV_REAL_QWEN_MODEL=" + MODEL)
        print("NF_SELFDEV_CODE_SUGGESTION_SHA256=" + proposed["content_sha256"])
        print("NF_SELFDEV_PROVIDER_EVIDENCE_SHA256=" + record["evidence_sha256"])
        print("NF_SELFDEV_QWEN_MODEL_CALLS=ONE_REAL_NO_RETRY")
        print("NF_SELFDEV_CORE_STATE=QUEUED_NO_CLAIM")
        print("NF_SELFDEV_APPLIED_FILES=NONE")
        print("NF_SELFDEV_INDEPENDENT_REVIEW=NOT_DONE")
        print("NF_SELFDEV_OWNER_PC=NOT_TOUCHED")


if __name__ == "__main__":
    main()
