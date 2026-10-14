"""Adversarial independent REVIEW regressions for GitHub-backed Qwen3 proof."""
import copy
import hashlib
import io
import json
import unittest
import zipfile

from verify_qwen3_github_evidence import (
    REPO, WORKFLOW, ReviewProofError, inspect_evidence, sha256,
)

HEAD = "279995e7fa252882fceec7ee2e955884382c4f54"
SOURCE = b"def immutable_module(value):\n    return value\n"
DIGEST = sha256(SOURCE)
RUN_ID = 38628093324
ARTIFACT_ID = 123451010


def encoded(item):
    return (json.dumps(item, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def fixture():
    prompt = json.dumps({"source_sha256": DIGEST,
                         "full_python_module": SOURCE.decode("utf-8")},
                        ensure_ascii=False)
    request = {"model": "qwen3:4b", "prompt": prompt}
    verdict = {"verdict": "APPROVE", "candidate_sha256": DIGEST,
               "findings": ["No security issue found in this synthetic sample"]}
    response = {"model": "qwen3:4b",
                "response": json.dumps(verdict, sort_keys=True)}
    raw_request, raw_response = encoded(request), encoded(response)
    result = {
        "git_commit": HEAD, "source_sha256": DIGEST, "requested_model": "qwen3:4b",
        "ollama_model_digest_claim": "e" * 64,
        "request_sha256": sha256(raw_request),
        "ollama_response_sha256": sha256(raw_response),
        "review": verdict, "model_review_only": True,
        "trusted_external_provenance_confirmed": False,
        "independent_review_owner_approved": False, "release_authorized": False,
        "publisher_enabled": False, "publication_count": 0,
    }
    raw_result = encoded(result)
    checkpoint = {
        "git_commit": HEAD, "source_sha256": DIGEST,
        "state": "awaiting_external_review_owner",
        "result_sha256": sha256(raw_result),
        "independent_review_owner_approved": False, "release_authorized": False,
        "publication_count": 0,
    }
    files = {
        "request.json": raw_request,
        "ollama-response.json": raw_response,
        "result.json": raw_result,
        "checkpoint.json": encoded(checkpoint),
    }
    run = {
        "id": RUN_ID, "status": "completed", "conclusion": "success",
        "run_attempt": 1, "head_sha": HEAD, "head_branch":
        "neurofactory-model-handoff-owned-20261013",
        "path": WORKFLOW, "event": "push",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
    }
    job = {
        "run_id": RUN_ID, "name": "real_qwen3_review",
        "status": "completed", "conclusion": "success",
        "steps": [{"name": x, "conclusion": "success"} for x in (
            "Acquire exact free Qwen3 locally, no paid API",
            "Independently inspect exact repaired source and save raw evidence",
            "Preserve read-only reviewer evidence even on failure")],
    }
    artifact = {
        "id": ARTIFACT_ID,
        "name": "neurofactory-handoff-owned-remediation-qwen3-evidence",
        "expired": False, "workflow_run": {"id": RUN_ID},
    }
    return run, [job], artifact, files


def pack(files, duplicates=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
        if duplicates:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr("request.json", files["request.json"])
    return stream.getvalue()


def verify(run=None, jobs=None, artifact=None, files=None, module=SOURCE, **kwargs):
    baseline = fixture()
    return inspect_evidence(
        baseline[0] if run is None else run,
        baseline[1] if jobs is None else jobs,
        baseline[2] if artifact is None else artifact,
        ARTIFACT_ID, pack(baseline[3] if files is None else files),
        HEAD, module, **kwargs)


class EvidenceReviewTests(unittest.TestCase):
    def test_realistic_valid_evidence_remains_pending_owner_approval(self):
        result = verify()
        self.assertTrue(result["github_metadata_consistent"])
        self.assertTrue(result["raw_bytes_integrity_verified"])
        self.assertEqual(result["model_opinion"], "APPROVE")
        for key in ("model_process_cryptographically_authenticated",
                    "independent_review_owner_approved",
                    "release_authorized", "merge_authorized", "publisher_allowed"):
            self.assertIs(result[key], False, key)

    def test_git_run_failed_or_running_never_accepted(self):
        for update in ({"status": "in_progress"}, {"conclusion": "failure"},
                       {"run_attempt": 2}, {"head_sha": "f"*40},
                       {"head_branch": "main"}, {"path": "untrusted.yml"},
                       {"event": "pull_request"},
                       {"repository": {"full_name": "attacker/repo"}},
                       {"head_repository": {"full_name": "attacker/repo"}}):
            with self.subTest(update=update):
                run = fixture()[0]
                run.update(update)
                with self.assertRaises(ReviewProofError):
                    verify(run=run)

    def test_artifact_from_another_run_and_expired_artifact_rejected(self):
        for mutation in ({"id": 13}, {"expired": True},
                         {"workflow_run": {"id": 99999}},
                         {"name": "different-job"}):
            artifact = fixture()[2]
            artifact.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ReviewProofError):
                verify(artifact=artifact)

    def test_model_step_failure_and_missing_job_rejected(self):
        jobs = fixture()[1]
        jobs[0]["steps"][1]["conclusion"] = "failure"
        with self.assertRaises(ReviewProofError):
            verify(jobs=jobs)
        with self.assertRaises(ReviewProofError):
            verify(jobs=[])

    def test_tampered_source_after_review_is_refused(self):
        with self.assertRaises(ReviewProofError):
            verify(module=SOURCE+b"# modified\n")

    def test_corrupt_response_checksum_rejected(self):
        files = fixture()[3]
        response = json.loads(files["ollama-response.json"])
        response["response"] = response["response"].replace("APPROVE","REJECT")
        files["ollama-response.json"] = encoded(response)
        with self.assertRaises(ReviewProofError):
            verify(files=files)

    def test_forged_approved_result_does_not_override_raw_model_output(self):
        files=fixture()[3]
        response=json.loads(files["ollama-response.json"])
        response["response"]=json.dumps({"verdict":"REJECT",
            "candidate_sha256":DIGEST,"findings":["Critical issue"]})
        files["ollama-response.json"]=encoded(response)
        result=json.loads(files["result.json"])
        result["ollama_response_sha256"]=sha256(files["ollama-response.json"])
        files["result.json"]=encoded(result)
        checkpoint=json.loads(files["checkpoint.json"])
        checkpoint["result_sha256"]=sha256(files["result.json"])
        files["checkpoint.json"]=encoded(checkpoint)
        with self.assertRaises(ReviewProofError):
            verify(files=files)

    def test_release_true_in_result_or_checkpoint_rejected(self):
        for field in ("result.json","checkpoint.json"):
            files = fixture()[3]
            content=json.loads(files[field])
            content["release_authorized"]=True
            files[field]=encoded(content)
            if field=="result.json":
                checkpoint=json.loads(files["checkpoint.json"])
                checkpoint["result_sha256"]=sha256(files["result.json"])
                files["checkpoint.json"]=encoded(checkpoint)
            with self.subTest(field=field), self.assertRaises(ReviewProofError):
                verify(files=files)

    def test_duplicate_members_rejected(self):
        items=fixture()
        with self.assertRaises(ReviewProofError):
            inspect_evidence(items[0],items[1],items[2],ARTIFACT_ID,
                             pack(items[3],duplicates=True),HEAD,SOURCE)

    def test_truncated_archive_rejected(self):
        items=fixture()
        blob=pack(items[3])[:20]
        with self.assertRaises(ReviewProofError):
            inspect_evidence(items[0],items[1],items[2],ARTIFACT_ID,
                             blob,HEAD,SOURCE)

    def test_duplicate_json_keys_and_unbound_prompt_rejected(self):
        files = fixture()[3]
        files["request.json"] = b'{"model":"qwen3:4b","model":"qwen3:4b"}'
        result=json.loads(files["result.json"])
        result["request_sha256"]=sha256(files["request.json"])
        files["result.json"]=encoded(result)
        checkpoint=json.loads(files["checkpoint.json"])
        checkpoint["result_sha256"]=sha256(files["result.json"])
        files["checkpoint.json"]=encoded(checkpoint)
        with self.assertRaises(ReviewProofError):
            verify(files=files)

    def test_model_weight_digest_is_only_claim_not_signature(self):
        result=verify()
        self.assertEqual(result["model_digest"],"e"*64)
        self.assertIs(result["model_process_cryptographically_authenticated"],False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
