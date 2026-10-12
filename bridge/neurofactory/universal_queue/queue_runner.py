"""Crash-resumable, serial GitHub-backed synthetic app queue.

Workflow receives approved Russian task descriptions only from this isolated repo inbox.
Models run without the GitHub token; a trusted publisher atomically commits verified files.
"""
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import queue_core as queue
import new_app_factory as factory

REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-public-lab-20261012"
INBOX = "bridge/neurofactory/universal_queue/inbox.json"
DESTINATION = "bridge/neurofactory/pilots/universal/"
API = "https://api.github.com/repos/" + REPO + "/"
MAX_TASK_ATTEMPTS_PER_RUN = 2

def identity():
    if (os.environ.get("GITHUB_REPOSITORY") != REPO
        or os.environ.get("GITHUB_REF_NAME") != BRANCH
        or os.environ.get("NF_FREE_PUBLIC_CONFIRMED") != "yes"):
        raise ValueError("Only the preapproved public free synthetic branch is authorized")
    if not os.environ.get("GITHUB_TOKEN"):
        raise ValueError("Trusted publisher credential unavailable")

def request(method, endpoint, payload=None):
    token = os.environ["GITHUB_TOKEN"]
    if not endpoint.startswith(API):
        raise ValueError("Cross-repo API request denied")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "Content-Type": "application/json", "User-Agent": "NeurofactorySerialQueue"}
    raw = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(endpoint, method=method, data=raw, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.load(res)

def raw_remote(path, absent_ok=False):
    if not path.startswith("bridge/neurofactory/") or ".." in path:
        raise ValueError("Forbidden remote read")
    url = API + "contents/" + urllib.parse.quote(path, safe="/") + "?ref=" + BRANCH
    try:
        obj = request("GET", url)
        return base64.b64decode(obj["content"].replace("\n", "")), obj["sha"]
    except urllib.error.HTTPError as exc:
        if absent_ok and exc.code == 404:
            return None, None
        raise

def read_queue():
    raw, sha = raw_remote(INBOX)
    q = json.loads(raw.decode("utf-8"))
    queue.validate_queue(q)
    return q, sha

def write_queue(q, sha, note):
    queue.validate_queue(q)
    safe_note = "".join(c for c in note if c.isalnum() or c in " -_:")[:100]
    payload = {
        "branch": BRANCH, "sha": sha,
        "message": "neurofactory-status: " + safe_note,
        "content": base64.b64encode((json.dumps(q, indent=2, ensure_ascii=False) + "\n").encode()).decode()
    }
    output = request("PUT", API + "contents/" + INBOX, payload)
    return output["content"]["sha"]

def verified_remote_receipt(kind, task_id):
    """Revalidate every persisted source before considering an interrupted job complete."""
    task_id = factory.safe_id(task_id)
    base = DESTINATION + task_id + "/"
    manifest_data, _ = raw_remote(base + "verification-manifest.json", True)
    if manifest_data is None:
        return None
    manifest = json.loads(manifest_data.decode("utf-8"))
    expected = set(factory.SPECS[kind]["modules"])
    files = {name + ".py" for name in expected} | {"main.py", "test_app.py", "README.md"}
    if set(manifest.get("sha256", {})) != files:
        raise ValueError("Untrusted published file list")
    for name in sorted(files):
        data, _ = raw_remote(base + name)
        if hashlib.sha256(data).hexdigest() != manifest["sha256"][name]:
            raise ValueError("Public source mutated after approval")
        factory.source_file(task_id, name).write_bytes(data)
    factory.source_file(task_id, "verification-manifest.json").write_bytes(manifest_data)
    factory.verify_published_candidate(kind, task_id)
    return manifest, hashlib.sha256(manifest_data).hexdigest()

def run_writer(kind, task_id):
    env = {k: v for k, v in os.environ.items() if k not in (
        "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "ACTIONS_RUNTIME_TOKEN")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["OLLAMA_MAX_LOADED_MODELS"] = "1"
    env["OLLAMA_KEEP_ALIVE"] = "0"
    env["OLLAMA_NUM_PARALLEL"] = "1"
    proc = subprocess.run([sys.executable, "-B", str(pathlib.Path(factory.__file__)),
                           kind, task_id], env=env, cwd=pathlib.Path(factory.__file__).parent,
                          timeout=900, check=False)
    if proc.returncode:
        raise ValueError("Bounded agent generation or independent acceptance failed")
    return factory.verify_published_candidate(kind, task_id)

def atomic_publish(kind, task_id):
    """Create every verified file and proof with one atomic Git commit (no partial publication)."""
    proof = factory.verify_published_candidate(kind, task_id)
    if verified_remote_receipt(kind, task_id):
        manifest, digest = verified_remote_receipt(kind, task_id)
        if manifest.get("sha256") != proof["sha256"]:
            raise ValueError("Existing published result differs from this generated candidate")
        return digest
    base = DESTINATION + factory.safe_id(task_id) + "/"
    names = list(sorted(proof["sha256"])) + ["verification-manifest.json"]
    head = request("GET", API + "git/ref/heads/" + BRANCH)
    old_commit = head["object"]["sha"]
    current = request("GET", API + "git/commits/" + old_commit)
    tree = []
    for name in names:
        if name not in set(proof["sha256"]) | {"verification-manifest.json"}:
            raise ValueError("Unlisted candidate source")
        tree.append({"path": base + name, "mode": "100644", "type": "blob",
                     "content": factory.source_file(task_id, name).read_text("utf-8")})
    new_tree = request("POST", API + "git/trees",
                       {"base_tree": current["tree"]["sha"], "tree": tree})
    commit = request("POST", API + "git/commits",
                     {"message": "neurofactory: two-model reviewed synthetic app " + task_id,
                      "parents": [old_commit], "tree": new_tree["sha"]})
    # Fast-forward only; competing writers must not be silently overwritten.
    request("PATCH", API + "git/refs/heads/" + BRANCH,
            {"sha": commit["sha"], "force": False})
    receipt = verified_remote_receipt(kind, task_id)
    if receipt is None or receipt[0]["sha256"] != proof["sha256"]:
        raise ValueError("Committed proof was not independently re-readable")
    return receipt[1]

def commit_proof_states(q, task_id, proof):
    if (proof.get("status") != "two_models_reviewed"
        or proof.get("writer") != factory.WRITER
        or proof.get("reviewer") != factory.REVIEWER
        or proof.get("review_verdict") != "REVIEW_OK"
        or proof.get("tests_passed") != 10):
        raise ValueError("Bad separate-model proof")
    queue.accept_evidence(q, task_id, {
        "verified_by_runner": True, "stage": "writer", "outcome": "pass",
        "source_hashes": proof["sha256"]
    })
    queue.accept_evidence(q, task_id, {
        "verified_by_runner": True, "stage": "testing", "outcome": "pass",
        "passed": 10, "total": 10
    })
    queue.accept_evidence(q, task_id, {
        "verified_by_runner": True, "stage": "reviewing", "outcome": "pass",
        "reviewer": factory.REVIEWER, "verdict": "REVIEW_OK"
    })

def handle_task(q, sha, action):
    task_id, kind = action["task_id"], action["kind"]
    task = next(t for t in q["tasks"] if t["id"] == task_id)
    if kind not in factory.SPECS:
        task["state"] = "blocked"
        task["stage"] = "closed"
        task["error"] = "No new-app adapter approved for this category"
        return write_queue(q, sha, "blocked unsupported kind " + task_id)
    if task["stage"] not in ("writer", "testing", "reviewing", "publishing"):
        raise ValueError("Unexpected in-flight stage")
    # On restart check immutable Git evidence before rerunning AI.
    old_receipt = verified_remote_receipt(kind, task_id)
    if old_receipt:
        proof, digest = old_receipt
        if task["stage"] == "writer":
            commit_proof_states(q, task_id, proof)
        elif task["stage"] in ("testing", "reviewing"):
            # Only reconstruct proof stages by replaying the published verified
            # manifest from the writer stage, not by inventing missing facts.
            task["stage"] = task["state"] = "writing"
            task["proof"] = {}
            commit_proof_states(q, task_id, proof)
        queue.accept_evidence(q, task_id, {
            "verified_by_runner": True, "stage": "publishing", "outcome": "pass",
            "manifest_sha256": digest
        })
        return write_queue(q, sha, "resume proved result " + task_id)
    if task["stage"] != "writer":
        # Interruption before atomic publication: rerun safely.
        queue.accept_evidence(q, task_id, {
            "verified_by_runner": True, "stage": task["stage"], "outcome": "fail",
            "reason": "Interrupted before atomic Git publication"
        })
        sha = write_queue(q, sha, "bounded recovery " + task_id)
        if task["state"] == "failed":
            return sha
    sha = write_queue(q, sha, "writer started " + task_id)
    proof = run_writer(kind, task_id)
    commit_proof_states(q, task_id, proof)
    sha = write_queue(q, sha, "models acceptance and reviewer pass " + task_id)
    receipt = atomic_publish(kind, task_id)
    queue.accept_evidence(q, task_id, {
        "verified_by_runner": True, "stage": "publishing", "outcome": "pass",
        "manifest_sha256": receipt
    })
    return write_queue(q, sha, "published and verified " + task_id)

def run():
    identity()
    processed = 0
    for _ in range(MAX_TASK_ATTEMPTS_PER_RUN):
        q, sha = read_queue()
        action = queue.next_action(q)
        if action is None:
            print("QUEUE_IDLE:", json.dumps(queue.progress(q)), flush=True)
            break
        task_id = action["task_id"]
        try:
            handle_task(q, sha, action)
            processed += 1
        except Exception as error:
            # Durable bounded retry; no deleting or overwriting already published proof.
            current, current_sha = read_queue()
            task = next(t for t in current["tasks"] if t["id"] == task_id)
            if task["state"] == "pending":
                queue.next_action(current)
            if task["state"] in {"writing", "testing", "reviewing", "publishing"}:
                queue.accept_evidence(current, task_id, {
                    "verified_by_runner": True, "stage": task["stage"],
                    "outcome": "fail", "reason": str(error)[:180]
                })
                write_queue(current, current_sha, "safe failure " + task_id)
            print("QUEUE_JOB_SAFE_STOP:", task_id, type(error).__name__,
                  str(error)[:260], flush=True)
            processed += 1
    updated, _ = read_queue()
    print("QUEUE_PROGRESS:", json.dumps(queue.progress(updated)), flush=True)
    return 0 if not any(t["state"] == "failed" for t in updated["tasks"]) else 1

if __name__ == "__main__":
    try:
        sys.exit(run())
    except Exception as e:
        print("QUEUE_FATAL_SAFE_STOP:", type(e).__name__, str(e)[:300], flush=True)
        sys.exit(1)
