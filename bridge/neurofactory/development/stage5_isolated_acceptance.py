"""Isolated, fail-closed Stage5 Q001 two-agent evidence and GitHub CAS publisher.

No generation ever receives GitHub credentials. Candidate code is never executed.
This is an acceptance proof, not a production code deployment.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-stage5-isolated-acceptance-20261013"
RECEIPT = "bridge/neurofactory/development/stage5-evidence/receipt-NF-DEV-05-Q001.json"
TASK = "NF-DEV-05-Q001"
WRITER = "qwen2.5-coder:7b"
REVIEWER = "qwen3:4b"
OLLAMA = "http://127.0.0.1:11434"
OUT = Path(os.environ.get("RUNNER_TEMP", ".")) / "neurofactory-stage5-evidence-Q001"
API = "https://api.github.com/repos/" + REPO + "/contents/" + RECEIPT
SAFE_IMPORTS = {"hashlib", "json", "typing", "dataclasses"}
FORBIDDEN = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "globals", "locals", "breakpoint", "input"}
MAX_OUTPUT = 9000


class GateError(ValueError):
    pass


def canon(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def request_json(url, data=None, *, token=None, timeout=30, method=None):
    headers = {"Content-Type": "application/json", "Accept": "application/vnd.github+json",
               "User-Agent": "NeurofactoryStage5-IsolatedGate"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=canon(data) if data is not None else None,
                                     headers=headers, method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def model_call(model, prompt):
    result = request_json(OLLAMA + "/api/generate", {
        "model": model, "prompt": prompt, "stream": False,
        "format": "json" if model == REVIEWER else None,
        "think": False,
        "options": {"temperature": 0, "num_predict": 480 if model == REVIEWER else 800,
                    "num_ctx": 3072},
        "keep_alive": 0
    }, timeout=600)
    if result.get("model", "").split(":")[0] != model.split(":")[0]:
        raise GateError("Wrong model responded")
    response = result.get("response")
    if not isinstance(response, str) or not response.strip() or len(response) > MAX_OUTPUT:
        raise GateError("Model output absent or oversized")
    return response, {"model": result.get("model"), "eval_count": result.get("eval_count"),
                      "total_duration_ns": result.get("total_duration")}


def clean_candidate(raw):
    src = raw.strip()
    if src.startswith("```"):
        lines = src.splitlines()
        if len(lines) < 3 or not lines[-1].strip().startswith("```"):
            raise GateError("Unclosed code fence")
        src = "\n".join(lines[1:-1]).strip()
    if not 25 <= len(src) <= MAX_OUTPUT:
        raise GateError("Invalid candidate length")
    try:
        parsed = ast.parse(src)
    except SyntaxError as exc:
        raise GateError("Writer output is not valid Python") from exc
    if not any(isinstance(node, (ast.FunctionDef, ast.ClassDef)) for node in parsed.body):
        raise GateError("No actual Python implementation")
    for node in ast.walk(parsed):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [alias.name.split(".")[0] for alias in node.names] if isinstance(node, ast.Import) else [((node.module or "").split(".")[0])]
            if any(module not in SAFE_IMPORTS for module in modules):
                raise GateError("Candidate imports unexpected dependency")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN:
            raise GateError("Unsafe candidate builtin")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise GateError("Dunder attribute access blocked")
    return src



def precheck():
    """Read-only Windows RAM and installed-local-model preflight."""
    if os.name == "nt":
        import ctypes
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        state = MemoryStatus()
        state.dwLength = ctypes.sizeof(MemoryStatus)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
            raise GateError("Cannot verify free physical RAM")
        if state.ullAvailPhys < 1800000 * 1024:
            raise GateError("Insufficient free RAM; no model or other app should be terminated")
    models = request_json(OLLAMA + "/api/tags", timeout=10)
    names = {item.get("name") for item in models.get("models", [])}
    if not {WRITER, REVIEWER}.issubset(names):
        raise GateError("Both approved free local models must already be installed")
    print("LOCAL_RAM_AND_TWO_FREE_MODELS_READY")

def generate():
    tags = request_json(OLLAMA + "/api/tags", timeout=10)
    available = {row.get("name") for row in tags.get("models", [])}
    if not {WRITER, REVIEWER}.issubset(available):
        raise GateError("Both free local models must already exist; no model downloads")
    prompt = (
        "Write only Python 3 source, no prose. Implement ONE PURE FUNCTION named "
        "approved_registry(records): accepts a list of dictionaries with exactly id, "
        "target, objective, checks duplicate ids and duplicate targets, rejects any "
        "empty id and path traversal, allows targets ONLY under "
        "bridge/neurofactory/development/, and returns an immutable tuple of "
        "validated records plus a deterministic sha256 string. "
        "Use hashlib and json standard-library imports if necessary. "
        "DO NOT define classes, magic methods or access any attribute beginning "
        "with double underscore. No filesystem, shell, network, dynamic execution, "
        "GitHub, secrets or other project operations."
    )
    writer_attempts = 0
    for writer_attempts in range(1, 3):
        writer_text, writer_stats = model_call(WRITER, prompt)
        try:
            candidate = clean_candidate(writer_text)
            break
        except GateError as exc:
            if writer_attempts == 2:
                raise
            prompt += (" Your preceding output FAILED static safety screening: " +
                       str(exc) + ". Rewrite with a simple pure function, "
                       "ordinary variables and no dunder attribute access.")
    writer_stats["attempts"] = writer_attempts
    digest = sha(candidate)
    review_prompt = (
        "/no_think\nYou are an INDEPENDENT security/code reviewer, not the author. "
        "Examine the ACTUAL Python candidate reproduced verbatim below. "
        "Check task identity/target duplication, path traversal, immutability, "
        "untrusted inputs and scope. Return ONLY JSON containing verdict "
        "('APPROVE' or 'REJECT'), candidate_sha256 (exact supplied digest) and findings "
        "(list of strings). Reject whenever requirements are not met. "
        "Task: immutable stage5 Neurofactory approved-task registry. "
        "Digest: " + digest + "\nACTUAL WRITER CANDIDATE:\n" + candidate
    )
    review_text, reviewer_stats = model_call(REVIEWER, review_prompt)
    try:
        verdict = json.loads(review_text)
    except (ValueError, TypeError) as exc:
        raise GateError("Independent reviewer did not emit JSON") from exc
    if not isinstance(verdict, dict) or verdict.get("candidate_sha256") != digest:
        raise GateError("Reviewer did not acknowledge actual candidate digest")
    if verdict.get("verdict") not in ("APPROVE", "REJECT") or not isinstance(verdict.get("findings"), list):
        raise GateError("Malformed independent review")
    evidence = {
        "schema": 1, "project": "НЕЙРОЗАВОД", "task_id": TASK,
        "source": "isolated_two_model_evidence_not_production",
        "chat_delivery": "paused_by_user", "paid_models_used": False,
        "writer": writer_stats, "reviewer": reviewer_stats,
        "candidate": candidate, "candidate_sha256": digest, "independent_review": verdict
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "evidence.json").write_bytes(canon(evidence) + b"\n")
    if verdict["verdict"] != "APPROVE":
        raise GateError("Independent reviewer rejected candidate: no publication")
    print("TWO_AGENT_HANDOFF_PASS", digest)


def validate():
    record = json.loads((OUT / "evidence.json").read_text(encoding="utf-8-sig"))
    if record.get("schema") != 1 or record.get("task_id") != TASK or record.get("source") != "isolated_two_model_evidence_not_production":
        raise GateError("Wrong task or untrusted artifact")
    source = record.get("candidate", "")
    if clean_candidate(source) != source or sha(source) != record.get("candidate_sha256"):
        raise GateError("Candidate bytes differ from reviewed digest")
    review = record.get("independent_review")
    if not isinstance(review, dict) or review.get("candidate_sha256") != sha(source) or review.get("verdict") != "APPROVE":
        raise GateError("No independent approval of exact candidate")
    if record.get("writer", {}).get("model", "").split(":")[0] != WRITER.split(":")[0] or record.get("reviewer", {}).get("model", "").split(":")[0] != REVIEWER.split(":")[0]:
        raise GateError("Model provenance mismatch")
    return record


def github_read(token):
    try:
        data = request_json(API + "?ref=" + BRANCH, token=token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        raise
    if data.get("path") != RECEIPT or not isinstance(data.get("sha"), str):
        raise GateError("Unexpected GitHub checkpoint path")
    raw = base64.b64decode(data["content"].replace("\n", ""))
    return json.loads(raw), data["sha"]



def verify_remote_record(record):
    if not isinstance(record, dict) or record.get("schema") != 1 or record.get("task_id") != TASK:
        raise GateError("Remote checkpoint belongs to another task")
    code = record.get("candidate")
    if not isinstance(code, str) or clean_candidate(code) != code or sha(code) != record.get("candidate_sha256"):
        raise GateError("Remote candidate digest invalid")
    verdict = record.get("independent_review")
    if not isinstance(verdict, dict) or verdict.get("verdict") != "APPROVE" or verdict.get("candidate_sha256") != sha(code):
        raise GateError("Remote result lacks matching independent approval")
    if record.get("writer", {}).get("model", "").split(":")[0] != WRITER.split(":")[0] or record.get("reviewer", {}).get("model", "").split(":")[0] != REVIEWER.split(":")[0]:
        raise GateError("Remote evidence model identities invalid")
    return record


def preflight():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GateError("Trusted preflight requires token")
    existing, _ = github_read(token)
    skip = existing is not None
    if skip:
        verify_remote_record(existing)
    target = os.environ.get("GITHUB_OUTPUT")
    if not target:
        raise GateError("Workflow output channel missing")
    with open(target, "a", encoding="utf-8") as out:
        out.write("skip_agents=" + ("true" if skip else "false") + "\n")
    print("EXISTING_PUBLISHED_RECEIPT_SKIP_AGENTS" if skip else "NO_EXISTING_RECEIPT_ALLOW_ONE_MODEL_CYCLE")


def audit_remote():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GateError("Trusted audit requires token")
    existing, _ = github_read(token)
    if existing is None:
        raise GateError("No durable remote receipt")
    verify_remote_record(existing)
    print("DURABLE_REMOTE_RECEIPT_VERIFIED", existing["candidate_sha256"])

def publish():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GateError("Only trusted publisher can use GitHub token")
    verified = validate()
    old, blobsha = github_read(token)
    if old is not None:
        if old == verified:
            print("PUBLICATION_ALREADY_EXISTS;NO_NEW_COMMIT")
            return
        raise GateError("Existing checked-in receipt differs; no replay or overwrite permitted")
    payload = {
        "branch": BRANCH,
        "message": "neurofactory: publish one independently verified Q001 isolated evidence receipt",
        "content": base64.b64encode(canon(verified) + b"\n").decode("ascii")
    }
    if blobsha:
        payload["sha"] = blobsha
    out = request_json(API, payload, token=token, method="PUT")
    observed, _ = github_read(token)
    if observed != verified or not out.get("commit", {}).get("sha"):
        raise GateError("Published GitHub receipt was not independently reread")
    print("ISOLATED_RECEIPT_PUBLISHED", out["commit"]["sha"])


def audit():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GateError("Trusted audit needs read token")
    verified = validate()
    observed, _ = github_read(token)
    if observed != verified:
        raise GateError("Remote checkpoint not equal to verified model proof")
    print("REMOTE_RECEIPT_VERIFIED", verified["candidate_sha256"])


if __name__ == "__main__":
    try:
        commands = {"generate": generate, "validate": validate,
                    "publish": publish, "audit": audit,
                    "preflight": preflight, "audit_remote": audit_remote, "precheck": precheck}
        if len(sys.argv) != 2 or sys.argv[1] not in commands:
            raise GateError("Choose generate / validate / publish / audit")
        result = commands[sys.argv[1]]()
        if sys.argv[1] == "validate":
            print("INDEPENDENT_CANDIDATE_DIGEST_VERIFIED", result["candidate_sha256"])
    except (GateError, OSError, ValueError, urllib.error.URLError) as exc:
        print("STAGE5_SAFE_STOP:", str(exc), file=sys.stderr)
        raise SystemExit(1)
