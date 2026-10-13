"""Live HANDOFF lab: isolated local Qwen author and independent Qwen reviewer.

Does not execute generated Python or write to GitHub. Models receive no credentials.
A reviewer approval is evidence for the REVIEW owner, not permission to merge.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

from model_handoff_owned import handoff_gate as gate

TASK = "NF-DEV-05-Q090"
TARGET = "bridge/neurofactory/development/model_handoff_owned/trial_only_not_published.py"
ENDPOINT = "http://127.0.0.1:11434/api/"
MAX_RETRIES = 2
TIMEOUT = 420
OUT = Path(os.environ.get("RUNNER_TEMP", ".")) / "neurofactory-handoff-live-q090"

class LiveError(ValueError):
    pass

def json_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def checkpoint(stage, *, error=None, **values):
    OUT.mkdir(parents=True, exist_ok=True)
    doc = {"schema": 1, "task_id": TASK, "lane": "handoff",
           "branch": gate.BRANCH, "stage": stage, "error": error,
           "publication_enabled": False, "chat_delivery": "paused",
           **values}
    destination = OUT / "checkpoint.json"
    temporary = OUT / "checkpoint.json.pending"
    if temporary.exists():
        raise LiveError("Prior interrupted checkpoint requires manual reconciliation")
    with temporary.open("xb") as stream:
        stream.write(json_bytes(doc) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    return doc

def local_model(model, prompt, *, formatted=False):
    payload = {"model": model, "prompt": prompt, "stream": False, "think": False,
               "options": {"temperature": 0, "num_predict": 560,
                           "num_ctx": 8192}, "keep_alive": 0}
    if formatted:
        payload["format"] = "json"
    req = urllib.request.Request(ENDPOINT + "generate", data=json_bytes(payload),
                                 method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Neurofactory-Isolated-Handoff"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            doc = json.load(resp)
    except (TimeoutError, OSError, urllib.error.URLError, ValueError) as exc:
        raise LiveError("Local model unavailable, invalid response or timeout") from exc
    if doc.get("model", "").split(":")[0] != model.split(":")[0]:
        raise LiveError("Unexpected model identity")
    answer = doc.get("response")
    if not isinstance(answer, str) or not answer.strip():
        raise LiveError("Model produced no answer")
    return answer, {"model": model, "eval_count": doc.get("eval_count"),
                    "total_duration": doc.get("total_duration")}

def call_bounded(model, prompt, *, formatted=False, phase):
    for attempt in range(1, MAX_RETRIES + 1):
        checkpoint(phase + "_attempt", attempts=attempt)
        try:
            return local_model(model, prompt, formatted=formatted)
        except LiveError as exc:
            checkpoint(phase + "_failed", attempts=attempt, error=str(exc))
            if attempt == MAX_RETRIES:
                raise
    raise LiveError("Retry limit exhausted")

def prepare_candidate(raw):
    source = raw.strip()
    if source.startswith("~~~"):
        raise LiveError("Unexpected code fence")
    if source.startswith(chr(96) * 3):
        rows = source.splitlines()
        if len(rows) < 3 or not rows[-1].strip().startswith(chr(96) * 3):
            raise LiveError("Unclosed writer code fence")
        source = "\n".join(rows[1:-1]).strip()
    return gate.candidate_packet(TASK, TARGET, source)

def review_module(source, reviewer_reply):
    result = gate.strict_object(reviewer_reply)
    expected = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if result["candidate_sha256"] != expected:
        raise LiveError("Reviewer did not bind module review to exact source")
    if result["verdict"] not in ("APPROVE", "REJECT"):
        raise LiveError("Module review verdict invalid")
    if not isinstance(result["findings"], list):
        raise LiveError("Module review findings missing")
    if result["verdict"] == "REJECT" and not result["findings"]:
        raise LiveError("Module review rejected without evidence")
    return {"model": gate.REVIEWER, "source_sha256": expected,
            "verdict": result["verdict"], "findings": result["findings"],
            "release_authorized": False, "independent_review_owner_pending": True}

def run():
    OUT.mkdir(parents=True, exist_ok=True)
    models_request = urllib.request.Request(ENDPOINT + "tags",
                                           headers={"User-Agent": "Neurofactory-Isolated-Handoff"})
    with urllib.request.urlopen(models_request, timeout=15) as response:
        models = json.load(response)
    names = {item.get("name") for item in models.get("models", [])}
    if not {gate.WRITER, gate.REVIEWER}.issubset(names):
        raise LiveError("Required free local model missing: do not substitute paid API")
    checkpoint("preflight_pass", models=list(sorted((gate.WRITER, gate.REVIEWER))))
    prompt = (
        "Write ONLY Python source (no explanations) for ONE PURE function "
        "normalize_label(value). Contract: reject non-string inputs by raising "
        "ValueError; for strings, strip leading/trailing whitespace, replace any "
        "internal run of whitespace with exactly one ASCII space, and lowercase "
        "the result. Empty strings must produce an empty string. No imports, "
        "files, network, eval or exec. Do not call any external service."
    )
    raw, author_stats = call_bounded(gate.WRITER, prompt, phase="writer")
    packet = prepare_candidate(raw)
    checkpoint("candidate_validated", writer=gate.WRITER,
               candidate_sha256=packet["candidate_sha256"])
    review_prompt = gate.review_request(packet)
    reply, reviewer_stats = call_bounded(gate.REVIEWER, review_prompt,
                                        formatted=True, phase="candidate_review")
    review = gate.review_packet(packet, reply, model=gate.REVIEWER)
    checkpoint("candidate_reviewed", candidate_sha256=packet["candidate_sha256"],
               verdict=review["verdict"])
    proofs = gate.persist_handoff(OUT, packet, review)
    if review["verdict"] != "APPROVE":
        checkpoint("blocked", error="Independent reviewer rejected actual candidate",
                   candidate_sha256=packet["candidate_sha256"])
        raise LiveError("Independent candidate verdict REJECT")
    source_path = Path(__file__).with_name("handoff_gate.py")
    module_source = source_path.read_text("utf-8")
    module_sha = hashlib.sha256(module_source.encode("utf-8")).hexdigest()
    audit_prompt = json.dumps({
        "instruction": (
            "Independently audit this HANDOFF Python module. Check candidate hash "
            "binding, strict reviewer JSON, possibility of forged identity or verdict, "
            "accidental file overwrites, cross-lane access, and unauthorized publication. "
            "Never claim tests were run unless actually executed. Output a single JSON "
            "object with exactly verdict ('APPROVE' or 'REJECT'), "
            "candidate_sha256 (copy provided source_sha256), and findings (specific "
            "reasons). Reject any meaningful security flaw or uncertainty."
        ), "source_sha256": module_sha, "actual_module_source": module_source
    }, ensure_ascii=False)
    module_reply, audit_stats = call_bounded(gate.REVIEWER, audit_prompt,
                                            formatted=True, phase="module_review")
    module_result = review_module(module_source, module_reply)
    (OUT / "module_review.json").write_bytes(json_bytes(module_result) + b"\n")
    record = {"task_id": TASK, "writer": author_stats, "reviewer": reviewer_stats,
              "module_reviewer": audit_stats, "candidate_sha256": packet["candidate_sha256"],
              "module_sha256": module_sha, "candidate_verdict": review["verdict"],
              "module_verdict": module_result["verdict"],
              "release_authorized": False, "publication_count": 0,
              "evidence_hashes": {name: row["sha256"] for name, row in proofs.items()}}
    (OUT / "summary.json").write_bytes(json_bytes(record) + b"\n")
    if module_result["verdict"] != "APPROVE":
        checkpoint("blocked", error="Independent module review rejected")
        raise LiveError("Independent module review not approved")
    checkpoint("awaiting_review_owner", candidate_sha256=packet["candidate_sha256"],
               module_sha256=module_sha, publisher_enabled=False)
    print("HANDOFF_REAL_TWO_MODEL_EVIDENCE_OK", packet["candidate_sha256"],
          "MODULE_REVIEW_OK", module_sha)
    print("NO_PUBLICATION; REVIEW_OWNER_APPROVAL_STILL_REQUIRED")

if __name__ == "__main__":
    try:
        run()
    except (LiveError, gate.HandoffError, OSError, ValueError, urllib.error.URLError) as error:
        try:
            checkpoint("blocked", error=str(error))
        except (OSError, LiveError):
            pass
        print("HANDOFF_ISOLATED_SAFE_STOP:", str(error), file=sys.stderr)
        raise SystemExit(1)
