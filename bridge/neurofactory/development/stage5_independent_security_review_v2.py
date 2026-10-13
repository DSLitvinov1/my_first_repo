"""Fail-closed independent Qwen3 review of all four current Stage5 queue components.

Each exact module is independently reviewed in full; verdicts are not synthesized
from incomplete/malformed model responses. No publisher credentials or effects.
"""
import hashlib
import json
import os
import pathlib
import urllib.request
import urllib.error

HERE = pathlib.Path(__file__).resolve().parent
PARTS = [
    ("stage5_development_queue.py", "approved task identity, role gating, cross-job concurrency, lease recovery, protected restore"),
    ("stage5_remote_journal.py", "compare-and-swap external checkpoint, no stale rewind, uncertain publishing safe halt"),
    ("stage5_git_receipts.py", "authentic GitHub ancestry, exact branch and path, source digest, forged Qwen approval"),
    ("stage5_usage_ledger.py", "no duplicated billing, no invented costs, appended audit integrity, foreign scope rejection")
]
OUTPUT = HERE / "stage5-independent-review-v2-result.json"
MODEL = "qwen3:4b"
SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["REVIEW_OK", "REVIEW_BAD"]},
        "reason": {"type": "string"},
    },
    "required": ["verdict", "reason"],
    "additionalProperties": False,
}

def question(filename, source, topic):
    # Show the reviewer the actual dependency that implements the cross-process
    # lock instead of asking it to guess whether the lock is process-global.
    context = ""
    if filename == "stage5_development_queue.py":
        dependency = (HERE / "durable_checkpoint.py").read_text("utf-8")
        regression = (HERE / "test_stage5_development_queue.py").read_text("utf-8")
        context = ("\nREAD-ONLY DEPENDENCY IMPLEMENTING _lock, _save AND LOAD:\n" +
                   dependency + "\nTWO-PROCESS CONCURRENCY / CRASH REGRESSIONS:\n" +
                   regression)
    prompt = (
        "You are the SECOND INDEPENDENT AI, Qwen3:4b, acting as a STRICT "
        "safety and correctness auditor. A different agent developed the code. "
        "Analyze all of the EXACT Python module provided below, not assumptions, "
        "before approving anything. Module: " + filename + ". Focus: " + topic +
        ". Required security properties: Neurofactory-only allowed paths and fixed "
        "branch; distinct approved tasks and role identities; Qwen2.5 Coder writes "
        "only draft; Qwen3 independently approves; trusted GitHub publisher validates "
        "SHA and content, commits checkpoint before effect, never blindly retries "
        "an uncertain side effect; stale or forged receipt cannot mark completion; "
        "no unrelated app modifications; no ChatGPT messaging or paid service. "
        "This module may be a single component calling other components; do not "
        "invent unshown logic. It is not yet auto-enabled. Examine a concrete "
        "bypass or race in this code, not marketing claims. "
        "Respond with one JSON object containing verdict REVIEW_OK or REVIEW_BAD "
        "and a detailed reason. REVIEW_BAD must identify a precise function or "
        "execution path and an actual counterexample. REVIEW_OK must describe "
        "at least two concrete verified safeguards and a remaining deployment "
        "limitation. Never return fields other than verdict and reason.\n"
        "SOURCE BELOW (ENTIRE FILE):\n" + source + context
    )
    payload = {
        "model": MODEL, "stream": False, "think": False,
        "format": SCHEMA, "keep_alive": "10m",
        "prompt": prompt,
        "options": {"temperature": 0, "num_ctx": 16000, "num_predict": 700,
                    "num_thread": 4, "num_gpu": 0},
    }
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            req, timeout=540) as connection:
        result = json.load(connection)
    if result.get("done") is not True:
        raise RuntimeError("Independent review incomplete for " + filename)
    raw = str(result.get("response", "")).strip()
    if not raw:
        raise RuntimeError("Qwen3 returned no review for " + filename)
    decision = json.loads(raw)
    if (set(decision) != {"verdict", "reason"} or
            decision.get("verdict") not in ("REVIEW_OK", "REVIEW_BAD") or
            not isinstance(decision.get("reason"), str) or
            len(decision["reason"].strip()) < 35):
        raise RuntimeError("Invalid or missing Qwen3 security rationale for " + filename)
    return decision

def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise RuntimeError("Independent reviewer must not have publisher credentials")
    if os.getenv("GITHUB_REPOSITORY") != "DSLitvinov1/my_first_repo":
        raise RuntimeError("Wrong review project")
    report = {"schema": 2, "stage": "NF-DEV-05",
              "scope": "neurofactory_only", "reviewer": MODEL,
              "chat_delivery_paused": True,
              "automatic_publication_enabled": False,
              "components": [], "verdict": "REVIEW_PENDING"}
    try:
        for filename, topic in PARTS:
            data = (HERE / filename).read_text(encoding="utf-8")
            digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
            print("INDEPENDENT_QWEN3_REVIEWING", filename, digest, flush=True)
            decision = question(filename, data, topic)
            report["components"].append(
                {"file": filename, "source_sha256": digest,
                 "verdict": decision["verdict"], "reason": decision["reason"][:1200]})
            print("INDEPENDENT_QWEN3_COMPONENT_VERDICT", filename, decision["verdict"],
                  decision["reason"][:300], flush=True)
            if decision["verdict"] != "REVIEW_OK":
                report["verdict"] = "REVIEW_BAD"
                break
        else:
            report["verdict"] = "REVIEW_OK"
    finally:
        OUTPUT.write_text(json.dumps(report, sort_keys=True, indent=2,
                    ensure_ascii=False) + "\n", encoding="utf-8")
    print("INDEPENDENT_STAGE5_FINAL_VERDICT", report["verdict"],
          "component_count", len(report["components"]), flush=True)
    if report["verdict"] != "REVIEW_OK" or len(report["components"]) != len(PARTS):
        raise RuntimeError("Stage5 requires four explicit Qwen3 approvals")
if __name__ == "__main__":
    main()
