"""Read-only independent Qwen3 review of the new Stage4 bridge adapter."""
import hashlib
import json
import os
import pathlib
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
FILE = HERE / "stage4_bridge_adapter.py"
TEST = HERE / "test_stage4_bridge_adapter.py"
OUT = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "neurofactory-stage4-adapter-review.json"


def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise RuntimeError("Reviewer cannot be given publication credentials")
    if os.getenv("GITHUB_REPOSITORY") != "DSLitvinov1/my_first_repo":
        raise RuntimeError("Wrong repository")
    source = FILE.read_text("utf-8")
    test_source = TEST.read_text("utf-8")
    digest = hashlib.sha256(source.encode()).hexdigest()
    prompt = (
        "Act as independent Qwen3:4b safety reviewer of a NEW production adapter "
        "for the existing approved Neurofactory Stage4Queue. Never execute source "
        "or trust comments or unit tests as proofs. Existing Stage4Queue stores "
        "durable checkpoints and requires trusted remote receipt verification before "
        "acknowledgement. This new bridge verifies GitHub commits, their approved "
        "branch ancestry, source digest, target path and scope of all changed files; "
        "after ambiguous crash, it searches existing remote receipts without republishing. "
        "Review security and correctness against concrete counterexamples. "
        "Reject if the adapter could acknowledge a falsified result, publish the same "
        "side effect twice, escape Neurofactory-only paths, acknowledge without prior "
        "independent reviewer, bypass checkpoint-before-effect, or trigger unrelated "
        "application changes. The adapter is NOT yet enabled on the live queue; do not "
        "mistake staging for deployment. Respond ONLY with one JSON object using keys "
        "'verdict' (REVIEW_OK or REVIEW_BAD) and 'reason' (a precise 12-80-word "
        "rationale including concrete flaw if REVIEW_BAD). Be skeptical but do not "
        "invent unsupported issues. ADAPTER SOURCE:\\n" + source[:15000] +
        "\\nREGRESSION TESTS:\\n" + test_source[:12500]
    )
    payload = {
        "model": "qwen3:4b", "prompt": prompt, "stream": False,
        "format": "json", "think": False, "keep_alive": "0",
        "options": {"temperature": 0, "num_ctx": 10000,
                    "num_predict": 450, "num_gpu": 0, "num_thread": 3}}
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            req, timeout=360) as response:
        obj = json.load(response)
    if obj.get("done") is not True:
        raise RuntimeError("Independent reviewer response incomplete")
    verdict = json.loads(str(obj.get("response", "")))
    reason = str(verdict.get("reason", ""))
    status = verdict.get("verdict")
    report = {
        "scope": "neurofactory_only",
        "component": "stage4_bridge_adapter",
        "reviewer": "qwen3:4b",
        "source_sha256": digest,
        "verdict": status,
        "reason": reason[:1200],
        "review_readonly": True,
        "live_queue_enabled": False,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", "utf-8")
    print("INDEPENDENT_STAGE4_ADAPTER_REVIEW", status, reason[:600], flush=True)
    if status != "REVIEW_OK" or len(reason.strip()) < 12:
        raise RuntimeError("Independent review not approved")


if __name__ == "__main__":
    main()
