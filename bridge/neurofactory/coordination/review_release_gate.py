"""Read-only release blocker for the exact independent HANDOFF rejection.

The REVIEW report is an audit input, NOT a cryptographic signature or authorization.
No GitHub publication/merging or model invocation is performed. All states remain
blocked until independently reviewed patched source and real protected-branch policy.
"""
import argparse
import base64
import hashlib
import json
import re
import urllib.parse
import urllib.request

REPO = "DSLitvinov1/my_first_repo"
ISSUE = 3
API = "https://api.github.com/repos/" + REPO + "/"
HANDOFF_BRANCH = "neurofactory-model-handoff-owned-20261013"
REVIEW_BRANCH = "neurofactory-review-owned-20261013"
HANDOFF_FILE = "bridge/neurofactory/development/model_handoff_owned/handoff_gate.py"
REVIEW_FILE = "bridge/neurofactory/development/review_owned/independent_handoff_review_20261014.json"
KNOWN_REJECTED_SHA = "b205a495b51aa125dd8273955c202a177df7a173"
KNOWN_REJECTED_SOURCE_SHA256 = "75197baba20d14fcaa2cb47ad52b94971082d1b3220032d6909ea1886678e6dc"
EXPECTED_FINDINGS = {"REVIEW-HANDOFF-001", "REVIEW-HANDOFF-002"}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")

class ReleaseEvidenceError(ValueError):
    pass


def github_get(url):
    if not isinstance(url, str) or not url.startswith(API):
        raise ReleaseEvidenceError("Cross-repository or untrusted URL")
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "Neurofactory-Coordinator-ReadOnly-Release-Gate"
    }, method="GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _head(branch, getter):
    doc = getter(API + "branches/" + urllib.parse.quote(branch, safe="-"))
    if not isinstance(doc, dict):
        raise ReleaseEvidenceError("Malformed branch information")
    sha = ((doc.get("commit") or {}).get("sha"))
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        raise ReleaseEvidenceError("No exact branch commit")
    return sha


def _file(path, branch, getter):
    url = API + "contents/" + path + "?ref=" + urllib.parse.quote(branch, safe="-")
    doc = getter(url)
    if not isinstance(doc, dict) or doc.get("path") != path or doc.get("type") != "file":
        raise ReleaseEvidenceError("Unverified content path or type")
    encoded = doc.get("content")
    if not isinstance(encoded, str) or doc.get("encoding") != "base64":
        raise ReleaseEvidenceError("Source is not verified base64 content")
    try:
        return base64.b64decode(encoded.replace("\n", ""), validate=True)
    except (ValueError, Exception) as exc:
        raise ReleaseEvidenceError("Unverifiable content bytes") from exc


def analyze(report, handoff_sha, review_sha, source_digest, *, protected=False):
    if not isinstance(report, dict) or report.get("schema") != 1 or report.get("role") != "REVIEW":
        raise ReleaseEvidenceError("No independent REVIEW report")
    if report.get("project") != "НЕЙРОЗАВОД" or report.get("issue") != ISSUE:
        raise ReleaseEvidenceError("Wrong project/issue")
    expected_source = report.get("reviewed")
    if not isinstance(expected_source, dict):
        raise ReleaseEvidenceError("Missing exact reviewed source")
    if (expected_source.get("source_branch") != HANDOFF_BRANCH
            or expected_source.get("reviewed_file") != HANDOFF_FILE):
        raise ReleaseEvidenceError("Report targets another source")
    original_sha = expected_source.get("exact_commit")
    original_hash = expected_source.get("source_sha256")
    if original_sha != KNOWN_REJECTED_SHA or original_hash != KNOWN_REJECTED_SOURCE_SHA256:
        # A changed approval/review requires *separate new* coordinator acceptance;
        # never silently allow release on a changed text record.
        return {"status":"REVIEW_RECORD_CHANGED", "blocked":True,
                "reasons":["review_source_changed_requires_new_coordination_check"],
                "handoff_sha":handoff_sha,"review_sha":review_sha}
    findings = report.get("blocking_findings")
    if not isinstance(findings, list):
        raise ReleaseEvidenceError("Missing independent adverse findings")
    ids = {f.get("id") for f in findings if isinstance(f, dict)}
    if not EXPECTED_FINDINGS.issubset(ids):
        raise ReleaseEvidenceError("Expected adverse findings absent")
    if (report.get("decision") != "REJECT"
            or report.get("allow_merging") is not False
            or report.get("allow_publication") is not False
            or report.get("allow_core_handoff_integration") is not False):
        raise ReleaseEvidenceError("Rejected report contradicts publication block")
    reason = []
    if handoff_sha == original_sha and source_digest == original_hash:
        reason.extend(["review_owner_rejected_exact_source",
                       "directory_swap_race_confirmed", "qwen_provenance_not_authenticated"])
        status = "REJECTED_CURRENT_SOURCE"
    else:
        reason.extend(["handoff_changed_after_review", "new_independent_review_required"])
        status = "HANDOFF_REVIEW_STALE"
    if not protected:
        reason.append("production_branch_protection_unconfirmed")
    return {"status":status, "blocked":True, "reasons":reason,
            "handoff_sha":handoff_sha, "review_sha":review_sha,
            "source_sha256":source_digest, "reviewed_sha":original_sha,
            "reviewed_source_sha256":original_hash,
            "adverse_findings":sorted(EXPECTED_FINDINGS),
            "review_owner_decision":"REJECT",
            "github_model_attestation":"not_established",
            "independent_review_report_is_not_cryptographic_signature":True}


def audit(getter=github_get):
    handoff_sha = _head(HANDOFF_BRANCH, getter)
    review_sha = _head(REVIEW_BRANCH, getter)
    # Read content at the immutable exact HEAD, not the moving branch name:
    # a concurrent writer cannot swap the blob between head and file read.
    raw_source = _file(HANDOFF_FILE, handoff_sha, getter)
    raw_review = _file(REVIEW_FILE, review_sha, getter)
    try:
        report = json.loads(raw_review)
    except (TypeError, ValueError) as exc:
        raise ReleaseEvidenceError("Review report is invalid JSON") from exc
    source_digest = hashlib.sha256(raw_source).hexdigest()
    conclusion = analyze(report, handoff_sha, review_sha, source_digest)
    return {"schema":1,"project":"НЕЙРОЗАВОД",
            "area":"COORDINATOR_ONLY", "stage":"NF-DEV-05",
            "no_model_invocation":True,"no_repository_mutation":True,
            "chatgpt_delivery_paused":True,"paid_models_disabled":True,
            "release":conclusion}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", help="Write local evidence only, no GitHub mutation")
    args = parser.parse_args()
    report = audit()
    print("NEUROFACTORY_HANDOFF_RELEASE_BLOCKED " +
          json.dumps(report, ensure_ascii=False, sort_keys=True))
    if args.output:
        from pathlib import Path
        path=Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n","utf-8")


if __name__ == "__main__":
    try:
        main()
    except ReleaseEvidenceError as exc:
        raise SystemExit("NEUROFACTORY_RELEASE_GATE_SAFE_STOP " + str(exc))
