"""Cross-platform, read-only verification of real two-agent-approved recovery source."""
import hashlib
import json
import pathlib
import recovery_proposal as model

ROOT=pathlib.Path(__file__).resolve().parent
SOURCE=ROOT/"recovery_decision.py"
PROOF=ROOT/"recovery-verification.json"
def verify():
    if not SOURCE.is_file() or not PROOF.is_file():
        raise ValueError("Published recovery module or review receipt missing")
    raw=SOURCE.read_bytes()
    canonical=raw.replace(b"\r\n",b"\n")
    if b"\r" in canonical:
        raise ValueError("Unexpected source line ending")
    proof=json.loads(PROOF.read_text("utf-8"))
    required={
        "stage":"NF-DEV-04",
        "writer":model.WRITER,
        "reviewer":model.REVIEWER,
        "scope":"neurofactory_only",
        "review_verdict":"REVIEW_OK",
        "github_branch":"neurofactory-public-lab-20261012",
        "file":"bridge/neurofactory/development/recovery_decision.py",
        "publication_status":"verified_candidate"
    }
    for key,value in required.items():
        if proof.get(key)!=value:
            raise ValueError("Incorrect real two-model recovery proof: "+key)
    digest=hashlib.sha256(canonical).hexdigest()
    if digest!=proof.get("sha256"):
        raise ValueError("Published recovery source changed after independent review")
    tests=model.acceptance(canonical.decode("utf-8"))
    if proof.get("tests_passed")!=tests:
        raise ValueError("Recovery behavior no longer matches accepted source")
    print("NEUROFACTORY_RECOVERY_SOURCE_SHA256",digest)
    print("NEUROFACTORY_RECOVERY_INDEPENDENT_MODELS",model.WRITER,model.REVIEWER)
    print("NEUROFACTORY_RECOVERY_BEHAVIOR_CHECKS",tests)
    return tests
if __name__=="__main__":
    verify()
