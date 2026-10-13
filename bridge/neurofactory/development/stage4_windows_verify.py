"""Windows read-only acceptance: real AI cycle, two distinct writes and no replay.

First source publication and independently approved security correction are separate
commits. A repeated identical result would appear as an additional commit and fails.
"""
import hashlib,json,pathlib,sys,urllib.request
import stage4_live_worker as checks

REPO="DSLitvinov1/my_first_repo"
STAGING="neurofactory-stage4-live-integration-20261013"
PROD="neurofactory-public-lab-20261012"
PREFIX="bridge/neurofactory/development/"
SOURCE=PREFIX+"stage4_receipt_rules.py"
PROOF=PREFIX+"stage4-live-proof.json"
HARDEN_PROOF=PREFIX+"stage4-receipt-hardening-verification.json"
CANDIDATE=PREFIX+"stage4-live-candidate.py"
REVIEW=PREFIX+"stage4-live-reviewed.json"
STATE=PREFIX+"stage4-live-state.json"
ORIGINAL_COMMIT="4156913b3572bc17b7579ca4cbcc0059c53928cf"

def github(path):
    if not path.startswith("/repos/"+REPO+"/"):raise ValueError("Wrong project")
    req=urllib.request.Request("https://api.github.com"+path,
      headers={"Accept":"application/vnd.github+json","User-Agent":"NeurofactoryStage4WindowsEvidence"})
    with urllib.request.urlopen(req,timeout=25) as r:return json.load(r)
def read(base,name):return (pathlib.Path(base)/name).read_bytes()
def audit(prod,staging,original):
    candidate=read(staging,CANDIDATE)
    first=read(original,SOURCE)
    hardened=read(prod,SOURCE)
    if candidate!=first:raise ValueError("First real AI source differs from initial GitHub publication")
    if hardened==first:raise ValueError("Missing genuine security correction")
    initial=json.loads(read(prod,PROOF))
    correction=json.loads(read(prod,HARDEN_PROOF))
    independent=json.loads(read(staging,REVIEW))
    state=json.loads(read(staging,STATE))
    if (state.get("scope")!="neurofactory_only" or state.get("chat_delivery")!="paused_by_user"
       or state.get("meta",{}).get("crash_injected") is not True):
        raise ValueError("Remote journal lacks crash proof or user safeguards")
    tasks={name:json.loads(state["files"][name])["data"] for name in ("writer","reviewer","publisher")}
    if any(t["state"]!="verified_done" for t in tasks.values()):
        raise ValueError("Durable role not verified")
    if [tasks[x]["attempts"] for x in ("writer","reviewer","publisher")]!=[2,1,1]:
        raise ValueError("Replay or crash recovery attempt counts incorrect")
    original_digest=hashlib.sha256(first).hexdigest()
    new_digest,passed=checks.check(hardened.decode("utf-8"))
    if passed!=15:raise ValueError("Behavior regression")
    if (initial.get("source_sha256")!=original_digest
        or independent.get("source_sha256")!=original_digest
        or correction.get("previous_source_sha256")!=original_digest
        or correction.get("source_sha256")!=new_digest
        or correction.get("reviewer",{}).get("verdict")!="REVIEW_OK"):
        raise ValueError("Broken two-agent source-to-review chain")
    for role in tasks:
        token=tasks[role].get("publication_sha","")
        if len(token)!=40 or any(c not in "0123456789abcdef" for c in token):
            raise ValueError("Missing exact remote commit evidence "+role)
    pcommit=tasks["publisher"]["publication_sha"]
    if pcommit!=ORIGINAL_COMMIT:raise ValueError("Original one-time production receipt changed")
    for branch,path,role in ((STAGING,CANDIDATE,"writer"),(STAGING,REVIEW,"reviewer")):
        commits=github("/repos/"+REPO+"/commits?sha="+branch+"&path="+path+"&per_page=5")
        if len(commits)!=1 or commits[0]["sha"]!=tasks[role]["publication_sha"]:
            raise ValueError("Staging agent result duplicated or mismatched: "+role)
    commits=github("/repos/"+REPO+"/commits?sha="+PROD+"&path="+SOURCE+"&per_page=5")
    if len(commits)!=2 or commits[1]["sha"]!=pcommit or commits[0]["sha"]==pcommit:
        raise ValueError("Original publication duplicated, or correction missing")
    for sha,allowed in ((pcommit,{SOURCE,PROOF}),(commits[0]["sha"],{SOURCE,HARDEN_PROOF})):
        diff=github("/repos/"+REPO+"/commits/"+sha)
        if {x["filename"] for x in diff.get("files",[])}!=allowed:
            raise ValueError("GitHub commit changed an unapproved component")
    import importlib.util
    file=pathlib.Path(prod)/SOURCE
    spec=importlib.util.spec_from_file_location("nf4_security_verified",file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    valid="b"*40
    for fake_repo,fake_path in (("attacker/other",SOURCE),(REPO,"../other_project"),("bad/bad","../bad")):
        forged={"repo":fake_repo,"path":fake_path,"sha":valid}
        if module.receipt_matches(forged,fake_repo,fake_path,valid) is not False:
            raise ValueError("Forged receipt unexpectedly accepted")
    print("NF4_WINDOWS_ACCEPTED_REAL_TWO_AGENT: saved attempts 2/1/1, owned worker and publisher crashes, "
          "one original GitHub source commit plus one DISTINCT independently reviewed security correction, "
          "no repeated publication, 15 behavior cases plus forged-identity attacks, no other project touched",
          flush=True)
if __name__=="__main__":
    if len(sys.argv)!=4:raise ValueError("Expected hardened production, staging, original publication")
    audit(*sys.argv[1:])
