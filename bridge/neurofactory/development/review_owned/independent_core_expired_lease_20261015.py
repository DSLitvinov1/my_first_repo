"""REVIEW-only single expired-at-boundary CORE one-file negative.
Exact tested CORE: 18becc1ad8c17c9259d0e7f646683d0568ce18d6
Synthetic local temp Git + sandbox only, no model or real project.
"""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from one_task_core import OneTaskCore, CoreSafetyError, EMPTY_SHA

TARGET="bridge/neurofactory/development/core_owned/review_expired_boundary.txt"
CONTENT="REVIEW_EXPIRED_LEASE = 1\n"

def git(repo,*args):
    return subprocess.check_output(["git","-C",str(repo),*args],text=True).strip()

with tempfile.TemporaryDirectory() as folder:
    temp=Path(folder)
    repo=temp/"source"
    repo.mkdir()
    git(repo,"init","-q")
    git(repo,"config","user.name","isolated-review")
    git(repo,"config","user.email","review@example.invalid")
    (repo/"README.md").write_text("synthetic fixture\n")
    git(repo,"add","README.md")
    git(repo,"commit","-qm","synthetic origin")
    sha=git(repo,"rev-parse","HEAD")
    q=OneTaskCore(temp/"workspace",repo)
    spec={
      "schema":"neurofactory.core.task.v1",
      "task_id":"NF-DEV-05-Q995","project_id":"review-only",
      "target":TARGET,
      "objective":"One synthetic expired lease test",
      "source_sha":sha,"source_sha256":EMPTY_SHA,
      "approval_commit":sha,"model":"qwen2.5-coder:1.5b",
      "reserved_units":1
    }
    q.enqueue(copy.deepcopy(spec),trusted_approval_check=lambda s:s==spec)
    holder=q.claim("review-worker",now=1000,lease_seconds=10)
    assert holder["lease_until"]==1010
    proposal={"schema":"neurofactory.core.proposal.v1",
              "target":TARGET,"content":CONTENT,
              "content_sha256":hashlib.sha256(CONTENT.encode()).hexdigest(),
              "mode":"OFFLINE_TEST"}
    try:
        receipt=q.apply_offline_test(spec["task_id"],holder["token"],proposal,now=1010)
    except CoreSafetyError:
        print("REVIEW_EXPIRED_AT_LEASE_DEADLINE=REJECTED")
    else:
        assert receipt["model_invoked"] is False
        assert (q.sandbox/TARGET).read_text()==CONTENT
        assert q.snapshot()["state"]=="CHECKPOINTED_TEST"
        print("REVIEW_EXPIRED_AT_LEASE_DEADLINE=WRITTEN_AND_CHECKPOINTED")
        print("REVIEW_EFFECT_AT_EXPIRY=VIOLATION_CONFIRMED")
    print("REVIEW_EXPECTED_INVARIANT=EFFECT_ALLOWED_ONLY_STRICTLY_BEFORE_LEASE_DEADLINE")
    print("REVIEW_REAL_QWEN=NOT_INVOKED")
    print("REVIEW_SCOPE=ONE_SYNTHETIC_OFFLINE_FILE")
