import unittest
from audit_stable_heads import frozen_scan, read_head
from audit_lane_heads import API, BOOTSTRAP, LANES, LaneAuditError
from check_lanes import load_policy

POLICY = load_policy()
BRANCHES = {row["id"]: row["branch"] for row in POLICY["chat_lanes"]}
SHA = {lane: format(i + 100, "040x") for i, lane in enumerate(LANES)}
PATHS = {
 "core": "bridge/neurofactory/development/core_owned/one.py",
 "handoff": "bridge/neurofactory/development/model_handoff_owned/one.py",
 "review": "bridge/neurofactory/development/review_owned/one.py",
 "providers": "bridge/neurofactory/providers/one.py",
 "coordinator": "bridge/neurofactory/coordination/one.json",
}

class Fake:
 def __init__(self, move=None, wrong=False):
  self.move=move
  self.wrong=wrong
  self.count={x:0 for x in LANES}
  self.calls=[]
 def __call__(self, url):
  self.calls.append(url)
  if "/branches/" in url:
   branch=url.split("/branches/")[1]
   lane=next(x for x in LANES if BRANCHES[x]==branch)
   self.count[lane]+=1
   new=self.move==lane and self.count[lane]==2
   return {"commit":{"sha":("f"*40 if new else SHA[lane])}}
  if "/compare/" in url:
   sha=url.split("...")[1]
   lane=next(x for x in LANES if SHA[x]==sha)
   return {"head_commit":{"sha":("a"*40 if self.wrong else sha)},
    "status":"ahead","ahead_by":1,"behind_by":0,"total_commits":1,
    "files":[{"filename":PATHS[lane],"status":"added"}]}
  raise AssertionError(url)

class FrozenAuditTests(unittest.TestCase):
 def test_immutable_sha_and_no_mutation(self):
  f=Fake()
  result=frozen_scan(POLICY,f)
  self.assertTrue(result["heads_verified_unchanged"])
  self.assertEqual(len(result["lanes"]),5)
  self.assertEqual(len(f.calls),15)
  self.assertFalse(any("/pulls/" in x or "/contents/" in x for x in f.calls))
 def test_race_in_any_owner_denied(self):
  for lane in LANES:
   with self.subTest(lane=lane):
    with self.assertRaisesRegex(LaneAuditError,"Concurrent branch"):
     frozen_scan(POLICY,Fake(move=lane))
 def test_wrong_compared_commit_denied(self):
  with self.assertRaisesRegex(LaneAuditError,"expected exact head"):
   frozen_scan(POLICY,Fake(wrong=True))
 def test_bad_sha_denied(self):
  with self.assertRaises(LaneAuditError):
   read_head(BRANCHES["core"],lambda _:{"commit":{"sha":"short"}})

if __name__=="__main__":
 unittest.main(verbosity=2)
