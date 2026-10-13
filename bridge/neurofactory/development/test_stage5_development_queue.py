"""3 separate Neurofactory development tasks, real crash, recovery and sealed snapshots.

No model call, billing, GitHub publication or ChatGPT sending is performed.
Only trusted GitHub commit verifiers may complete a production task.
"""
import copy
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import stage5_development_queue as stages
import stage4_queue as stage4

HERE = pathlib.Path(__file__).resolve().parent
PLAN = json.loads((HERE / "roadmap.json").read_text("utf-8"))
TASKS = [
    {"id":"NF-DEV-05-Q001","target":"bridge/neurofactory/development/stage5_development_queue.py",
     "objective":"Implement serial persistent development task selection only for Neurofactory"},
    {"id":"NF-DEV-05-Q002","target":"bridge/neurofactory/development/stage5_git_receipts.py",
     "objective":"Verify approved GitHub commit identity against exact development file content"},
    {"id":"NF-DEV-05-Q003","target":"bridge/neurofactory/development/stage5_usage_ledger.py",
     "objective":"Append verified execution usage without inventing billable monetary expenses"},
]
SOURCE_HASHES = ["a"*64,"b"*64,"c"*64]
ROLE_COMMITS = [
    ["1"*40,"2"*40,"3"*40],
    ["4"*40,"5"*40,"6"*40],
    ["7"*40,"8"*40,"9"*40]
]


def verified_remote(repo, branch, path, sha, digest):
    assert repo == stages.REPO and branch == stages.BRANCH
    assert path.startswith(stages.SAFE)
    return len(sha)==40 and len(digest)==64


class Stage5DevelopmentQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-stage5-development-")
        self.addCleanup(self.tmp.cleanup)
        self.queue=stages.DevelopmentQueue(self.tmp.name,copy.deepcopy(PLAN),copy.deepcopy(TASKS))
        self.queue.prepare()

    def finish_job(self,i):
        item=TASKS[i]["id"]
        digest=SOURCE_HASHES[i]
        for role,commit in zip(stage4.STAGES,ROLE_COMMITS[i]):
            self.queue.claim(item,role,100+i*100,10)
            self.queue.before_effect(item,role,**(
                {"source_sha256":digest} if role=="writer" else
                {"source_sha256":digest,"verdict":"REVIEW_OK"} if role=="reviewer" else {}))
            self.queue.acknowledge(item,role,commit,verify_remote=verified_remote)

    def test_three_tasks_in_order_and_unique_agents(self):
        self.assertEqual(self.queue.next_job()["id"],TASKS[0]["id"])
        for i in range(3):
            self.finish_job(i)
            expected=None if i==2 else TASKS[i+1]["id"]
            self.assertEqual(None if self.queue.next_job() is None else self.queue.next_job()["id"],expected)
        self.assertIsNone(self.queue.next_job())
        for task in TASKS:
            self.assertEqual(self.queue.snapshot()[task["id"]]["writer"]["actor"],"qwen2.5-coder:7b")
            self.assertEqual(self.queue.snapshot()[task["id"]]["reviewer"]["actor"],"qwen3:4b")

    def test_cannot_skip_second_task_or_claim_second_writer_early(self):
        with self.assertRaises(stages.DevelopmentQueueError):
            self.queue.claim(TASKS[1]["id"],"writer",100)
        with self.assertRaises(stage4.Stage4Error):
            self.queue.claim(TASKS[0]["id"],"reviewer",100)

    def test_writer_receipt_must_be_independently_verified(self):
        name=TASKS[0]["id"]
        self.queue.claim(name,"writer",100)
        self.queue.before_effect(name,"writer",source_sha256=SOURCE_HASHES[0])
        with self.assertRaises(stages.DevelopmentQueueError):
            self.queue.acknowledge(name,"writer",ROLE_COMMITS[0][0],verify_remote=None)
        with self.assertRaises(stages.DevelopmentQueueError):
            self.queue.acknowledge(name,"writer",ROLE_COMMITS[0][0],verify_remote=lambda *a:False)
        self.assertEqual(self.queue.snapshot()[name]["writer"]["state"],"publishing")
        self.queue.acknowledge(name,"writer",ROLE_COMMITS[0][0],verify_remote=verified_remote)

    def test_duplicate_job_manifest_rejected(self):
        for changes in (
            [TASKS[0],TASKS[0]],
            [TASKS[0],{**TASKS[1],"target":TASKS[0]["target"]}],
            [TASKS[0],{**TASKS[1],"target":"bridge/other_project/service.py"}],
            [TASKS[0],{**TASKS[1],"id":"../../elsewhere"}],
        ):
            with self.assertRaises(stages.DevelopmentQueueError):
                stages.DevelopmentQueue(self.tmp.name,PLAN,changes)

    def test_manifest_mutation_after_setup_refused(self):
        changed=copy.deepcopy(TASKS)
        changed[0]["objective"]="New approved scope with a completely different goal"
        other=stages.DevelopmentQueue(self.tmp.name,PLAN,changed)
        with self.assertRaises(stages.DevelopmentQueueError):other.prepare()

    def test_publisher_never_replays_even_after_many_restarts(self):
        self.finish_job(0)
        snapshot=self.queue.sealed_snapshot()
        with tempfile.TemporaryDirectory(prefix="nf-stage5-restore-") as directory:
            recreated=stages.DevelopmentQueue(directory,PLAN,TASKS)
            self.assertTrue(recreated.restore_snapshot(snapshot))
            self.assertEqual(recreated.next_job()["id"],TASKS[1]["id"])
            with self.assertRaises(stages.DevelopmentQueueError):
                recreated.claim(TASKS[0]["id"],"writer",1000)
            self.assertEqual(recreated.sealed_snapshot()["sha256"],snapshot["sha256"])

    def test_three_tasks_persist_across_new_python_process(self):
        self.finish_job(0)
        script="""
import json,sys
from pathlib import Path
from stage5_development_queue import DevelopmentQueue
base=Path(sys.argv[2])
plan=json.loads((base/'roadmap.json').read_text('utf-8'))
jobs=json.loads(sys.argv[3])
q=DevelopmentQueue(sys.argv[1],plan,jobs)
assert q.prepare()[jobs[0]['id']]['publisher']['state']=='verified_done'
assert q.next_job()['id']==jobs[1]['id']
print('NF_STAGE5_NEW_PROCESS_RESTORED_SECOND_TASK')
"""
        cp=subprocess.run([sys.executable,"-B","-c",script,self.tmp.name,str(HERE),
                           json.dumps(TASKS)],env=os.environ.copy(),capture_output=True,text=True,timeout=20)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertIn("NF_STAGE5_NEW_PROCESS_RESTORED_SECOND_TASK",cp.stdout)

    def test_owned_writer_child_crash_recovered_only_once(self):
        name=TASKS[0]["id"]
        script="""
import json,os,sys
from pathlib import Path
from stage5_development_queue import DevelopmentQueue
root=Path(sys.argv[2]);plan=json.loads((root/'roadmap.json').read_text('utf-8'))
q=DevelopmentQueue(sys.argv[1],plan,json.loads(sys.argv[3]))
q.claim('NF-DEV-05-Q001','writer',100,10)
os._exit(73)
"""
        cp=subprocess.run([sys.executable,"-B","-c",script,self.tmp.name,str(HERE),
                           json.dumps(TASKS)],env=os.environ.copy(),timeout=20)
        self.assertEqual(cp.returncode,73)
        self.assertEqual(self.queue.snapshot()[name]["writer"]["attempts"],1)
        self.queue.recover(120)
        self.assertEqual(self.queue.snapshot()[name]["writer"]["state"],"queued")
        self.assertEqual(self.queue.claim(name,"writer",121,10)["attempts"],2)

    def test_writer_uncertain_publication_refuses_repeat(self):
        name=TASKS[0]["id"]
        self.queue.claim(name,"writer",100,10)
        self.queue.before_effect(name,"writer",source_sha256=SOURCE_HASHES[0])
        self.queue.recover(120)
        with self.assertRaises(stage4.Stage4Error):
            self.queue.claim(name,"writer",121)
        with self.assertRaises(stages.DevelopmentQueueError):
            self.queue.claim(TASKS[1]["id"],"writer",121)
        self.assertEqual(self.queue.snapshot()[name]["writer"]["state"],"needs_receipt_check")

    def test_corrupt_sealed_snapshot_refused(self):
        snapshot=self.queue.sealed_snapshot()
        snapshot["body"]["files"][self.queue.manifest.name]="{}"
        with tempfile.TemporaryDirectory() as directory:
            target=stages.DevelopmentQueue(directory,PLAN,TASKS)
            with self.assertRaises(stages.DevelopmentQueueError):
                target.restore_snapshot(snapshot)

    def test_sealed_snapshot_cannot_overwrite_existing(self):
        snapshot=self.queue.sealed_snapshot()
        with self.assertRaises(stages.DevelopmentQueueError):
            self.queue.restore_snapshot(snapshot)

    def test_chat_delivery_and_paid_services_remain_blocked(self):
        unsafe=copy.deepcopy(PLAN);unsafe["chat_delivery_paused"]=False
        with self.assertRaises(Exception):
            stages.DevelopmentQueue(self.tmp.name,unsafe,TASKS)
        unsafe=copy.deepcopy(PLAN);unsafe["free_only"]=False
        with self.assertRaises(Exception):
            stages.DevelopmentQueue(self.tmp.name,unsafe,TASKS)


if __name__=="__main__":
    unittest.main(verbosity=2)
