"""Deterministic preflight of the isolated real-model job and exact proof gates.

No model, network, credentials, GitHub publishing or ChatGPT sender.
"""
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import stage5_live_pair_lab as worker
import stage5_live_publish_lab as publisher
import stage5_live_restore_artifact as recovery

SOURCE_ONE="""def valid_task_ids(items):
    if not isinstance(items, list) or not items:
        return False
    if not all(isinstance(x,str) and len(x)==14 and x.startswith("NF-DEV-05-Q") and x[11:].isdigit() for x in items):
        return False
    return len(set(items)) == len(items)
"""
SOURCE_TWO="""def reconcile_receipt(state,published,hash_matches):
    if not isinstance(published,bool) or not isinstance(hash_matches,bool):
        return "block"
    if state == "verified_done":
        return "done" if published and hash_matches else "block"
    if state in ("publishing","needs_receipt_check"):
        if published is False:
            return "wait"
        return "verify" if hash_matches else "block"
    if state == "queued" and published is False:
        return "ready"
    return "block"
"""

class SequentialRealWorkflowPreflight(unittest.TestCase):
    def test_first_bounded_production_contract_accepts_unhashable_denial(self):
        proof=worker.check_source(SOURCE_ONE,"valid_task_ids")
        self.assertEqual(proof["behavior_cases"],14)

    def test_second_publication_reconciliation_contract(self):
        proof=worker.check_source(SOURCE_TWO,"reconcile_receipt")
        self.assertEqual(proof["behavior_cases"],13)

    def test_scope_denied_without_trusted_github_publisher(self):
        with mock.patch.dict(publisher.os.environ,{},clear=True):
            with self.assertRaises(ValueError):publisher.guard()

    def test_exact_writer_and_reviewer_proof_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=pathlib.Path(tmp)
            jobid,filename,fn,_=worker.JOBS[0]
            digest=hashlib.sha256(SOURCE_ONE.encode()).hexdigest()
            (d/filename).write_text(SOURCE_ONE,"utf-8")
            proof={"task_id":jobid,"target":publisher.PREFIX+filename,
                "writer":"qwen2.5-coder:7b","reviewer":"qwen3:4b",
                "source_sha256":digest,"tests":14,
                "independent_verdict":{"verdict":"REVIEW_OK","source_sha256":digest},
                "scope":"neurofactory_only","chat_delivery":"paused_by_user"}
            p=d/(filename+".proof.json")
            p.write_text(json.dumps(proof),"utf-8")
            raw,approval,identity=publisher.files_for(jobid,filename,d)
            self.assertEqual(identity,digest)
            self.assertEqual(raw,SOURCE_ONE.encode())
            proof["independent_verdict"]["verdict"]="REVIEW_BAD"
            p.write_text(json.dumps(proof),"utf-8")
            with self.assertRaises(ValueError):
                publisher.files_for(jobid,filename,d)

    def test_readonly_restore_skips_already_published_task(self):
        first=worker.JOBS[0]
        digest=hashlib.sha256(SOURCE_ONE.encode()).hexdigest()
        info={"task_id":first[0],"target":publisher.PREFIX+first[1],
              "source_sha256":digest,"writer":"qwen2.5-coder:7b","reviewer":"qwen3:4b",
              "independent_verdict":{"verdict":"REVIEW_OK","source_sha256":digest}}
        state={"scope":"neurofactory_only","chat_delivery":"paused_by_user",
               "branch":recovery.BRANCH,"tasks":{
                  worker.JOBS[0][0]:{"state":"verified_done","target":publisher.PREFIX+first[1],
                    "source_sha256":digest,"commit_sha":"a"*40},
                  worker.JOBS[1][0]:{"state":"queued","target":publisher.PREFIX+worker.JOBS[1][1]}}}
        files={
           recovery.STATE:json.dumps(state).encode(),
           publisher.PREFIX+first[1]:SOURCE_ONE.encode(),
           publisher.PREFIX+"stage5-e2e-evidence/"+first[0]+".json":json.dumps(info).encode()
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(recovery,"fetch",side_effect=lambda path:files.get(path)):
                self.assertTrue(recovery.restore(first[0],tmp))
                self.assertEqual((pathlib.Path(tmp)/first[1]).read_text("utf-8"),SOURCE_ONE)

    def test_second_model_task_restores_without_reexecution(self):
        second=worker.JOBS[1]
        digest=hashlib.sha256(SOURCE_TWO.encode()).hexdigest()
        info={"task_id":second[0],"target":publisher.PREFIX+second[1],
              "source_sha256":digest,"writer":"qwen2.5-coder:7b",
              "reviewer":"qwen3:4b",
              "independent_verdict":{"verdict":"REVIEW_OK","source_sha256":digest}}
        state={"scope":"neurofactory_only","chat_delivery":"paused_by_user",
               "branch":recovery.BRANCH,"tasks":{
                  worker.JOBS[0][0]:{"state":"verified_done",
                     "target":publisher.PREFIX+worker.JOBS[0][1]},
                  worker.JOBS[1][0]:{"state":"verified_done",
                     "target":publisher.PREFIX+second[1],
                     "source_sha256":digest,"commit_sha":"b"*40}}}
        remote={
          recovery.STATE:json.dumps(state).encode(),
          publisher.PREFIX+second[1]:SOURCE_TWO.encode(),
          publisher.PREFIX+"stage5-e2e-evidence/"+second[0]+".json":json.dumps(info).encode()
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(recovery,"fetch",side_effect=lambda path:remote.get(path)):
                self.assertTrue(recovery.restore(second[0],tmp))
            self.assertEqual((pathlib.Path(tmp)/second[1]).read_text("utf-8"),SOURCE_TWO)

    def test_queued_task_never_reissued_when_remote_source_exists(self):
        job=worker.JOBS[0]
        state={"scope":"neurofactory_only","chat_delivery":"paused_by_user",
               "branch":recovery.BRANCH,"tasks":{
                  worker.JOBS[0][0]:{"state":"queued","target":publisher.PREFIX+worker.JOBS[0][1]},
                  worker.JOBS[1][0]:{"state":"queued","target":publisher.PREFIX+worker.JOBS[1][1]}}}
        with tempfile.TemporaryDirectory() as tmp:
            def fake(path):
                if path==recovery.STATE:return json.dumps(state).encode()
                if path==publisher.PREFIX+job[1]:return SOURCE_ONE.encode()
                return None
            with mock.patch.object(recovery,"fetch",side_effect=fake):
                with self.assertRaises(ValueError):recovery.restore(job[0],tmp)

    def test_only_one_exact_job_can_be_issued_or_published(self):
        self.assertEqual({j[0] for j in worker.JOBS},
                         {j[0] for j in publisher.JOBS})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                worker.run(tmp,"NF-DEV-05-Q999")
            with self.assertRaises(ValueError):
                publisher.publish(tmp,"NF-DEV-05-Q999")

if __name__=="__main__":
    unittest.main()
