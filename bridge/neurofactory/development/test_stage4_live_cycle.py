"""Offline production-integration contracts, no real GitHub calls or models."""
import copy,hashlib,json,pathlib,tempfile,types,unittest
from unittest import mock
import stage4_live_cycle as live
import stage4_live_worker as agent

PLAN=json.loads((pathlib.Path(__file__).parent/"roadmap.json").read_text("utf-8"))
RULE="""def receipt_matches(record, repo, path, sha):
    if not isinstance(record, dict) or not isinstance(repo, str) or not isinstance(path, str) or not isinstance(sha, str):
        return False
    if repo != 'DSLitvinov1/my_first_repo' or path != 'bridge/neurofactory/development/stage4_receipt_rules.py':
        return False
    if len(sha) != 40 or not all(c in '0123456789abcdef' for c in sha):
        return False
    return record.get('repo') == repo and record.get('path') == path and record.get('sha') == sha
"""
class LiveContractTests(unittest.TestCase):
    def test_real_security_receipt_behavior(self):
        digest,n=agent.check(RULE)
        self.assertEqual(n,15);self.assertEqual(digest,hashlib.sha256(RULE.encode()).hexdigest())
    def test_source_rejects_import_and_file_access(self):
        with self.assertRaises(ValueError):
            agent.check("import os\n"+RULE)
        with self.assertRaises(ValueError):
            agent.check(RULE.replace("return False","return open('secret')",1))
    def test_source_rejects_wrong_public_function(self):
        with self.assertRaises(ValueError):
            agent.check(RULE.replace("def receipt_matches","def anything"))
    def test_api_cross_repo_disallowed_before_network(self):
        with self.assertRaises(ValueError):live.api("GET","https://api.github.com/repos/other/name")
    def test_remote_path_fails_outside_neurofactory(self):
        with self.assertRaises(ValueError):live.read_remote("bridge/other_project/secret","main")
    def test_agent_child_never_inherits_github_token(self):
        def fake_run(cmd,env,**kwargs):
            self.assertNotIn("GITHUB_TOKEN",env);self.assertNotIn("GH_TOKEN",env)
            return types.SimpleNamespace(returncode=0,stdout="ok",stderr="")
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(live.os.environ,{"GITHUB_TOKEN":"fake","GH_TOKEN":"fake"}):
                with mock.patch.object(live.subprocess,"run",side_effect=fake_run):
                    self.assertEqual(live.run_child("writer",pathlib.Path(d)/"candidate.py",pathlib.Path(d)/"review.json"),0)
    def test_approved_plan_does_not_unpause_chat(self):
        p=copy.deepcopy(PLAN);p["chat_delivery_paused"]=False
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Exception):live.queue.Stage4Queue(d,p)
    def test_create_remote_state_before_work_and_rehydrate(self):
        memory={}
        def fake_put(method,url,data=None):
            if method!="PUT":raise AssertionError(method)
            raw=__import__("base64").b64decode(data["content"])
            memory["saved"]=raw
            return {"content":{"sha":"b"*40}}
        def fake_read(path,branch):
            self.assertEqual(path,live.STATE_PATH)
            return None if "saved" not in memory else {"bytes":memory["saved"],"blob_sha":"b"*40}
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            with mock.patch.object(live,"api",side_effect=fake_put),mock.patch.object(live,"read_remote",side_effect=fake_read):
                store,state=live.restore_into(d1,copy.deepcopy(PLAN))
                self.assertTrue(memory["saved"])
                store.claim("writer",100,10)
                live.direct_checkpoint_sync(state,store)
                resumed,again=live.restore_into(d2,copy.deepcopy(PLAN))
                self.assertEqual(resumed._read("writer")["state"],"running")
                self.assertEqual(resumed._read("writer")["attempts"],1)
                self.assertEqual(again["sha"],"b"*40)
    def test_writer_uncertain_receipt_does_not_republish(self):
        with tempfile.TemporaryDirectory() as d:
            q=live.queue.Stage4Queue(d,copy.deepcopy(PLAN));q.prepare()
            q.claim("writer",100,10)
            q.before_external_effect("writer",source_sha256="f"*64)
            state={"sha":None,"meta":{}}
            with mock.patch.object(live,"read_remote",return_value=None),mock.patch.object(live,"direct_checkpoint_sync"):
                with self.assertRaisesRegex(ValueError,"no remote receipt"):
                    live.reconcile(q,state,"writer",live.CANDIDATE_PATH,live.STAGING,None)
            self.assertEqual(q._read("writer")["state"],"needs_receipt_check")
            with self.assertRaises(live.queue.Stage4Error):q.claim("writer",250,10)
    def test_reconcile_existing_candidate_only_once(self):
        raw=b"test content"
        with tempfile.TemporaryDirectory() as d:
            q=live.queue.Stage4Queue(d,copy.deepcopy(PLAN));q.prepare()
            q.claim("writer",100,10);q.before_external_effect("writer",source_sha256=hashlib.sha256(raw).hexdigest())
            state={"sha":None,"meta":{}}
            with mock.patch.object(live,"read_remote",return_value={"bytes":raw}),mock.patch.object(live,"direct_checkpoint_sync"):
                with mock.patch.object(live,"confirm",return_value="b"*40):
                    self.assertTrue(live.reconcile(q,state,"writer",live.CANDIDATE_PATH,live.STAGING,raw))
            self.assertEqual(q._read("writer")["state"],"verified_done")
            self.assertEqual(q._read("writer")["publication_sha"],"b"*40)
    def test_publication_refuses_review_digest_mismatch(self):
        wrong=json.dumps({"verdict":"REVIEW_OK","source_sha256":"f"*64}).encode()
        with self.assertRaisesRegex(ValueError,"review does not match"):
            live.prod_publish(RULE.encode(),wrong)
    def test_publication_preexisting_file_never_written_twice(self):
        digest,_=agent.check(RULE)
        approved=json.dumps({"verdict":"REVIEW_OK","source_sha256":digest}).encode()
        with mock.patch.object(live,"read_remote",return_value={"bytes":RULE.encode()}):
            with self.assertRaisesRegex(ValueError,"already exists"):
                live.prod_publish(RULE.encode(),approved)
    def test_replay_complete_refused(self):
        with tempfile.TemporaryDirectory() as d:
            q=live.queue.Stage4Queue(d,copy.deepcopy(PLAN));q.prepare()
            q.claim("writer",100,10);q.before_external_effect("writer",source_sha256="f"*64)
            q.acknowledge("writer","b"*40,remote_verified=True)
            with self.assertRaises(live.queue.Stage4Error):q.claim("writer",1000,10)
if __name__=="__main__":unittest.main()
