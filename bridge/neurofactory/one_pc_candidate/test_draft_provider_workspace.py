"""UI draft -> one-shot pinned local provider storage, simulated model ONLY in tests.

Never a proof of real Qwen weights, CORE authorization, or Windows service.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import socket
import tempfile
from http.server import HTTPServer
import http.client
from threading import Thread
import unittest

from local_workspace import WorkspaceStore, WorkspaceDenied,handler

MODEL="qwen3:0.6b"

class DurableDraftProposalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="nf-draft-provider-")
        self.root=Path(self.temp.name)
        self.store=WorkspaceStore(self.root/"state")
        project=self.store.create_project({"name":"Sample approved workspace","description":""})
        self.project_id=project["id"]
        self.task=self.store.create_task({"project_id":self.project_id,
                 "objective":"Prepare a harmless draft with a short example sentence.",
                 "model_preference":MODEL})

    def tearDown(self):
        self.temp.cleanup()

    def good_result(self):
        content="This is an untrusted text proposal. It never executes.\n"
        return {"status":"PROPOSED_UNVERIFIED","model":MODEL,
                "text":content,"content_sha256":sha256(content.encode()).hexdigest(),
                "response_sha256":"a"*64}

    def test_single_reservation_and_no_replay_even_after_restart(self):
        self.store.reserve_task_proposal(self.task["id"],MODEL)
        with self.assertRaises(WorkspaceDenied):
            self.store.reserve_task_proposal(self.task["id"],MODEL)
        again=WorkspaceStore(self.store.directory)
        with self.assertRaises(WorkspaceDenied):
            again.reserve_task_proposal(self.task["id"],MODEL)
        self.assertEqual(again.recover_unknown_proposals(),1)
        self.assertEqual(again.list_task_proposals()[0]["status"],"UNKNOWN")
        self.assertEqual(again.recover_unknown_proposals(),0)
        # Lost result is UNKNOWN, not a successful completion and not retried.
        self.assertEqual(self.task["state"],"DRAFT_PENDING_OWNER_AUTH")
        self.assertFalse(again.diag()["real_core_dispatch_enabled"])

    def test_persists_verified_hash_but_never_grants_host_rights(self):
        self.store.reserve_task_proposal(self.task["id"],MODEL)
        stored=self.store.finalize_task_proposal(self.task["id"],self.good_result())
        self.assertFalse(stored["core_enqueued"])
        self.assertFalse(stored["host_write_allowed"])
        self.assertFalse(stored["review_approved"])
        self.assertEqual(stored["status"],"PROPOSED_UNVERIFIED")
        db=WorkspaceStore(self.store.directory)
        self.assertEqual(db.list_task_proposals()[0]["text"],self.good_result()["text"])
        self.assertEqual(db.list_tasks()[0]["state"],"DRAFT_PENDING_OWNER_AUTH")
        with self.assertRaises(WorkspaceDenied):
            db.finalize_task_proposal(self.task["id"],self.good_result())
        with self.assertRaises(WorkspaceDenied):
            db.reserve_task_proposal(self.task["id"],MODEL)

    def test_forged_digest_model_and_unknown_project_denied(self):
        with self.assertRaises(WorkspaceDenied):
            self.store.reserve_task_proposal("f"*32,MODEL)
        with self.assertRaises(WorkspaceDenied):
            self.store.reserve_task_proposal(self.task["id"],"remote-paid")
        self.store.reserve_task_proposal(self.task["id"],MODEL)
        original=self.good_result()
        for bad in (
            {**original,"content_sha256":"0"*64},
            {**original,"response_sha256":"BAD"},
            {**original,"model":"qwen2.5-coder:1.5b"},
        ):
            with self.subTest(bad=bad),self.assertRaises(WorkspaceDenied):
                self.store.finalize_task_proposal(self.task["id"],bad)
        self.assertEqual(self.store.list_task_proposals()[0]["status"],"REQUESTED")

    def test_unknown_network_after_reserved_cannot_retry(self):
        self.store.reserve_task_proposal(self.task["id"],MODEL)
        s=self.store.finalize_task_proposal(self.task["id"],
            {"status":"UNKNOWN","model":MODEL,"error_code":"UNKNOWN_MODEL_RESULT"})
        self.assertEqual(s["status"],"UNKNOWN")
        self.assertIsNone(s["text"])
        with self.assertRaises(WorkspaceDenied):
            self.store.reserve_task_proposal(self.task["id"],MODEL)

    def test_local_http_requires_installed_provider_and_csrf(self):
        ui=Path(__file__).resolve().parent.parent/"control_ui"
        sock=socket.socket();sock.bind(("127.0.0.1",0));port=sock.getsockname()[1];sock.close()
        app=HTTPServer(("127.0.0.1",port),handler(self.store,ui,"test-token",port))
        thread=Thread(target=app.serve_forever,daemon=True);thread.start()
        def post(headers=None):
            c=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
            h={"Content-Type":"application/json",**(headers or {})}
            c.request("POST","/api/draft-propose",
                      body=json.dumps({"task_id":self.task["id"]}),headers=h)
            response=c.getresponse();status=response.status;response.read();c.close()
            return status
        try:
            self.assertEqual(post(),403)
            self.assertEqual(post({"X-NF-Local-Token":"test-token",
                "Origin":"https://attacker.invalid"}),403)
            self.assertEqual(post({"X-NF-Local-Token":"test-token"}),400)
            self.assertEqual(self.store.list_task_proposals(),[])
            c=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
            c.request("GET","/api/task-proposals")
            response=c.getresponse()
            data=json.loads(response.read());c.close()
            self.assertEqual(response.status,200)
            self.assertEqual(data["proposals"],[])
        finally:
            app.shutdown();app.server_close();thread.join(timeout=3)

    def test_old_database_migrates_to_v3_with_drafts(self):
        with self.store.connect() as db:
            db.execute("PRAGMA user_version=2")
        again=WorkspaceStore(self.store.directory)
        self.assertEqual(len(again.list_tasks()),1)
        with again.connect() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],3)

if __name__=="__main__":
    unittest.main()
