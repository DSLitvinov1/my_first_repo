"""ChatGPT / private GitHub issue relay: owner verification, replay, consent."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from chatgpt_bridge_one import (BRIDGE_SCHEMA, ChatGPTBridgeOne,
                                GithubIssueTransport, verify_command)
from work_core import WorkDenied, WorkStore

NOW=1794710000
OWNER="DSLitvinov1"
REPO="DSLitvinov1/lesson3.1"


def owner_issue(project, operation="status", params=None, ident=501, request_id=None,
                issued_at=NOW):
    return {"id":ident,"number":ident,"state":"open","title":"[ONE-COMMAND] Task",
            "user":{"login":OWNER},
            "body":json.dumps({"schema":BRIDGE_SCHEMA,"request_id":request_id or
                                ("%032x"%ident),"issued_at":issued_at,
                                "project_id":project,"operation":operation,
                                "params":params if params is not None else {}},
                               ensure_ascii=False)}


class FakeVault:
    def __init__(self):self.data={}
    def ready(self):return True
    def put(self,provider,key,data):self.data[(provider,key)]=dict(data)
    def get(self,provider,key):return self.data.get((provider,key))
    def delete(self,provider,key):self.data.pop((provider,key),None)


class FakeIssues:
    def __init__(self,issues=(),private=True):
        self.list=list(issues);self.messages=[];self.private=private
        self.fail_comment=False
    def issues(self):return list(self.list)
    def comment(self,number,receipt):
        if self.fail_comment:raise WorkDenied("SIMULATED_REPLY_LOST")
        self.messages.append((number,dict(receipt)))
    def verify_private_repo(self):
        if not self.private:raise WorkDenied("CHATGPT_PRIVATE_REPOSITORY_REQUIRED")
        return True


class FakeAgent:
    def __init__(self):self.calls=[]
    def create_audit(self,project,urls):
        self.calls.append(("prepare",project,urls))
        return {"id":"f"*32}
    def execute(self,run,project):
        self.calls.append(("execute",run,project))
        return {"state":"DONE","steps":[{"state":"DONE"}]}


class FakeDesktop:
    def __init__(self):self.calls=[];self.session={"id":"owner-session","app":"notepad.exe"}
    def status(self,project):return {"session":self.session}
    def action(self,project,session,op,**data):
        self.calls.append((project,session,op))
        return {"result":{"controls":[{"label":"Открыть"}],"truncated":False}}


class FakeScripts:
    def __init__(self):self.approved=[];self.prepared=[]
    def prepare(self,project,session,script):
        self.prepared.append((project,session,script))
        return {"id":"a"*32,"step_count":2}
    def start(self,project,session,plan_id,script):
        self.approved.append((project,session,plan_id,script))
        return {"state":"RUNNING"}
    def get(self,project,ident):
        return {"state":"DONE","completed":2}


class ChatGPTBridgeTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("ChatGPT owner test","empty")["id"]
        self.issues=FakeIssues()
        self.agent=FakeAgent()
        self.desktop=FakeDesktop()
        self.scripts=FakeScripts()
        self.bridge=ChatGPTBridgeOne(self.store,self.agent,self.desktop,
                                     self.scripts,FakeVault(),
                                     transport=self.issues,now=lambda:NOW)
        self.bridge.owner=OWNER;self.bridge.repo=REPO

    def test_only_trusted_private_owner_json_and_fresh_command(self):
        cmd=owner_issue(self.project)
        self.assertEqual(verify_command(cmd,OWNER,NOW)["operation"],"status")
        for item in (
            {**cmd,"user":{"login":"other-user"}},
            {**cmd,"state":"closed"},
            {**cmd,"title":"not a ONE command"},
            {**cmd,"pull_request":{"url":"pr"}},
            {**cmd,"body":'{"schema":"a","schema":"b"}'},
            owner_issue(self.project,issued_at=NOW-3601),
            owner_issue(self.project,operation="shell",params={"cmd":"del *"}),
            owner_issue(self.project,operation="desktop.prepare",
                        params={"script":"Нажми Ctrl+Alt+Del"}),
        ):
            with self.subTest(item=str(item)[:80]),self.assertRaises(WorkDenied):
                verify_command(item,OWNER,NOW)
        with self.assertRaises(WorkDenied):
            GithubIssueTransport("a"*25,"other/repo",OWNER)
        with self.assertRaises(WorkDenied):
            GithubIssueTransport("short",REPO,OWNER)

    def test_status_issue_returns_receipt_once_after_durable_checkpoint(self):
        item=owner_issue(self.project)
        self.issues.list=[item]
        reply=self.bridge.poll_once()
        self.assertEqual(reply["state"],"DONE")
        self.assertEqual(reply["operation"],"status")
        self.assertEqual(len(self.issues.messages),1)
        self.assertEqual(self.bridge.poll_once(),None)
        self.assertEqual(len(self.issues.messages),1)
        with self.store.db() as conn:
            row=conn.execute("SELECT state FROM one_chatgpt_commands WHERE issue_id=501").fetchone()
        self.assertEqual(row["state"],"DONE")

    def test_readonly_audit_and_window_observation_do_not_write(self):
        self.issues.list=[owner_issue(self.project,"site.audit",
                                     {"urls":["https://example.org/"]})]
        audit=self.bridge.poll_once()
        self.assertEqual(audit["pages"],1)
        self.assertEqual(len(self.agent.calls),2)
        self.issues.list=[owner_issue(self.project,"desktop.observe",ident=503)]
        seen=self.bridge.poll_once()
        self.assertEqual(seen["visible_controls"],1)
        self.assertEqual(self.desktop.calls[0][2],"observe")
        self.assertNotIn("Открыть",str(seen))
        self.assertEqual(self.scripts.approved,[])

    def test_remote_desktop_script_requires_local_confirm(self):
        script="Посмотри окно\nНайди элемент «Отчёты»"
        item=owner_issue(self.project,"desktop.prepare",{"script":script},ident=508)
        self.issues.list=[item]
        staged=self.bridge.poll_once()
        self.assertEqual(staged["state"],"NEEDS_LOCAL_OWNER_APPROVAL")
        self.assertEqual(self.scripts.approved,[])
        pending=self.bridge.pending_approvals()
        self.assertEqual(pending[0]["script"],script)
        wrong=self.store.create_project("Other","empty")["id"]
        with self.assertRaises(WorkDenied):
            self.bridge.approve(wrong,508)
        result=self.bridge.approve(self.project,508)
        self.assertEqual(result["state"],"RUNNING")
        self.assertEqual(len(self.scripts.approved),1)
        self.assertEqual(self.bridge.pending_approvals(),[])
        self.bridge.poll_once()
        self.assertEqual(self.issues.messages[-1][1]["state"],"DONE")
        self.assertTrue(self.issues.messages[-1][1]["owner_approved"])
        with self.assertRaises(WorkDenied):
            self.bridge.approve(self.project,508)

    def test_comment_network_failure_does_not_reexecute_job(self):
        self.issues.list=[owner_issue(self.project,"site.audit",
                                     {"urls":["https://example.org/"]})]
        self.issues.fail_comment=True
        self.bridge.poll_once()
        self.bridge.poll_once()
        self.assertEqual(len(self.agent.calls),2)
        self.assertEqual(self.bridge.last_error,"CHATGPT_RECEIPT_DELIVERY_UNKNOWN_NO_RETRY")

    def test_untrusted_and_cross_project_inputs_cannot_act(self):
        self.issues.list=[
            {**owner_issue(self.project,ident=600),"user":{"login":"untrusted"}},
            owner_issue("f"*32,"site.audit",{"urls":["https://example.org/"]},ident=601),
        ]
        reply=self.bridge.poll_once()
        self.assertEqual(reply["state"],"STOPPED")
        self.assertFalse(self.agent.calls)
        self.assertFalse(self.desktop.calls)
        with self.assertRaises(WorkDenied):
            self.bridge.approve(self.project,601)


if __name__=="__main__":
    unittest.main(verbosity=2)
