"""CORE author-side v2 sandbox adapter tests. No HOST/DB/filesystem writes."""
import copy
import hashlib
import json
import os
import unittest
from unittest.mock import patch

from four_party_sandbox_client import (
    CoreFourPartySandboxClient, CoreFourPartyDenied, CoreFourPartyUnknown,
)

NOW=1800000000
def h(b):
    return hashlib.sha256(b).hexdigest()
def hs(s):
    return h(s.encode())

class Connect:
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def execute(self,*args): pass

class FakeCore:
    def __init__(self,scope):
        self.row=dict(
            state="CLAIMED", owner=scope["worker_id"],
            lease_until=NOW+90, token=hs("test-only-token"),
            spec=dict(
                task_id=scope["task_id"],
                project_id=scope["project_id"],
                source_sha=scope["source_sha40"],
                source_sha256=scope["source_file_sha256"],
                target=scope["target"],
                schema="neurofactory.core.task.v1",
            ),
        )
    def _connect(self): return Connect()
    def _row(self,c): return self.row

class CoreFourPartyAdapterTests(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,{
            "NF_CORE_OFFLINE_RECEIVER_TEST_ONLY":"1",
            "NF_ATOMIC_TEST_ONLY":"1",
        })
        self.env.start();self.addCleanup(self.env.stop)
        self.content=b"content"
        self.scope=dict(
            owner_id="owner-101",
            repository="DSLitvinov1/my_first_repo",
            github_user_id="151650108", repository_id="723328237",
            project_id="nf-sandbox", task_id="NF-DEV-05-Q999",
            operation_id="op-unique-12", worker_id="worker-01",
            source_sha40="a"*40, source_file_sha256=hs("source"),
            target="bridge/neurofactory/development/core_owned/one_result.txt",
            content_sha256=h(self.content), policy_sha256=hs("policy"),
            lease_epoch=7, fencing_token_sha256=hs("fence"),
            idempotency_key=hs("idempotency"), challenge_sha256=hs("nonce"),
        )
        self.digest=h(json.dumps(self.scope,sort_keys=True,separators=(",",":"),
            ensure_ascii=True,allow_nan=False).encode("ascii"))
        self.docs={role:dict(body=dict(
                    schema="neurofactory.attested."+role+".v1",
                    scope_sha256=self.digest),signature_base64="A"*88)
                   for role in ("operator","owner","host","witness")}
        self.core=FakeCore(self.scope)
        self.client=CoreFourPartySandboxClient(self.core)
        self.proposal=dict(schema="neurofactory.core.proposal.v1",
            target=self.scope["target"],content="content",
            content_sha256=h(self.content),mode="OFFLINE_TEST")
        self.calls=0

    def host(self,**kwargs):
        self.calls+=1
        self.assertEqual(kwargs["content"],self.content)
        self.assertIs(kwargs["expected_effect"],self.scope)
        return dict(
            status="SANDBOX_FILE_AND_SQL_COMPLETED_TEST_ONLY",
            operation_id=self.scope["operation_id"],
            content_sha256=self.scope["content_sha256"],
            live_execution_allowed=False,release_approved=False,
            automatic_retry_allowed=False,real_external_witness_attested=False,
        )

    def send(self,client=None,proposal=None,scope=None,docs=None,**kw):
        s=self.scope if scope is None else scope
        p=self.proposal if proposal is None else proposal
        d=self.docs if docs is None else docs
        return (client or self.client).submit_once(
            task_id=s["task_id"],worker_id=s["worker_id"],
            core_token=kw.get("core_token","test-only-token"),
            proposal=p,expected_effect=s,
            signed_operator_acl=d["operator"],
            signed_owner_grant=d["owner"],
            signed_host_lease=d["host"],
            signed_external_witness=d["witness"],
            now_unix=NOW,
            host_submit=kw.get("host_submit",self.host),
        )

    def test_one_sandbox_dispatch_receipt_never_grants_live(self):
        r=self.send()
        self.assertEqual(r["status"],"CORE_HOST_FOUR_PARTY_SANDBOX_COMPLETED_TEST_ONLY")
        self.assertEqual(self.calls,1)
        self.assertFalse(r["core_wrote_local_file"])
        for x in ("live_execution_allowed","automatic_retry_allowed","independent_review_approved"):
            self.assertIs(r[x],False)

    def test_repeat_on_same_object_is_never_dispatched(self):
        self.send()
        with self.assertRaises(CoreFourPartyUnknown):self.send()
        self.assertEqual(self.calls,1)

    def test_lost_host_response_blocks_retry(self):
        def timeout(**kw):
            self.calls+=1
            raise TimeoutError("reply lost after file write")
        with self.assertRaises(CoreFourPartyUnknown):self.send(host_submit=timeout)
        with self.assertRaises(CoreFourPartyUnknown):self.send()
        self.assertEqual(self.calls,1)

    def test_false_host_completed_response_denied_as_unknown(self):
        def false_receipt(**kw):
            return dict(self.host(**kw),live_execution_allowed=True)
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(host_submit=false_receipt)
        with self.assertRaises(CoreFourPartyUnknown):self.send()
        self.assertEqual(self.calls,1)

    def test_missing_current_local_claim(self):
        for field,value in (("state","BLOCKED"),("lease_until",NOW-1),
                            ("owner","attacker"),("token",hs("foreign"))):
            with self.subTest(field=field):
                c=FakeCore(self.scope);c.row[field]=value
                with self.assertRaises(CoreFourPartyDenied):
                    self.send(client=CoreFourPartySandboxClient(c))
        self.assertEqual(self.calls,0)

    def test_invalid_token(self):
        with self.assertRaises(CoreFourPartyDenied):
            self.send(core_token="bad-token")
        self.assertEqual(self.calls,0)

    def test_foreign_repo_project_source_or_target_no_dispatch(self):
        for key,value in (
            ("project_id","other-project"),
            ("source_sha40","b"*40),
            ("source_file_sha256","b"*64),
            ("target","bridge/neurofactory/development/core_owned/foreign.txt"),
        ):
            with self.subTest(key=key):
                s=dict(self.scope);s[key]=value
                with self.assertRaises(CoreFourPartyDenied):
                    self.send(scope=s,client=CoreFourPartySandboxClient(self.core))
        self.assertEqual(self.calls,0)

    def test_invalid_lease_epoch_or_content_digest(self):
        for key,value in (("lease_epoch",True),
                          ("fencing_token_sha256","x"*64),
                          ("content_sha256","b"*64)):
            with self.subTest(field=key):
                s=dict(self.scope);s[key]=value
                with self.assertRaises(CoreFourPartyDenied):
                    self.send(scope=s,client=CoreFourPartySandboxClient(self.core))
        self.assertEqual(self.calls,0)

    def test_wrong_signature_envelope_scope_or_missing_role(self):
        for role in self.docs:
            docs=copy.deepcopy(self.docs)
            docs[role]["body"]["scope_sha256"]="f"*64
            with self.subTest(role=role),self.assertRaises(CoreFourPartyDenied):
                self.send(docs=docs,client=CoreFourPartySandboxClient(self.core))
        self.assertEqual(self.calls,0)

    def test_wrong_proposal_hash_or_mode(self):
        for kw,value in (("content","tamper"),("mode","AUTOMATIC")):
            p=dict(self.proposal,**{kw:value})
            with self.subTest(field=kw),self.assertRaises(CoreFourPartyDenied):
                self.send(proposal=p,client=CoreFourPartySandboxClient(self.core))
        self.assertEqual(self.calls,0)

    def test_unset_fixture_gate_refuses_client(self):
        with patch.dict(os.environ,{"NF_ATOMIC_TEST_ONLY":"0"}):
            with self.assertRaises(CoreFourPartyDenied):
                CoreFourPartySandboxClient(self.core)
        self.assertEqual(self.calls,0)

    def test_invalid_local_spec_extra_owner_claim_not_accepted_as_host_authority(self):
        c=FakeCore(self.scope);c.row["spec"]["source_sha"]="b"*40
        with self.assertRaises(CoreFourPartyDenied):
            self.send(client=CoreFourPartySandboxClient(c))
        self.assertEqual(self.calls,0)

if __name__=="__main__":
    unittest.main()
