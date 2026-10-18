"""Exact, two-branch CORE->HOST four-party sandbox E2E test, one ephemeral runner.

CORE adapter is loaded from separately pinned CORE branch by isolated CI
checkout: no CORE source copied to HOST repository tree or modified here.
Temporary PostgreSQL16, disposable local file, in-memory witness double.
Never an OS-isolated or physical two-host production verification.
"""
import hashlib
import json
import subprocess
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import psycopg

PINNED_CORE_DIR=os.environ.get("NF_CORE_PINNED_ADAPTER_DIR")
if not PINNED_CORE_DIR or not Path(PINNED_CORE_DIR).is_dir():
    raise RuntimeError("pinned CORE adapter checkout absent: refuse fake integration")
sys.path.insert(0,PINNED_CORE_DIR)
from one_task_core import OneTaskCore, CoreSafetyError
from four_party_sandbox_client import (
    CoreFourPartySandboxClient, CoreFourPartyDenied, CoreFourPartyUnknown,
)
from sandbox_atomic_effect_candidate import apply_sandbox_once
from test_db_bound_four_party_preflight import (
    SQLSignedEffectsE2E, SCHEMA_PATH, DSN, DB_NAME,
)
from test_independent_four_party_scope import FourPartyScopeTests, NOW
from test_sandbox_atomic_effect_candidate import WitnessDouble

def sha(s):
    return hashlib.sha256(s.encode("utf8")).hexdigest()

class Conn:
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def execute(self,*args): return None

class ExistingCoreClaim:
    """Imitates OneTaskCore._row exact task.v1 fields, never a HOST grant."""
    def __init__(self,scope):
        self.row={
            "state":"CLAIMED",
            "owner":scope["worker_id"],
            "lease_until":NOW+90,
            "token":sha("test-only-token"),
            "spec":{
                "schema":"neurofactory.core.task.v1",
                "task_id":scope["task_id"],
                "project_id":scope["project_id"],
                "source_sha":scope["source_sha40"],
                "source_sha256":scope["source_file_sha256"],
                "target":scope["target"],
            },
        }
    def _connect(self): return Conn()
    def _row(self,c): return self.row

class CoreHostRealDisposableE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.name!="posix" or
                os.environ.get("NF_DB_SCHEMA_CI_ONLY")!="1" or
                os.environ.get("NF_ATOMIC_TEST_ONLY")!="1" or
                os.environ.get("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY")!="1"):
            raise RuntimeError("required isolated host+CORE fixture gates missing")
        cls.db=psycopg.connect(DSN,autocommit=True,connect_timeout=5)
        cls.addClassCleanup(cls.db.close)
        if cls.db.execute("SELECT current_database()").fetchone()[0]!=DB_NAME:
            raise RuntimeError("wrong disposable database")
        cls.db.execute(SCHEMA_PATH.read_text(encoding="utf8"))

    _seed=SQLSignedEffectsE2E._seed
    _insert_only_receipt=SQLSignedEffectsE2E._insert_only_receipt

    def setUp(self):
        self.db.execute(
            "TRUNCATE nf_trusted_host.effect_receipt, nf_trusted_host.lease_register CASCADE")
        self.four=FourPartyScopeTests(
            methodName="test_positive_all_four_cryptographic_scopes_still_no_authority")
        self.four.setUp()
        self.scope=self.four.scope
        self.pins=dict(
            pinned_keys=self.four.pins,
            metadata=dict(
                repository=self.scope["repository"],
                github_user_id=self.scope["github_user_id"],
                repository_id=self.scope["repository_id"],
                live_execution_allowed=False,
            ),
        )
        self._seed()
        self.core=ExistingCoreClaim(self.scope)
        self.content="content"
        self.proposal=dict(
            schema="neurofactory.core.proposal.v1",
            target=self.scope["target"],content=self.content,
            content_sha256=sha(self.content),mode="OFFLINE_TEST",
        )
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-atomic-ci-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.file=self.root/"one_result.txt"
        self.witness=WitnessDouble()
        self.host_calls=0

    def new_client(self):
        return CoreFourPartySandboxClient(self.core)

    def host(self, *, crash=False):
        def submit(**kw):
            self.host_calls+=1
            with patch("db_bound_four_party_preflight.load_operator_installed_public_pins",
                       return_value=self.pins):
                return apply_sandbox_once(
                    self.db,sandbox_root=self.root,witness=self.witness,
                    inject_crash_after_fsync=crash,**kw)
        return submit

    def send(self, *, client=None, docs=None, host=None, token="test-only-token"):
        d=self.four.packets if docs is None else docs
        return (self.new_client() if client is None else client).submit_once(
            task_id=self.scope["task_id"],
            worker_id=self.scope["worker_id"],
            core_token=token,proposal=self.proposal,
            expected_effect=self.scope,
            signed_operator_acl=d["operator"],
            signed_owner_grant=d["owner"],
            signed_host_lease=d["host"],
            signed_external_witness=d["witness"],
            now_unix=NOW,
            host_submit=self.host() if host is None else host,
        )

    def receipt(self):
        return self.db.execute(
            "SELECT status,receiver_file_sha256 FROM nf_trusted_host.effect_receipt"
        ).fetchone()

    def test_one_core_to_host_real_sandbox_file_and_sql_commit(self):
        r=self.send()
        self.assertEqual(r["status"],"CORE_HOST_FOUR_PARTY_SANDBOX_COMPLETED_TEST_ONLY")
        self.assertEqual(self.host_calls,1)
        self.assertEqual(self.file.read_bytes(),b"content")
        self.assertEqual(self.receipt(),("COMPLETED",self.scope["content_sha256"]))
        self.assertEqual(self.db.execute(
            "SELECT state FROM nf_trusted_host.lease_register").fetchone(),("COMPLETED",))
        self.assertEqual(len(self.witness.reservations),1)
        self.assertFalse(r["core_wrote_local_file"])
        self.assertFalse(r["live_execution_allowed"])
        self.assertFalse(r["automatic_retry_allowed"])

    def test_wrong_core_token_cannot_reach_host_or_file(self):
        with self.assertRaises(CoreFourPartyDenied):
            self.send(token="bad-token")
        self.assertEqual(self.host_calls,0)
        self.assertFalse(self.file.exists())
        self.assertFalse(self.witness.reservations)

    def test_expired_local_core_lease_blocks_before_host(self):
        self.core.row["lease_until"]=NOW-1
        with self.assertRaises(CoreFourPartyDenied):
            self.send()
        self.assertEqual(self.host_calls,0)
        self.assertFalse(self.file.exists())

    def test_wrong_signed_owner_rejected_by_host_never_writer(self):
        d=dict(self.four.packets)
        d["owner"]=dict(d["owner"], signature_base64="A"*88)
        client=self.new_client()
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(client=client,docs=d)
        self.assertEqual(self.host_calls,1)
        self.assertFalse(self.file.exists())
        self.assertFalse(self.witness.reservations)
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(client=client)
        self.assertEqual(self.host_calls,1)

    def test_expired_central_pg_lease_rejected_no_file(self):
        self.db.execute(
            "UPDATE nf_trusted_host.lease_register "
            "SET lease_deadline=clock_timestamp()-interval '1 second'")
        with self.assertRaises(CoreFourPartyUnknown):
            self.send()
        self.assertEqual(self.host_calls,1)
        self.assertFalse(self.file.exists())
        self.assertFalse(self.witness.reservations)

    def test_crash_after_fsync_returns_unknown_and_blocks_retry(self):
        c=self.new_client()
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(client=c,host=self.host(crash=True))
        self.assertEqual(self.file.read_bytes(),b"content")
        self.assertEqual(self.receipt()[0],"UNKNOWN")
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(client=c)
        self.assertEqual(self.host_calls,1)

    def test_successful_host_file_cannot_be_duplicated_by_new_core_client(self):
        self.send()
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(client=self.new_client())
        self.assertEqual(self.file.read_bytes(),b"content")
        self.assertEqual(len(self.witness.reservations),1)
        self.assertEqual(self.receipt()[0],"COMPLETED")

    def test_db_snapshot_replay_after_file_restore_denied_by_witness(self):
        self.send()
        self.db.execute("TRUNCATE nf_trusted_host.effect_receipt")
        self.db.execute(
            "UPDATE nf_trusted_host.lease_register SET state='CLAIMED'")
        self._insert_only_receipt()
        self.file.unlink()
        with self.assertRaises(CoreFourPartyUnknown):
            self.send(client=self.new_client())
        self.assertFalse(self.file.exists())
        self.assertEqual(self.receipt()[0],"UNKNOWN")
        self.assertEqual(len(self.witness.reservations),1)

    def prepare_real_core_sqlite(self):
        """Create authentic OneTaskCore task.v1 using a disposable Git commit."""
        source=tempfile.TemporaryDirectory(prefix="nf-core-real-ci-")
        self.addCleanup(source.cleanup)
        base=Path(source.name)
        repo=base/"repository"
        repo.mkdir(mode=0o700)
        subprocess.run(["git","-C",str(repo),"init","--quiet"],check=True)
        (repo/"README.md").write_text("inert checkout only",encoding="utf-8")
        subprocess.run(["git","-C",str(repo),"add","README.md"],check=True)
        subprocess.run(["git","-C",str(repo),
                        "-c","user.email=ci@example.invalid",
                        "-c","user.name=CI Sandbox",
                        "commit","-m","inert source","--quiet"],check=True)
        source_sha=subprocess.check_output(
            ["git","-C",str(repo),"rev-parse","HEAD"],text=True).strip()
        self.scope["source_sha40"]=source_sha
        self.scope["source_file_sha256"]=hashlib.sha256(b"").hexdigest()
        payload=json.dumps(self.scope,sort_keys=True,separators=(",",":"),
                           ensure_ascii=True,allow_nan=False).encode("ascii")
        self.four.scope_hash=hashlib.sha256(payload).hexdigest()
        for body in self.four.bodies.values():
            body["scope_sha256"]=self.four.scope_hash
        self.four.packets={role:self.four.sign(role) for role in self.four.packets}
        self.db.execute(
            "TRUNCATE nf_trusted_host.effect_receipt, nf_trusted_host.lease_register CASCADE")
        self._seed()
        root=base/"core-state"
        root.mkdir(mode=0o700)
        self.core=OneTaskCore(root,repo)
        spec=dict(
            schema="neurofactory.core.task.v1",
            task_id=self.scope["task_id"],project_id=self.scope["project_id"],
            target=self.scope["target"],
            objective="Perform one inert isolated CORE to HOST test file transaction",
            source_sha=source_sha,
            source_sha256=self.scope["source_file_sha256"],
            model="qwen3:0.6b",reserved_units=1,approval_commit=source_sha,
        )
        # Synthetic approval only; no external operator has approved production.
        self.core.enqueue(spec,trusted_approval_check=lambda task: task==spec)
        claim=self.core.claim(self.scope["worker_id"],now=NOW,lease_seconds=120)
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")
        return claim

    def test_actual_onetaskcore_git_source_and_sqlite_claim_to_host_receipt(self):
        claim=self.prepare_real_core_sqlite()
        r=self.send(client=self.new_client(),token=claim["token"])
        self.assertEqual(r["status"],"CORE_HOST_FOUR_PARTY_SANDBOX_COMPLETED_TEST_ONLY")
        self.assertEqual(self.file.read_bytes(),b"content")
        self.assertEqual(self.receipt(),("COMPLETED",self.scope["content_sha256"]))
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")
        self.assertEqual(len(self.witness.reservations),1)
        self.assertFalse(r["core_wrote_local_file"])
        self.assertFalse(r["live_execution_allowed"])
        self.assertFalse(r["independent_review_approved"])

    def test_actual_onetaskcore_expired_sqlite_claim_never_reaches_host(self):
        claim=self.prepare_real_core_sqlite()
        with self.core._connect() as con:
            con.execute("UPDATE single_job SET lease_until=? WHERE singleton=1",(NOW-1,))
        with self.assertRaises(CoreFourPartyDenied):
            self.send(client=self.new_client(),token=claim["token"])
        self.assertEqual(self.host_calls,0)
        self.assertFalse(self.file.exists())
        self.assertEqual(self.receipt()[0],"UNKNOWN")

if __name__=="__main__": unittest.main()
