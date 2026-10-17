"""Cross-UID Linux/PG16 antirollback regression. No user host or live issuer."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import psycopg

MODULE=Path(__file__).with_name("offline_operator_anchor.py")
PY=os.environ.get("NF_OPERATOR_TEST_PYTHON")
DB="postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"

def command(user,*args):
    return subprocess.run(["sudo","-n","-u",user,"env",
       "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(MODULE),*map(str,args)],
       capture_output=True,text=True,timeout=10)

class OperatorSeparateUidTests(unittest.TestCase):
    def setUp(self):
        if not PY or os.name!="posix":
            raise RuntimeError("requires explicit disposable Linux named uid gate")
        self.temp=tempfile.TemporaryDirectory(prefix="nf-op-role-ci-")
        self.addCleanup(self.cleanup)
        self.base=Path(self.temp.name)
        self.base.chmod(0o755)
        self.home=self.base/"nf-signer-fixture"
        subprocess.run(["sudo","-n","install","-d","-m","0700","-o","nf_signer","-g",
             "nf_signer",str(self.home)],check=True)
        out=command("nf_signer","bootstrap",self.home)
        self.assertEqual(out.returncode,0,out.stderr)
        self.bootstrap=json.loads(out.stdout)
        self.pub=self.bootstrap["public_key_base64"]
        self.pubsha=self.bootstrap["public_key_sha256"]
        self.assertFalse(self.bootstrap["can_authorize_live_operations"])
        self.db=psycopg.connect(DB,autocommit=True,connect_timeout=3)
        self.addCleanup(self.db.close)
        self.db.execute("""CREATE TABLE IF NOT EXISTS nf_operator_mirror_fixture
          (singleton integer PRIMARY KEY CHECK(singleton=1),sequence bigint NOT NULL,
           head varchar(64) NOT NULL,packet jsonb NOT NULL)""")
        self.db.execute("DELETE FROM nf_operator_mirror_fixture")
    def cleanup(self):
        # Whole signer OS identity exists only on short-lived github hosted VM.
        subprocess.run(["sudo","-n","rm","-rf","--",str(self.home)],check=True)
        self.temp.cleanup()
    def advance(self,claim):
        result=command("nf_signer","advance",self.home,claim)
        self.assertEqual(result.returncode,0,result.stderr)
        packet=json.loads(result.stdout)
        self.assertFalse(packet["execution_allowed"])
        return packet
    def sample(self,suffix):
        return hashlib.sha256(("fixture approved checkpoint "+suffix).encode()).hexdigest()
    def db_write(self,packet):
        cert=packet["certificate"]
        self.db.execute("""INSERT INTO nf_operator_mirror_fixture(singleton,sequence,head,packet)
             VALUES(1,%s,%s,%s) ON CONFLICT(singleton) DO UPDATE SET
             sequence=excluded.sequence,head=excluded.head,packet=excluded.packet""",
             (cert["sequence"],cert["head"],json.dumps(packet)))
    def verify(self,packet,*,pin=None,pub=None):
        path=self.base/"db-presented.json"
        path.write_text(json.dumps(packet),encoding="ascii")
        path.chmod(0o644)
        return command("nf_signer","verify",self.home,path,pin or self.pubsha,pub or self.pub)
    def test_distinct_os_principal_owns_private_key_and_tip(self):
        self.assertEqual(self.home.stat().st_uid,
            int(subprocess.check_output(["id","-u","nf_signer"],text=True).strip()))
        self.assertEqual(stat.S_IMODE(self.home.stat().st_mode),0o700)
        for name in ("issuer-private.raw","protected-anchor.json","operator.lock"):
            file=self.home/name
            self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
        attempt=subprocess.run(["sudo","-n","-u","nf_db_actor","cat",
             str(self.home/"issuer-private.raw")],capture_output=True,text=True)
        self.assertNotEqual(attempt.returncode,0)
        self.assertNotIn("BEGIN PRIVATE KEY",attempt.stdout)
    def test_successful_signed_checkpoint_matches_independent_current_tip(self):
        packet=self.advance(self.sample("one"))
        self.db_write(packet)
        self.assertEqual(self.verify(packet).returncode,0)
        self.assertEqual(packet["certificate"]["sequence"],1)
        self.assertEqual(self.db.execute(
             "SELECT sequence FROM nf_operator_mirror_fixture").fetchone()[0],1)
    def test_postgresql_db_admin_rollback_detected_by_protected_other_uid_tip(self):
        first=self.advance(self.sample("one"));self.db_write(first)
        second=self.advance(self.sample("two"));self.db_write(second)
        self.assertEqual(self.verify(second).returncode,0)
        # DB actor can restore an old valid signed packet in its DB.
        self.db_write(first)
        rolled=json.loads(self.db.execute(
             "SELECT packet::text FROM nf_operator_mirror_fixture").fetchone()[0])
        fail=self.verify(rolled)
        self.assertNotEqual(fail.returncode,0)
        self.assertIn("ROLLBACK_OR_UNPINNED_CHECKPOINT",fail.stderr)
        self.assertFalse(self.bootstrap["can_authorize_live_operations"])
    def test_database_actor_cannot_edit_external_tip(self):
        before=(self.home/"protected-anchor.json").read_bytes() if os.geteuid()==0 else None
        attempt=subprocess.run(["sudo","-n","-u","nf_db_actor","sh","-c",
             'echo attack > "$1"',"sh",str(self.home/"protected-anchor.json")],
             capture_output=True,text=True)
        self.assertNotEqual(attempt.returncode,0)
        p=self.advance(self.sample("valid"))
        self.assertEqual(self.verify(p).returncode,0)
    def test_wrong_externally_pinned_public_key_denied(self):
        p=self.advance(self.sample("one"))
        self.assertNotEqual(self.verify(p,pin="f"*64).returncode,0)
    def test_forged_signed_receipt_denied(self):
        p=self.advance(self.sample("one"))
        p["certificate"]["claim_sha256"]="f"*64
        result=self.verify(p)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("bad cryptographic witness",result.stderr)
    def test_duplicate_claim_refused_without_advancing_tip(self):
        claim=self.sample("duplicate")
        p=self.advance(claim)
        rejected=command("nf_signer","advance",self.home,claim)
        self.assertNotEqual(rejected.returncode,0)
        self.assertEqual(self.verify(p).returncode,0)
    def test_stale_signed_packet_replay_denied(self):
        old=self.advance(self.sample("old"))
        new=self.advance(self.sample("new"))
        self.assertEqual(self.verify(new).returncode,0)
        self.assertNotEqual(self.verify(old).returncode,0)
    def test_unprivileged_actor_cannot_reset_or_bootstrap_signer(self):
        attempts=[
            command("nf_db_actor","bootstrap",self.home),
            command("nf_db_actor","advance",self.home,self.sample("x")),
        ]
        self.assertTrue(all(x.returncode!=0 for x in attempts))
        duplicate_bootstrap=command("nf_signer","bootstrap",self.home)
        self.assertNotEqual(duplicate_bootstrap.returncode,0)
    def test_two_concurrent_operator_commands_have_unique_tip(self):
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
            results=list(e.map(lambda x:command("nf_signer","advance",self.home,x),
                                [self.sample("concurrent-a"),self.sample("concurrent-b")]))
        self.assertTrue(all(r.returncode==0 for r in results),[r.stderr for r in results])
        packets=[json.loads(r.stdout) for r in results]
        self.assertEqual(sorted(p["certificate"]["sequence"] for p in packets),[1,2])
        top=max(packets,key=lambda p:p["certificate"]["sequence"])
        self.assertEqual(self.verify(top).returncode,0)
    def test_local_root_is_out_of_security_boundary(self):
        self.assertNotEqual(
            subprocess.run([PY,str(MODULE),"bootstrap",str(self.home)],
                           capture_output=True,text=True,env=dict(os.environ,
                               NF_OPERATOR_ANCHOR_FIXTURE_ONLY="1")).returncode,0)
    def test_absent_real_owner_approval_does_not_grant_execution(self):
        p=self.advance(self.sample("not owner authenticated"))
        self.assertEqual(p["kind"],"MONOTONIC_FIXTURE_WITNESS_NOT_OPERATION_APPROVAL")
        self.assertFalse(p["execution_allowed"])
        self.assertFalse(json.loads(self.verify(p).stdout)["operation_execution_allowed"])

if __name__=="__main__":
    unittest.main()
