"""New CORE OS-bound Unix transport policy tests. Socket response is mocked
by tiny in-process test server; no HOST file effect asserted by this suite.
Separate UID+real effect proven in HOST-owned hosted Linux CI elsewhere.
"""
import hashlib,json,os,socket,tempfile,threading,time,unittest
from pathlib import Path
from offline_os_receiver_client import CoreProtectedUnixReceiverClient,CoreOSRouteDenied

TASK="NF-DEV-05-Q973"
WORKER="worker-sandbox-01"
CONTENT="test only a bounded proposal"
TARGET="bridge/neurofactory/development/core_owned/one.txt"
def sha(s):return hashlib.sha256(s.encode()).hexdigest()

class Conn:
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self,*args):return None
class Core:
    def __init__(self):
        self.row={
           "state":"CLAIMED","owner":WORKER,
           "lease_until":int(time.time())+100,
           "token":sha("single-core-token"),
           "spec":{
             "task_id":TASK,"project_id":"nf-sandbox",
             "source_sha":"a"*40,"source_sha256":"b"*64,
             "target":TARGET}}
    def _connect(self):return Conn()
    def _row(self,conn):return self.row

class OSBoundCORETests(unittest.TestCase):
    def setUp(self):
        self.envs=("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY",
                   "NF_RECEIVER_OS_FIXTURE_ONLY")
        self.old={e:os.environ.get(e) for e in self.envs}
        os.environ["NF_CORE_OFFLINE_RECEIVER_TEST_ONLY"]="1"
        os.environ["NF_RECEIVER_OS_FIXTURE_ONLY"]="1"
        self.addCleanup(self.restore_env)
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-core-os-test-")
        self.addCleanup(self.tmp.cleanup)
        self.dir=Path(self.tmp.name)/"nf-recipient-ipc"
        self.dir.mkdir()
        self.sock=str(self.dir/"nf-recipient.sock")
        self.core=Core()
        self.proposal={
           "schema":"neurofactory.core.proposal.v1",
           "target":TARGET,"content":CONTENT,
           "content_sha256":sha(CONTENT),"mode":"OFFLINE_TEST"}
        self.packet={"payload":{
           "task_id":TASK,"project_id":"nf-sandbox",
           "source_sha40":"a"*40,"source_file_sha256":"b"*64,
           "target":TARGET,"worker_id":WORKER,
           "proposed_content_sha256":sha(CONTENT)},"signature_base64":"fixture"}
        self.receipt={"status":"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY",
                      "file_sha256":sha(CONTENT),"live_execution_allowed":False}
        self.client=CoreProtectedUnixReceiverClient(self.core,socket_path=self.sock,
                                      pinned_receiver_uid=os.geteuid())
    def restore_env(self):
        for k,v in self.old.items():
            if v is None:os.environ.pop(k,None)
            else:os.environ[k]=v
    def call(self,proposal=None,packet=None,client=None):
        return (self.client if client is None else client).propose_once(
             task_id=TASK,worker_id=WORKER,core_token="single-core-token",
             proposal=self.proposal if proposal is None else proposal,
             signed_packet=self.packet if packet is None else packet,
             witness={"certificate":"not independent owner approval"})
    def serve_one(self,receipt=None):
        ready=threading.Event()
        def server():
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                    s.bind(self.sock);s.listen(1);s.settimeout(4)
                    ready.set()
                    conn,_=s.accept()
                    with conn:
                        conn.recv(111000)
                        body=self.receipt if receipt is None else receipt
                        conn.sendall(json.dumps(body).encode())
            finally:
                try:os.unlink(self.sock)
                except FileNotFoundError:pass
        t=threading.Thread(target=server,daemon=True)
        t.start();self.assertTrue(ready.wait(2))
        return t
    def test_exact_claim_and_receipt_is_nonlive(self):
        t=self.serve_one()
        r=self.call()
        t.join(3)
        self.assertEqual(r["status"],"CORE_TO_SEPARATE_UID_HOST_ONE_TEST_EFFECT_ONLY")
        self.assertFalse(r["live_execution_allowed"])
        self.assertFalse(r["core_wrote_local_file"])
        self.assertFalse(r["independent_review_approved"])
    def test_wrong_server_uid_denies_before_response(self):
        other=CoreProtectedUnixReceiverClient(self.core,socket_path=self.sock,
                                             pinned_receiver_uid=os.geteuid()+10000)
        t=self.serve_one()
        with self.assertRaises(CoreOSRouteDenied):self.call(client=other)
    def test_wrong_core_token_denies_before_connect(self):
        self.core.row["token"]=sha("different")
        with self.assertRaises(CoreOSRouteDenied):self.call()
    def test_expired_core_claim_denies(self):
        self.core.row["lease_until"]=int(time.time())-1
        with self.assertRaises(CoreOSRouteDenied):self.call()
    def test_scope_attacks_denied_before_connect(self):
        for key,value in (("target","bridge/neurofactory/development/core_owned/foreign.py"),
                          ("worker_id","wrong"),("project_id","foreign"),
                          ("source_sha40","0"*40)):
            with self.subTest(key=key):
                p={"payload":dict(self.packet["payload"],**{key:value}),
                    "signature_base64":"fixture"}
                with self.assertRaises(CoreOSRouteDenied):self.call(packet=p)
    def test_model_proposal_untrusted_hash_denied(self):
        with self.assertRaises(CoreOSRouteDenied):
            self.call(proposal=dict(self.proposal,content="modified code"))
    def test_host_denied_receipt_fail_closed(self):
        t=self.serve_one({"status":"DENIED_OR_UNKNOWN_MANUAL_STOP",
                         "live_execution_allowed":False})
        with self.assertRaises(CoreOSRouteDenied):self.call()
        t.join(3)
    def test_host_forged_live_true_fail_closed(self):
        t=self.serve_one(dict(self.receipt,live_execution_allowed=True))
        with self.assertRaises(CoreOSRouteDenied):self.call()
        t.join(3)
    def test_host_unreachable_blocks_without_mutating(self):
        with self.assertRaises(CoreOSRouteDenied):self.call()
        self.assertEqual(list(self.dir.iterdir()),[])

if __name__=="__main__":unittest.main()
