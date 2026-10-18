"""Windows hosted isolated test of separate mTLS witness PROCESS and durable DB.

One physical GitHub runner, NOT two authorized computers, NOT an OS reboot.
Test certificates are freshly generated per case, no permanent credentials.
"""
import base64
import hashlib
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from contextlib import closing
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from windows_external_witness_pilot import (
    WitnessPilotDenied, check_claim, request_test_once,
    PinnedWindowsWitnessSandboxAdapter,
)

def hashbytes(b):
    return hashlib.sha256(b).hexdigest()

def name(s):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,s)])

def cert(priv,common,issuer,issuer_key,*,ca=False,client=False):
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name(common))
         .issuer_name(name(issuer)).public_key(priv.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now-timedelta(days=1))
         .not_valid_after(now+timedelta(days=2))
         .add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca else None),
                        critical=True))
    if not ca:
        usage = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        b=b.add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        if not client:
            b=b.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("nf-witness.test")]),critical=False)
    return b.sign(issuer_key, hashes.SHA256())

def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())

class WindowsExternalWitnessPilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-witness-ci-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{"NF_WINDOWS_WITNESS_TEST_ONLY":"1"})
        self.env.start();self.addCleanup(self.env.stop)
        self.ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.ca=self.write("ca.crt",cert(self.ca_key,"TEST CA","TEST CA",
                                       self.ca_key,ca=True).public_bytes(
                                           serialization.Encoding.PEM))
        server_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        server_cert=cert(server_key,"nf-witness.test","TEST CA",self.ca_key)
        self.srv_cert=self.write("server.crt",server_cert.public_bytes(
                                serialization.Encoding.PEM))
        self.srv_key=self.write("server.key",private_pem(server_key))
        self.srv_fp=hashbytes(server_cert.public_bytes(serialization.Encoding.DER))
        client_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        client_cert=cert(client_key,"nf-receiver.test","TEST CA",self.ca_key,client=True)
        self.cli_cert=self.write("client.crt",client_cert.public_bytes(
                                serialization.Encoding.PEM))
        self.cli_key=self.write("client.key",private_pem(client_key))
        self.cli_fp=hashbytes(client_cert.public_bytes(serialization.Encoding.DER))
        signer=ed25519.Ed25519PrivateKey.generate()
        self.signer=self.write("witness-key.raw",signer.private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        self.witness_pub=base64.b64encode(signer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode("ascii")
        self.claim=dict(
            schema="nf.windows.witness.reserve.test.v1",
            scope_sha256=hashbytes(b"four separately verified signatures"),
            task_id="NF-DEV-05-Q973",
            target_sha256=hashbytes(b"one inert target"),
            operation_id="offline-op-003",
            commit_sequence=12,
            journal_root_sha256="0"*64,
        )
        self.proc=None
        self.addCleanup(self.stop)

    def write(self,filename,data):
        p=self.root/filename
        p.write_bytes(data)
        return p

    def database_count(self):
        db=self.root/"reservations.sqlite3"
        if not db.exists():return 0
        with closing(sqlite3.connect(str(db))) as con:
            return con.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]

    def head(self):
        with closing(sqlite3.connect(str(self.root/"reservations.sqlite3"))) as con:
            return con.execute(
                "SELECT sequence,root FROM witness_head WHERE id=1").fetchone()

    def pick_port(self):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1",0))
            return s.getsockname()[1]

    def start(self,*,drop=False,pinned_client=None):
        self.stop()
        self.port=self.pick_port()
        args=[sys.executable,"-u",str(Path(__file__).with_name(
            "windows_external_witness_pilot.py")),
            "serve-one-ci",str(self.root),str(self.port),str(self.srv_cert),
            str(self.srv_key),str(self.ca),str(self.signer),
            self.cli_fp if pinned_client is None else pinned_client,
            "drop" if drop else "normal"]
        self.proc=subprocess.Popen(args,env=os.environ.copy(),
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   text=True)
        line=self.proc.stdout.readline().strip()
        self.assertEqual(line,"WITNESS_TEST_READY",
                         "witness child did not reach a listening state")
        return self.proc

    def stop(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                try:self.proc.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    self.proc.terminate()
                    try:self.proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:self.proc.kill()
            self.proc=None

    def call(self,*,claim=None,serverpin=None,witnesspub=None,clientcert=None,clientkey=None):
        return request_test_once(
            port=self.port,claim=self.claim if claim is None else claim,
            client_cert=self.cli_cert if clientcert is None else clientcert,
            client_key=self.cli_key if clientkey is None else clientkey,
            ca_cert=self.ca,
            pinned_server_cert_sha256=self.srv_fp if serverpin is None else serverpin,
            pinned_witness_public_b64=self.witness_pub if witnesspub is None else witnesspub)

    def test_one_signed_mutual_tls_durable_reservation_and_process_restart(self):
        self.start()
        result=self.call()
        self.assertEqual(result["status"],"DURABLY_RESERVED_TEST_ONLY")
        self.assertEqual(self.database_count(),1)
        seq,root=self.head()
        self.assertEqual(seq,12)
        self.assertNotEqual(root,"0"*64)
        self.stop()
        self.start()  # actual child PROCESS restart; DB survives
        with self.assertRaises(WitnessPilotDenied):
            self.call()
        self.assertEqual(self.database_count(),1)
        self.assertEqual(self.head(),(seq,root))

    def test_fake_client_certificate_same_ca_is_denied(self):
        other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        othercrt=self.write("other.crt",cert(other,"foreign.test","TEST CA",
            self.ca_key,client=True).public_bytes(serialization.Encoding.PEM))
        otherkey=self.write("other.key",private_pem(other))
        self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call(clientcert=othercrt,clientkey=otherkey)
        self.assertEqual(self.database_count(),0)

    def test_wrong_server_cert_pin_denies_before_reservation(self):
        self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call(serverpin="f"*64)
        self.assertEqual(self.database_count(),0)

    def test_wrong_pinned_witness_public_key_is_unknown_and_not_retryable(self):
        other=ed25519.Ed25519PrivateKey.generate()
        forged_pub=base64.b64encode(other.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call(witnesspub=forged_pub)
        self.assertEqual(self.database_count(),1)
        self.stop();self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call()
        self.assertEqual(self.database_count(),1)

    def test_lost_ack_after_durable_commit_and_restart_denies_replay(self):
        self.start(drop=True)
        with self.assertRaises(WitnessPilotDenied):
            self.call()
        self.assertEqual(self.database_count(),1)
        self.stop();self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call()
        self.assertEqual(self.database_count(),1)

    def test_invalid_lease_sequence_cannot_be_saved(self):
        self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call(claim={**self.claim,"commit_sequence":True})
        self.assertEqual(self.database_count(),0)

    def test_db_receiver_rollback_does_not_rewind_witness_process(self):
        # This is NOT a real machine snapshot restore. Separate receiver
        # checkpoint file is deliberately overwritten after witness has synced.
        self.start()
        self.call()
        receiver=self.write("receiver_checkpoint.json",b'{"phase":"COMPLETED"}')
        receiver.write_bytes(b'{"phase":"UNKNOWN"}')
        self.stop();self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.call()
        self.assertEqual(self.database_count(),1)

    def test_second_operation_on_same_task_or_target_is_denied(self):
        self.start();self.call();self.stop()
        self.start()
        c={**self.claim, "operation_id":"offline-op-004",
           "commit_sequence":13,"journal_root_sha256":self.head()[1]}
        with self.assertRaises(WitnessPilotDenied):
            self.call(claim=c)
        self.assertEqual(self.database_count(),1)

    def test_wrong_chain_head_or_replayed_sequence_denied(self):
        self.start();self.call();self.stop()
        self.start()
        c={**self.claim,"task_id":"NF-DEV-05-Q974",
           "target_sha256":hashbytes(b"different file"),
           "operation_id":"offline-op-004","commit_sequence":12}
        with self.assertRaises(WitnessPilotDenied):
            self.call(claim=c)
        self.assertEqual(self.database_count(),1)

    def adapter(self):
        return PinnedWindowsWitnessSandboxAdapter(
            task_id=self.claim["task_id"],
            target_sha256=self.claim["target_sha256"],
            port=self.port,
            client_cert=self.cli_cert, client_key=self.cli_key,
            ca_cert=self.ca,
            pinned_server_cert_sha256=self.srv_fp,
            pinned_witness_public_b64=self.witness_pub,
        )

    def test_host_reserve_precommit_adapter_reaches_signed_witness(self):
        self.start()
        a=self.adapter()
        ack=a.reserve_precommit(
            scope_sha256=self.claim["scope_sha256"],
            operation_id=self.claim["operation_id"],
            commit_sequence=self.claim["commit_sequence"],
            journal_root_sha256=self.claim["journal_root_sha256"])
        self.assertEqual(ack["status"],"DURABLY_RESERVED_TEST_ONLY")
        self.assertEqual(self.database_count(),1)
        self.stop();self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.adapter().reserve_precommit(
                scope_sha256=self.claim["scope_sha256"],
                operation_id=self.claim["operation_id"],
                commit_sequence=self.claim["commit_sequence"],
                journal_root_sha256=self.claim["journal_root_sha256"])
        self.assertEqual(self.database_count(),1)

    def test_host_adapter_ack_loss_is_unknown_never_a_permission(self):
        self.start(drop=True)
        with self.assertRaises(WitnessPilotDenied):
            self.adapter().reserve_precommit(
                scope_sha256=self.claim["scope_sha256"],
                operation_id=self.claim["operation_id"],
                commit_sequence=self.claim["commit_sequence"],
                journal_root_sha256=self.claim["journal_root_sha256"])
        self.assertEqual(self.database_count(),1)
        self.stop();self.start()
        with self.assertRaises(WitnessPilotDenied):
            self.adapter().reserve_precommit(
                scope_sha256=self.claim["scope_sha256"],
                operation_id=self.claim["operation_id"],
                commit_sequence=self.claim["commit_sequence"],
                journal_root_sha256=self.claim["journal_root_sha256"])

    def test_explicit_ci_gate_required(self):
        with patch.dict(os.environ,{"NF_WINDOWS_WITNESS_TEST_ONLY":"0"}):
            with self.assertRaises(WitnessPilotDenied):
                request_test_once(
                    port=9999,claim=self.claim,client_cert=self.cli_cert,
                    client_key=self.cli_key,ca_cert=self.ca,
                    pinned_server_cert_sha256=self.srv_fp,
                    pinned_witness_public_b64=self.witness_pub)
        self.assertEqual(self.database_count(),0)

if __name__=="__main__":unittest.main()
