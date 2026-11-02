"""One contiguous REAL TLS1.3/Ed25519 witness -> CORE -> one inert CI file.

The remote peer is a distinct localhost server socket & SQLite ledger on the
same GitHub-hosted Linux machine, NOT a physically independent production VPS.
Only the public-network address safety check is patched to loopback; neither
the wire request, certificate handshake, signatures nor witness DB are mocked.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from external_highwater_store import provision_empty_database, inspect_external_highwater
from external_highwater_mtls_server import serve_once
from protected_host_remote_bridge import OneShotHostWitnessBridge
from remote_highwater_client import RemoteHighwaterDenied
from scm_one_effect_witness_fence import RecipientFenceUnknown
from test_external_highwater_mtls_server import (
    selfsigned_ca, issued, write, private_pem, digest,
)
from test_scm_one_effect_witness_fence import SignedRecipientWitnessFenceTests


class FullWireAndOneFileLab(unittest.TestCase):
    def setUp(self):
        if os.name != "posix" or os.geteuid() == 0:
            self.skipTest("must be a disposable nonroot Linux runner")
        if (os.getenv("GITHUB_ACTIONS") != "true" or
                os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
                not os.getenv("RUNNER_TEMP")):
            self.skipTest("no personal computer or production remote witness")
        self.fixture=SignedRecipientWitnessFenceTests(
            "test_exact_live_claim_three_signatures_witness_once_durable")
        self.fixture.setUp()
        self.addCleanup(lambda: (self.fixture.tearDown(),self.fixture.doCleanups()))
        self.fixture._approved_ci_file()
        # The disposable independent witness has an empty ledger, so the
        # first request must be epoch 1 and not the in-memory ACK fixture's 5.
        fx=self.fixture.fx
        fx.claim["external_epoch"]=1
        fx.expected["minimum_external_epoch"]=1
        fx.remote["external_epoch"]=1
        self.temp=tempfile.TemporaryDirectory(prefix="nf-wire-to-file-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        ca_key,ca=selfsigned_ca()
        s_key,s_cert=issued(ca_key,ca,client=False)
        c_key,c_cert=issued(ca_key,ca,client=True)
        self.ca_file=write(self.root/"ca.pem",ca.public_bytes(serialization.Encoding.PEM))
        self.server_cert=write(self.root/"server.pem",s_cert.public_bytes(serialization.Encoding.PEM))
        self.server_key=write(self.root/"server.key",private_pem(s_key))
        self.client_cert=write(self.root/"client.pem",c_cert.public_bytes(serialization.Encoding.PEM))
        self.client_key=write(self.root/"client.key",private_pem(c_key))
        self.witness_key=Ed25519PrivateKey.generate()
        self.signer=write(self.root/"signer.raw",self.witness_key.private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        self.client_pin=digest(c_cert.public_bytes(serialization.Encoding.DER))
        self.server_pin=digest(s_cert.public_bytes(serialization.Encoding.DER))
        self.db=self.root/"remote-ledger.sqlite3"
        provision_empty_database(self.db)
        self.fx=fx
        self.fixture.bridge=lambda: OneShotHostWitnessBridge(
            pinned_owner_public=fx.owner.public_key(),
            pinned_reviewer_public=fx.reviewer.public_key(),
            pinned_witness_public=self.witness_key.public_key(),
            pinned_witness_id="lab-separated-socket",
            operator_expected=dict(fx.expected),
            trusted_minimum_remote_epoch=1,
            tls_hostname="witness.test.invalid",tls_port=self.port,
            tls_ca=self.ca_file,tls_client_cert=self.client_cert,
            tls_client_key=self.client_key,
            pinned_tls_server_der_sha256=self.server_pin,
            operator_protected_attempt_dir=self.fixture.attempt_dir)
        self.folder=self.fixture._fixed_ci_output()
        self.port=0

    def serve(self):
        socket_probe=socket.socket()
        socket_probe.bind(("127.0.0.1",0))
        self.port=socket_probe.getsockname()[1]
        socket_probe.close()
        ready=threading.Event()
        result={}
        def server():
            try:
                result["value"]=serve_once(
                    listen_address="127.0.0.1",port=self.port,
                    server_cert=self.server_cert,server_key=self.server_key,
                    trusted_clients_ca=self.ca_file,
                    pinned_client_der_sha256=self.client_pin,
                    db=self.db,witness_private_key=self.signer,
                    witness_id="lab-separated-socket",
                    machine_sha256=self.fx.claim["machine_identity_sha256"],
                    package_sha256=self.fx.claim["package_sha256"],
                    source_sha40=self.fx.claim["source_sha40"],
                    ready_callback=ready.set)
            except Exception as e:
                result["error"]=repr(e)
        # Test-only loopback authorization must be in scope BEFORE the
        # independent server thread validates its bind address.
        previous=os.environ.get("NF_EXTERNAL_WITNESS_EPHEMERAL_CI")
        os.environ["NF_EXTERNAL_WITNESS_EPHEMERAL_CI"]="1"
        self.addCleanup(lambda: os.environ.pop("NF_EXTERNAL_WITNESS_EPHEMERAL_CI",None)
                        if previous is None else
                        os.environ.__setitem__("NF_EXTERNAL_WITNESS_EPHEMERAL_CI",previous))
        t=threading.Thread(target=server,daemon=True)
        t.start()
        self.assertTrue(ready.wait(6),"TLS witness not listening")
        self.addCleanup(lambda:t.join(timeout=8))
        return result,t

    def _connect_scope(self):
        real_connect=socket.create_connection
        return (
            patch.dict(os.environ,{"NF_EXTERNAL_WITNESS_EPHEMERAL_CI":"1"}),
            patch("remote_highwater_client.socket.create_connection",
                  side_effect=lambda addr,timeout: real_connect(("127.0.0.1",self.port),timeout)),
            patch("remote_highwater_client._verified_public_peer",return_value=None),
        )

    def test_real_mtls_witness_sqlite_signed_ack_then_one_file_and_no_replay(self):
        result,server=self.serve()
        patches=self._connect_scope()
        with patches[0],patches[1],patches[2]:
            reply=self.fixture._file(self.fixture.fence(),self.folder)
        server.join(timeout=8)
        self.assertFalse(server.is_alive())
        self.assertNotIn("error",result)
        self.assertEqual(result["value"]["status"],
                         "DURABLY_RESERVED_AND_SIGNED_NO_TASK_EXECUTION")
        self.assertEqual(reply["status"],"ONE_INERT_CI_FILE_AFTER_SIGNED_REMOTE_ACK")
        self.assertEqual((self.folder/"windows_pilot.txt").read_bytes(),
                         self.fixture.payload)
        self.assertEqual(inspect_external_highwater(self.db)["highest_committed_epoch"],1)
        self.assertEqual(inspect_external_highwater(self.db)["reserved_operations"],1)
        self.assertEqual(self.fixture.stage()[0][0],
                         "ACK_OBSERVED_NO_EFFECT_AUTHORITY")
        with self.assertRaises(RecipientFenceUnknown):
            self.fixture._file(self.fixture.fence(),self.folder)
        self.assertEqual(inspect_external_highwater(self.db)["reserved_operations"],1)
        print("NF_REAL_MTLS_CORE_SIGNED_REMOTE_ACK_SINGLE_FILE_NO_REPLAY=PASS_CI_ONLY")

    def test_real_mtls_witness_ack_committed_but_local_file_crash_never_retries(self):
        result,server=self.serve()
        def crash():
            raise RuntimeError("crash injection AFTER wire signed ACK before file")
        patches=self._connect_scope()
        with patches[0],patches[1],patches[2]:
            with self.assertRaises(RecipientFenceUnknown):
                self.fixture._file(self.fixture.fence(),self.folder,
                                   after_ack_test_hook=crash)
        server.join(timeout=8)
        self.assertFalse(server.is_alive())
        self.assertNotIn("error",result)
        self.assertEqual(inspect_external_highwater(self.db)["highest_committed_epoch"],1)
        self.assertFalse((self.folder/"windows_pilot.txt").exists())
        with self.assertRaises(RecipientFenceUnknown):
            self.fixture._file(self.fixture.fence(),self.folder)
        self.assertEqual(inspect_external_highwater(self.db)["reserved_operations"],1)
        print("NF_REAL_MTLS_ACK_COMMITTED_CRASH_BEFORE_FILE_NO_AUTO_RETRY=PASS_CI_ONLY")


    def test_valid_local_sqlite_snapshot_rollback_denied_by_remote_epoch(self):
        """A privileged local-only snapshot rollback cannot reset live remote epoch.

        This is NOT immunity against simultaneous remote key/ledger rollback.
        Only the OS-local CORE/fence/attempt journals are reverted in CI;
        the independently running witness ledger retains its committed epoch.
        """
        import shutil
        local_fence=self.fixture.fence_dir/"recipient-one-effect-intents.sqlite3"
        host_attempt=self.fixture.attempt_dir/"signed-witness-attempts.sqlite3"
        snap_fence=self.root/"fence-prior.sqlite3"
        snap_attempt=self.root/"attempt-prior.sqlite3"
        shutil.copy2(local_fence,snap_fence)
        shutil.copy2(host_attempt,snap_attempt)

        first,server=self.serve()
        patches=self._connect_scope()
        with patches[0],patches[1],patches[2]:
            initial=self.fixture._file(self.fixture.fence(),self.folder)
        server.join(timeout=8)
        self.assertNotIn("error",first)
        self.assertEqual(initial["status"],"ONE_INERT_CI_FILE_AFTER_SIGNED_REMOTE_ACK")
        self.assertEqual(inspect_external_highwater(self.db)["highest_committed_epoch"],1)

        # Simulate local elevated actor restoring only rollback-prone storage.
        # A real independently administered witness remains at epoch 1.
        shutil.copy2(snap_fence,local_fence)
        shutil.copy2(snap_attempt,host_attempt)
        self.assertEqual(self.fixture.stage(),[])
        other=self.fixture._fixed_ci_output()
        second,second_server=self.serve()
        patches=self._connect_scope()
        with patches[0],patches[1],patches[2]:
            with self.assertRaises(RecipientFenceUnknown):
                self.fixture._file(self.fixture.fence(),other)
        second_server.join(timeout=8)
        self.assertFalse(second_server.is_alive())
        self.assertFalse((other/"windows_pilot.txt").exists())
        self.assertEqual(inspect_external_highwater(self.db)["highest_committed_epoch"],1)
        self.assertEqual(inspect_external_highwater(self.db)["reserved_operations"],1)
        self.assertNotIn("value",second)
        print("NF_LOCAL_SNAPSHOT_ROLLBACK_WITH_REMOTE_HIGHWATER_RETAINED=DENIED_CI_ONLY")


if __name__=="__main__":
    unittest.main(verbosity=2)
