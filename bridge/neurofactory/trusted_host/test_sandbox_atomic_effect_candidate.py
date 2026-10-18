"""Disposable PostgreSQL + signed-four-party + real fsync sandbox effect tests.

No user machine, public listener, production keys, permanent service or queue.
Witness double is NOT off-machine durable hardware; all results remain test-only.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import psycopg

from sandbox_atomic_effect_candidate import (
    apply_sandbox_once, SandboxDenied, SandboxEffectUnknown,
)
from test_db_bound_four_party_preflight import (
    DSN, DB_NAME, SCHEMA_PATH, SQLSignedEffectsE2E,
)
from test_independent_four_party_scope import FourPartyScopeTests, NOW


class WitnessDouble:
    def __init__(self):
        self.reservations = set()
        self.reject = False
        self.bad_ack = False

    def reserve_precommit(self, *, scope_sha256, operation_id,
                          commit_sequence, journal_root_sha256):
        if self.reject:
            raise ValueError("external witness unavailable")
        key = (scope_sha256, operation_id)
        if key in self.reservations:
            raise ValueError("replayed externally reserved operation")
        # Deliberately durable across the test's simulated database rollback.
        self.reservations.add(key)
        result = dict(
            status="DURABLY_RESERVED_TEST_ONLY",
            scope_sha256=scope_sha256,
            operation_id=operation_id,
            commit_sequence=commit_sequence,
            journal_root_sha256=journal_root_sha256,
        )
        if self.bad_ack:
            result["journal_root_sha256"] = "f" * 64
        return result


class AtomicSandboxCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.environ.get("NF_DB_SCHEMA_CI_ONLY") != "1" or
                os.environ.get("NF_ATOMIC_TEST_ONLY") != "1"):
            raise RuntimeError("refuse to touch non-disposable PostgreSQL")
        cls.db = psycopg.connect(DSN, autocommit=True, connect_timeout=5)
        cls.addClassCleanup(cls.db.close)
        if cls.db.execute("SELECT current_database()").fetchone()[0] != DB_NAME:
            raise RuntimeError("unexpected DB")
        cls.db.execute(SCHEMA_PATH.read_text(encoding="utf8"))

    _seed = SQLSignedEffectsE2E._seed
    _insert_only_receipt = SQLSignedEffectsE2E._insert_only_receipt

    def setUp(self):
        self.db.execute(
            "TRUNCATE nf_trusted_host.effect_receipt, nf_trusted_host.lease_register CASCADE"
        )
        self.four = FourPartyScopeTests(
            methodName="test_positive_all_four_cryptographic_scopes_still_no_authority")
        self.four.setUp()
        self.scope = self.four.scope
        self.pins = dict(pinned_keys=self.four.pins, metadata=dict(
            repository=self.scope["repository"],
            github_user_id=self.scope["github_user_id"],
            repository_id=self.scope["repository_id"],
            live_execution_allowed=False,
        ))
        self._seed()
        self.directory = tempfile.TemporaryDirectory(prefix="nf-atomic-ci-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.file = self.root / "one_result.txt"
        self.witness = WitnessDouble()

    def run_effect(self, *, conn=None, docs=None, content=b"content",
                   crash=False, root=None, witness=None):
        packets = self.four.packets if docs is None else docs
        with patch("db_bound_four_party_preflight.load_operator_installed_public_pins",
                   return_value=self.pins):
            return apply_sandbox_once(
                self.db if conn is None else conn,
                expected_effect=self.scope,
                signed_operator_acl=packets["operator"],
                signed_owner_grant=packets["owner"],
                signed_host_lease=packets["host"],
                signed_external_witness=packets["witness"],
                now_unix=NOW,
                content=content,
                sandbox_root=self.root if root is None else root,
                witness=self.witness if witness is None else witness,
                inject_crash_after_fsync=crash,
            )

    def record(self):
        return self.db.execute(
            "SELECT status,receiver_file_sha256 FROM nf_trusted_host.effect_receipt"
        ).fetchone()

    def test_one_real_exclusive_file_and_completed_receipt(self):
        result = self.run_effect()
        self.assertEqual(result["status"], "SANDBOX_FILE_AND_SQL_COMPLETED_TEST_ONLY")
        self.assertEqual(self.file.read_bytes(), b"content")
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.record(), ("COMPLETED", self.scope["content_sha256"]))
        self.assertEqual(self.db.execute(
            "SELECT state FROM nf_trusted_host.lease_register").fetchone(), ("COMPLETED",))
        self.assertEqual(len(self.witness.reservations), 1)
        for key in ("live_execution_allowed", "automatic_retry_allowed",
                    "release_approved", "real_external_witness_attested"):
            self.assertIs(result[key], False)

    def test_expired_lease_blocks_before_witness_and_file(self):
        self.db.execute(
            "UPDATE nf_trusted_host.lease_register "
            "SET lease_deadline=clock_timestamp()-interval '1 second'")
        with self.assertRaises(SandboxDenied):
            self.run_effect()
        self.assertFalse(self.file.exists())
        self.assertFalse(self.witness.reservations)
        self.assertEqual(self.record()[0], "UNKNOWN")

    def test_forged_owner_blocks_before_witness_and_file(self):
        p = dict(self.four.packets)
        p["owner"] = dict(p["owner"], signature_base64="A" * 88)
        with self.assertRaises(SandboxDenied):
            self.run_effect(docs=p)
        self.assertFalse(self.witness.reservations)
        self.assertFalse(self.file.exists())

    def test_duplicate_after_success_denied_no_second_effect(self):
        self.run_effect()
        with self.assertRaises(SandboxDenied):
            self.run_effect()
        self.assertEqual(self.file.read_bytes(), b"content")
        self.assertEqual(len(self.witness.reservations), 1)

    def test_crash_after_fsync_is_unknown_and_never_retried(self):
        with self.assertRaises(SandboxEffectUnknown):
            self.run_effect(crash=True)
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(self.file.read_bytes(), b"content")
        self.assertEqual(len(self.witness.reservations), 1)
        with self.assertRaises((SandboxDenied, SandboxEffectUnknown)):
            self.run_effect()
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(self.file.read_bytes(), b"content")

    def test_witness_unavailable_or_ack_lost_is_unknown_no_retry(self):
        # A remote timeout does NOT prove reservation failed.
        self.witness.reject = True
        with self.assertRaises(SandboxEffectUnknown):
            self.run_effect()
        self.assertFalse(self.file.exists())
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.witness.reject = False
        self.witness.bad_ack = True
        with self.assertRaises(SandboxEffectUnknown):
            self.run_effect()
        self.assertFalse(self.file.exists())
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(len(self.witness.reservations), 1)
        self.witness.bad_ack = False
        with self.assertRaises(SandboxEffectUnknown):
            self.run_effect()
        self.assertFalse(self.file.exists())
        self.assertEqual(len(self.witness.reservations), 1)

    def test_database_receipt_failure_after_fsync_remains_unknown(self):
        self.db.execute("""
            CREATE FUNCTION nf_trusted_host.deny_completion_ci()
            RETURNS trigger LANGUAGE plpgsql AS $
            BEGIN RAISE EXCEPTION 'simulated receipt failure'; END; $""")
        self.db.execute("""
            CREATE TRIGGER nf_ci_deny_receipt BEFORE UPDATE
            ON nf_trusted_host.effect_receipt FOR EACH ROW
            EXECUTE FUNCTION nf_trusted_host.deny_completion_ci()""")
        try:
            with self.assertRaises(SandboxEffectUnknown):
                self.run_effect()
        finally:
            self.db.execute("DROP TRIGGER nf_ci_deny_receipt "
                            "ON nf_trusted_host.effect_receipt")
            self.db.execute("DROP FUNCTION nf_trusted_host.deny_completion_ci()")
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(self.file.read_bytes(), b"content")
        self.assertEqual(len(self.witness.reservations), 1)
        with self.assertRaises(SandboxEffectUnknown):
            self.run_effect()
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(self.file.read_bytes(), b"content")

    def test_old_database_snapshot_with_witness_highwater_blocks_replay(self):
        self.run_effect()
        self.assertEqual(len(self.witness.reservations), 1)
        # Privileged database/local-file rollback is simulated explicitly.
        # Witness is separate state and is NOT restored with the SQL snapshot.
        self.db.execute("TRUNCATE nf_trusted_host.effect_receipt")
        self.db.execute("UPDATE nf_trusted_host.lease_register SET state='CLAIMED'")
        self._insert_only_receipt()
        self.file.unlink()
        with self.assertRaises(SandboxDenied):
            self.run_effect()
        self.assertFalse(self.file.exists())
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(len(self.witness.reservations), 1)

    def test_separate_session_nowait_row_lock_denies_competing_worker(self):
        with psycopg.connect(DSN, autocommit=True, connect_timeout=5) as other:
            with self.db.transaction():
                self.db.execute(
                    "SELECT task_id FROM nf_trusted_host.lease_register "
                    "WHERE task_id=%s FOR UPDATE", (self.scope["task_id"],))
                with self.assertRaises(SandboxDenied):
                    self.run_effect(conn=other)
                self.assertFalse(self.file.exists())
                self.assertFalse(self.witness.reservations)
        self.assertEqual(self.record()[0], "UNKNOWN")

    def test_existing_file_is_never_overwritten(self):
        self.file.write_bytes(b"old-sentinel")
        with self.assertRaises(SandboxEffectUnknown):
            self.run_effect()
        self.assertEqual(self.file.read_bytes(), b"old-sentinel")
        self.assertEqual(self.record()[0], "UNKNOWN")
        self.assertEqual(len(self.witness.reservations), 1)

    def test_symlink_root_is_rejected_before_witness(self):
        link = self.root.parent / (self.root.name + "-link")
        try:
            link.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(SandboxDenied):
                self.run_effect(root=link)
            self.assertFalse(self.witness.reservations)
        finally:
            link.unlink(missing_ok=True)

    def test_never_operates_without_explicit_disposable_gate(self):
        with patch.dict(os.environ, {"NF_ATOMIC_TEST_ONLY": "0"}):
            with self.assertRaises(SandboxDenied):
                self.run_effect()
        self.assertFalse(self.file.exists())
        self.assertFalse(self.witness.reservations)

    def test_content_mismatch_does_not_touch_sql_or_witness(self):
        with self.assertRaises(SandboxDenied):
            self.run_effect(content=b"attacker-data")
        self.assertFalse(self.file.exists())
        self.assertFalse(self.witness.reservations)
        self.assertEqual(self.record()[0], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
