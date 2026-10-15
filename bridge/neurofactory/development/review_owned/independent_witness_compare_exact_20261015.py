"""REVIEW-owned exact-SHA negative checks for TEST-ONLY external witness comparator.
Independent from HOST author test suite. No live issuer, Qwen, workflow queue, or secrets.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from offline_highwater import OfflineHighwater
from offline_witness_compare import (
    OfflineWitnessError, compare_signed_witness_to_ephemeral_postgres,
)

TASK = "NF-DEV-05-Q997"
H0, H1, H2, H3 = ("0" * 64, "1" * 64, "2" * 64, "3" * 64)
SIGNER = Ed25519PrivateKey.generate()
PUBLIC_KEY = SIGNER.public_key()
expected = dict(
    expected_task_id=TASK, expected_project_id="review-sandbox",
    expected_core_sha40="a" * 40,
    expected_source_file_sha256="b" * 64,
    expected_input_task_sha256="c" * 64,
    expected_policy_sha256="d" * 64,
    expected_witness_identity="review-ephemeral",
    expected_witness_key_id="review-key-001",
    externally_pinned_next_witness_sequence=7,
    externally_pinned_previous_witness_sha256="e" * 64,
)
payload = dict(
    schema="neurofactory.trusted_host.offline_external_witness.v1",
    task_id=TASK, project_id="review-sandbox",
    input_core_sha40="a" * 40, source_file_sha256="b" * 64,
    input_task_sha256="c" * 64, policy_sha256="d" * 64,
    witness_identity="review-ephemeral", witness_key_id="review-key-001",
    witness_sequence=7, previous_witness_sha256="e" * 64,
    checkpoint_sequence=2, checkpoint_sha256=H2,
    issued_at_utc="2026-10-15T12:00:00Z",
    purpose="OFFLINE_CHECKPOINT_COMPARISON_ONLY",
)
FALSE_GATES = (
    "externally_pinned_key_provenance_attested",
    "externally_pinned_witness_sequence_durably_protected",
    "independent_host_operator_approval", "live_execution_allowed",
    "publication_allowed", "automatic_retry_allowed",
)

def sign(p=None, signer=None):
    p = copy.deepcopy(payload if p is None else p)
    data = json.dumps(p, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
    return {
        "payload": p,
        "signature_base64": base64.b64encode(
            (SIGNER if signer is None else signer).sign(data)
        ).decode("ascii"),
    }

def no_permission(result):
    assert all(result[x] is False for x in FALSE_GATES), result
    assert result["handoff"] == "PAUSED_BY_USER", result

def denied(fn, case):
    try:
        fn()
    except OfflineWitnessError:
        print("REVIEW_DENIED_" + case + "=YES")
        return
    raise AssertionError("Untrusted witness accepted: " + case)

with psycopg.connect(os.environ["REVIEW_ONLY_EPHEMERAL_PG_DSN"],
                     autocommit=True, connect_timeout=4) as conn:
    assert conn.execute("SELECT current_database()").fetchone() == ("nf_test",)
    conn.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    conn.execute((root / "schema_v1.sql").read_text())
    conn.execute((root / "offline_highwater_schema.sql").read_text())
    conn.execute(
        """INSERT INTO nf_task(task_id, project_id, input_core_sha40,
           source_file_sha256, input_task_sha256, fixture_authorized)
           VALUES(%s,%s,%s,%s,%s,FALSE)""",
        (TASK, "review-sandbox", "a"*40, "b"*64, "c"*64)
    )
    ledger = OfflineHighwater(conn)
    assert ledger.append(TASK, 1, H0, H1)["status"] == "RECORDED_TEST_ONLY"
    assert ledger.append(TASK, 2, H1, H2)["status"] == "RECORDED_TEST_ONLY"
    original = sign()
    def verify(witness=original, exp=expected, key=PUBLIC_KEY):
        return compare_signed_witness_to_ephemeral_postgres(
            conn, key, witness, **exp
        )
    def db_state():
        return (
            conn.execute(
                "SELECT last_sequence, last_digest_sha256 FROM nf_offline_chain_head WHERE task_id=%s",
                (TASK,)
            ).fetchone(),
            conn.execute(
                "SELECT sequence, prior_digest_sha256, receipt_digest_sha256 "
                "FROM nf_offline_chain_event WHERE task_id=%s ORDER BY sequence",
                (TASK,)
            ).fetchall()
        )
    before = db_state()
    good = verify()
    assert good["status"] == "SIGNED_WITNESS_MATCHES_TEST_DB"
    assert good["checkpoint_matches_signed_witness"] is True
    no_permission(good)
    assert db_state() == before, "read-only comparison modified ledger"
    print("REVIEW_SIGNED_CURRENT_WITNESS=LOCAL_MATCH_NONLIVE")
    print("REVIEW_WITNESS_COMPARISON_DB_WRITES=ZERO")

    for name, wrong in (
        ("SOURCE_SHA", {"expected_core_sha40": "f"*40}),
        ("SOURCE_FILE_DIGEST", {"expected_source_file_sha256": "f"*64}),
        ("INPUT_TASK_DIGEST", {"expected_input_task_sha256": "f"*64}),
        ("POLICY_DIGEST", {"expected_policy_sha256": "f"*64}),
        ("PROJECT", {"expected_project_id": "other-project"}),
        ("TASK", {"expected_task_id": "NF-DEV-05-Q996"}),
        ("WITNESS_ID", {"expected_witness_identity": "wrong-witness"}),
        ("KEY_ID", {"expected_witness_key_id": "wrong-key-123"}),
        ("PREVIOUS_DIGEST", {"externally_pinned_previous_witness_sha256": "f"*64}),
    ):
        denied(lambda x=wrong: verify(exp=dict(expected, **x)), name)
    denied(lambda: verify(key=Ed25519PrivateKey.generate().public_key()),
           "DIFFERENT_ED25519_KEY")
    denied(lambda: verify(witness=sign(signer=Ed25519PrivateKey.generate())),
           "FORGED_SIGNATURE")
    tampered = sign()
    tampered["payload"]["checkpoint_sha256"] = H3
    denied(lambda: verify(witness=tampered), "POST_SIGNING_TAMPER")
    for value, label in ((True, "BOOL"), (7.0, "FLOAT"), ("7", "STRING")):
        bad = dict(payload, witness_sequence=value)
        denied(lambda p=bad: verify(witness=sign(p)), "SEQUENCE_" + label)
    for field in ("owner_approved", "live_execution_allowed", "review_approved"):
        bad = dict(payload, **{field: True})
        denied(lambda p=bad: verify(witness=sign(p)), "INJECTED_" + field.upper())

    stale = dict(payload, witness_sequence=6)
    denied(lambda: verify(witness=sign(stale)), "STALE_WITNESS_WITH_PIN_7")
    self_pin = dict(expected, externally_pinned_next_witness_sequence=6)
    replayed = verify(witness=sign(stale), exp=self_pin)
    assert replayed["status"] == "SIGNED_WITNESS_MATCHES_TEST_DB"
    no_permission(replayed)
    print("REVIEW_SELF_CHOSEN_OLD_SIGNED_WITNESS=LOCAL_MATCH_NO_PROVENANCE")

    conn.execute(
        "DELETE FROM nf_offline_chain_event WHERE task_id=%s AND sequence=2",
        (TASK,)
    )
    conn.execute(
        "UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s "
        "WHERE task_id=%s", (H1, TASK)
    )
    rollback = verify()
    assert rollback["status"] == "UNKNOWN_OR_ROLLBACK"
    assert rollback["checkpoint_matches_signed_witness"] is False
    no_permission(rollback)
    print("REVIEW_COHERENT_ADMIN_ROLLBACK=UNKNOWN_OR_ROLLBACK_NONLIVE")
    assert ledger.append(TASK, 2, H1, H3)["status"] == "RECORDED_TEST_ONLY"
    fork = verify()
    assert fork["status"] == "UNKNOWN_OR_ROLLBACK"
    no_permission(fork)
    print("REVIEW_ALTERNATE_FORK_SAME_SEQUENCE=UNKNOWN_OR_ROLLBACK_NONLIVE")

    # Attacker with synthetic signing capability can self-select all inputs,
    # but the comparator MUST NEVER claim independently protected provenance.
    replacement = dict(payload, checkpoint_sha256=H3)
    replacement_receipt = sign(replacement)
    attacker_chosen = verify(witness=replacement_receipt)
    assert attacker_chosen["status"] == "SIGNED_WITNESS_MATCHES_TEST_DB"
    no_permission(attacker_chosen)
    print("REVIEW_SELF_REPINNED_FORK=LOCAL_MATCH_NO_PROVENANCE")
    print("REVIEW_PROTECTED_EXTERNAL_SIGNER_AND_IMMUTABLE_PIN=NOT_DEPLOYED")
    print("REVIEW_FINAL_VERDICT=APPROVE_NARROW_OFFLINE_COMPARISON_REJECT_LIVE")
