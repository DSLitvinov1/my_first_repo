"""REVIEW-only one concurrency-negative on CORE pinned SHA cbe2bb0e...
A separate SQLite writer tries to coherently replace the spec while the
reader holds a metadata snapshot. No model, live code edits or paid calls.
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
from unittest.mock import patch

CORE_PATH=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(CORE_PATH))
from one_task_core import CoreSafetyError, _canonical
from independent_external_anchor_20261015 import prepare

with tempfile.TemporaryDirectory() as temporary:
    q=prepare(pathlib.Path(temporary))
    pinned_before=q.checkpoint_fingerprint()
    original_file=q._file
    worker_ready=threading.Event()
    commit_finished=threading.Event()
    unexpected=[]
    started=[]

    def untrusted_writer():
        try:
            con=sqlite3.connect(str(q.db),timeout=6,isolation_level=None)
            con.execute("PRAGMA busy_timeout=6000")
            con.execute("BEGIN IMMEDIATE")
            spec=json.loads(con.execute("SELECT spec FROM single_job WHERE singleton=1").fetchone()[0])
            spec["objective"]="COHERENT FORGED SPEC DURING EXTERNAL ANCHOR READ"
            raw=_canonical(spec)
            con.execute("UPDATE single_job SET spec=?,spec_sha256=? WHERE singleton=1",
                        (raw.decode("utf8"),hashlib.sha256(raw).hexdigest()))
            worker_ready.set()
            con.execute("COMMIT")
            commit_finished.set()
            con.close()
        except Exception as exc:
            unexpected.append(type(exc).__name__+":"+str(exc))
            worker_ready.set()

    def pause_read_at_first_file_lookup(*args,**kwargs):
        assert not started, "Only one file lookup in one checkpoint read expected"
        started.append(True)
        t=threading.Thread(target=untrusted_writer,daemon=True)
        t.start()
        threads.append(t)
        assert worker_ready.wait(3), "Competing sqlite writer never acquired its reserved write"
        assert not unexpected,unexpected
        assert not commit_finished.wait(0.2), (
            "Writer managed to COMMIT coherent metadata replacement before snapshot ended"
        )
        print("REVIEW_CONCURRENT_SPEC_COMMIT_WHILE_READ_HELD=BLOCKED")
        return original_file(*args,**kwargs)

    threads=[]
    with patch.object(q,"_file",side_effect=pause_read_at_first_file_lookup):
        fingerprint_during_race=q.checkpoint_fingerprint()
    assert fingerprint_during_race==pinned_before, (
        "In-flight one-shot snapshot returned a cross-version digest"
    )
    assert len(threads)==1
    threads[0].join(timeout=5)
    assert commit_finished.is_set(), "Writer did not complete after reader released SQLite snapshot"
    assert not unexpected,unexpected
    print("REVIEW_AFTER_SNAPSHOT_RELEASE_SPEC_FORGERY=COMMITTED")

    try:
        q.check_external_checkpoint(pinned_before)
    except CoreSafetyError:
        print("REVIEW_OLD_PINNED_ANCHOR_AFTER_CONCURRENT_FORGERY=REJECTED")
    else:
        raise AssertionError("Forged SQLite spec accepted after mismatch with old digest")
    print("REVIEW_EXTERNAL_ISSUER=NOT_DEPLOYED")
    print("REVIEW_SCOPE=SQLITE_SNAPSHOT_ATOMICITY_ONLY_NOT_FILESYSTEM_OR_ORIGIN")
