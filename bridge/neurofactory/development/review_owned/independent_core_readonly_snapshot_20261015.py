"""REVIEW-only independent read-only snapshot race on exact CORE ce619115...
Separate synthetic SQLite writer attempts a coherent spec change during
snapshot() file readback.  No real projects, models, or foreign source edits.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
from unittest.mock import patch

sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from one_task_core import _canonical
from independent_external_anchor_20261015 import prepare

with tempfile.TemporaryDirectory() as folder:
    q=prepare(Path(folder))
    before=q.snapshot()
    prior_receipt=before["receipt"]
    old_anchor=q.checkpoint_fingerprint()
    true_file=q._file
    writer_ready=threading.Event()
    writer_finished=threading.Event()
    info={"errors":[]}

    def adversary():
        try:
            with sqlite3.connect(q.db,timeout=6,isolation_level=None) as db:
                db.execute("PRAGMA busy_timeout=6000")
                db.execute("BEGIN IMMEDIATE")
                record=json.loads(db.execute("SELECT spec FROM single_job WHERE singleton=1").fetchone()[0])
                record["objective"]="REVIEW COHERENT MUTATION DURING READ-ONLY SNAPSHOT"
                raw=_canonical(record)
                db.execute("UPDATE single_job SET spec=?,spec_sha256=? WHERE singleton=1",
                           (raw.decode(),hashlib.sha256(raw).hexdigest()))
                writer_ready.set()
                db.execute("COMMIT")
                writer_finished.set()
        except Exception as exc:
            info["errors"].append(type(exc).__name__+":"+str(exc))
            writer_ready.set()

    threads=[]
    class CheckedFile:
        def __init__(self,file):self.file=file
        def exists(self):return self.file.exists()
        def read_bytes(self):
            thread=threading.Thread(target=adversary,daemon=True)
            threads.append(thread)
            thread.start()
            assert writer_ready.wait(3),"A separate SQLite writer did not reach COMMIT"
            assert not info["errors"],info["errors"]
            assert not writer_finished.wait(0.4), (
                "Coherent SQLite task spec mutation COMMITTED during snapshot file readback"
            )
            print("REVIEW_READONLY_SNAPSHOT_DB_WRITER_COMMIT=BLOCKED_DURING_FILE_READ")
            return self.file.read_bytes()

    def intercept(target,*args,**kwargs):
        return CheckedFile(true_file(target,*args,**kwargs))

    with patch.object(q,"_file",side_effect=intercept):
        snapshot=q.snapshot()
    assert snapshot["state"]=="CHECKPOINTED_TEST"
    assert snapshot["receipt"]==prior_receipt
    assert len(threads)==1
    threads[0].join(timeout=5)
    assert writer_finished.is_set() and not info["errors"],info
    print("REVIEW_WRITER_AFTER_READONLY_SNAPSHOT_COMMIT=SUCCEEDED")
    assert q.snapshot()["state"]=="CHECKPOINTED_TEST"
    try:
        q.check_external_checkpoint(old_anchor)
    except Exception as exc:
        assert type(exc).__name__=="CoreSafetyError",str(exc)
        print("REVIEW_OLD_EXTERNAL_DIGEST_AFTER_COHERENT_MUTATION=REJECTED")
    else:
        raise AssertionError("Old external digest incorrectly accepted new metadata")
    print("REVIEW_SCOPE=SINGLE_LOCAL_SQLITE_METADATA_READBACK_NOT_REAL_OS_OR_ISSUER")
