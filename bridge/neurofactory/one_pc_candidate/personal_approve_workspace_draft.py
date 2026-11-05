"""Interactive OWNER-only approval of ONE saved Qwen draft from workspace SQLite.

This is the trust boundary: model text is NOT execution authority. The owner
reads the exact text and types a task-specific approval in an interactive
terminal. There is no unattended, background or API signing path. The ONLY
available effect remains a Unicode note inside the protected host's outputs.

This file is intentionally never imported by the LocalService SCM.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from hashlib import sha256
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

from personal_approve_safe_note import approve_one_note

TASK_ID = re.compile(r"[a-f0-9]{32}\Z")
MODEL = "qwen2.5-coder:1.5b"


class DraftOwnerApprovalDenied(ValueError):
    pass


def owner_approvable_saved_draft(workspace_dir: Path, task_id: str) -> dict:
    if (os.name != "nt" or
            not isinstance(workspace_dir, Path) or
            not workspace_dir.is_absolute() or
            workspace_dir.is_symlink() or
            not workspace_dir.is_dir() or
            type(task_id) is not str or
            TASK_ID.fullmatch(task_id) is None):
        raise DraftOwnerApprovalDenied("Existing Windows user workspace and task ID required")
    db = workspace_dir / "workspace.sqlite3"
    if db.is_symlink() or not db.is_file() or db.stat().st_size < 512:
        raise DraftOwnerApprovalDenied("Workspace SQLite missing or redirected; refuse reset")
    try:
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro",
                                     uri=True, timeout=4)) as con:
            con.execute("PRAGMA query_only=ON")
            if con.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise DraftOwnerApprovalDenied("Workspace SQLite integrity damaged")
            item = con.execute(
                "SELECT t.id,t.project_id,t.objective,t.state,p.name,"
                "q.model,q.status,q.proposal_text,q.content_sha256 "
                "FROM tasks AS t "
                "JOIN projects AS p ON p.id=t.project_id "
                "JOIN task_proposals AS q ON q.task_id=t.id "
                "WHERE t.id=?",
                (task_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        raise DraftOwnerApprovalDenied("Cannot read immutable draft snapshot") from exc
    if (item is None or item[0] != task_id or
            type(item[1]) is not str or TASK_ID.fullmatch(item[1]) is None or
            type(item[2]) is not str or not 15 <= len(item[2]) <= 1200 or
            item[3] != "DRAFT_PENDING_OWNER_AUTH" or
            type(item[4]) is not str or not 3 <= len(item[4]) <= 100 or
            item[5] != MODEL or item[6] != "PROPOSED_UNVERIFIED" or
            type(item[7]) is not str or
            not 1 <= len(item[7].encode("utf-8")) <= 2048 or
            type(item[8]) is not str or
            sha256(item[7].encode("utf-8")).hexdigest() != item[8] or
            any(ord(c) < 32 and c not in "\n\t" for c in item[7])):
        raise DraftOwnerApprovalDenied(
            "Only intact previously saved Qwen Coder draft can be considered"
        )
    return {
        "task_id": item[0],
        "project_id": item[1],
        "objective": item[2],
        "project_name": item[4],
        "text": item[7],
        "text_sha256": item[8],
    }


def approve_interactively(workspace_dir: Path, owner_folder: Path,
                          task_id: str, epoch: int) -> dict:
    if (not sys.stdin.isatty() or not sys.stdout.isatty() or
            type(epoch) is not int or not 1 <= epoch < 2 ** 62):
        raise DraftOwnerApprovalDenied(
            "Human interactive desktop and explicit expected epoch required"
        )
    item = owner_approvable_saved_draft(workspace_dir, task_id)
    print("\nНЕЙРОЗАВОД: ПРОВЕРКА ПЕРЕД ОДНОЙ ЗАПИСЬЮ", flush=True)
    print("Проект:", item["project_name"], flush=True)
    print("Задача:", item["objective"], flush=True)
    print("Идентификатор:", item["task_id"], flush=True)
    print("Следующий номер защищённой операции:", epoch, flush=True)
    print("SHA256 полного черновика:", item["text_sha256"], flush=True)
    print("\n----- ПОЛНЫЙ ТЕКСТ ПРЕДЛОЖЕНИЯ QWEN -----", flush=True)
    print(item["text"], flush=True)
    print("----- КОНЕЦ ПРЕДЛОЖЕНИЯ -----\n", flush=True)
    code = "ПОДТВЕРЖДАЮ " + task_id[:8]
    if input("Чтобы сохранить ЭТОТ текст в защищённую папку, введите "
             + code + ": ").strip() != code:
        raise DraftOwnerApprovalDenied("Owner did not approve exact proposal")
    # Re-open the SQLite snapshot after human review. Any changed model text,
    # project, digest or objective invalidates the confirmation.
    current = owner_approvable_saved_draft(workspace_dir, task_id)
    if current != item:
        raise DraftOwnerApprovalDenied("Draft changed while awaiting human approval")
    if not owner_folder.is_absolute() or owner_folder.is_symlink():
        raise DraftOwnerApprovalDenied("Owner private key folder not canonical")
    # The trusted signer already accepts a fixed owner-selected text-file
    # payload; keep a transient private UTF-8 file ONLY in the user's
    # dedicated signing directory and never publish it to CORE/SSH.
    with tempfile.TemporaryDirectory(prefix="draft-approval-", dir=owner_folder) as name:
        temporary = Path(name) / "text.txt"
        with temporary.open("xb") as file:
            file.write(current["text"].encode("utf-8"))
            file.flush()
            os.fsync(file.fileno())
        result = approve_one_note(
            owner_folder=owner_folder, task_id=task_id,
            project_id=current["project_id"],
            text_file=temporary, epoch=epoch,
        )
    return {
        "status": result["status"],
        "task_id": task_id,
        "remote_witness_result": result["remote_witness_result"],
        "automatic_execution_permitted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--expected-epoch", required=True, type=int)
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("Interactive Windows user only")
    workspace = Path(os.environ.get("LOCALAPPDATA", "")) / "NeurofactoryData"
    owner = workspace / "owner-signing"
    print(approve_interactively(workspace, owner, args.task_id,
                                args.expected_epoch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
