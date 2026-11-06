"""Actual cloud Qwen draft generation over a dedicated forced-command SSH key.

Runs ONLY under the existing unprivileged Linux cloudagent account. This
program cannot execute proposed user/model commands or operate CORE/HOST.
Each immutable task ID consumes one durable attempt BEFORE running a model.
SSH forced-command/authorized_keys is provisioned separately, with all
forwarding, PTY and shell disabled. No paid API.
"""
from __future__ import annotations

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

ROOT = Path("/home/cloudagent/neurofactory-lab/cloud-qwen-draft-20261105")
MODEL = Path("/home/cloudagent/neurofactory-lab/models/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf")
LLAMA = Path("/home/cloudagent/neurofactory-lab/bin/llama-b12040/llama-cli")
MODEL_SHA = "cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046"
MODEL_NAME = "qwen2.5-coder:1.5b"
MODEL_Q35_NAME = "qwen3.5:9b"
MODEL_Q35 = Path("/home/cloudagent/neurofactory-lab/models/qwen3.5-9b-instruct-q4_k_m.gguf")
MODEL_Q35_SHA = "cd76ec205963b3b33350093e6904d9de16c4e666fd104e1f632d25c7f15f2a13"
# The existing 1.5B model remains a selectable, independently hash-checked
# fallback. No model may be selected by a free-form path from the client.
MODELS = {MODEL_Q35_NAME: (MODEL_Q35, MODEL_Q35_SHA),
          MODEL_NAME: (MODEL, MODEL_SHA)}
REQ_SCHEMA = "nf.cloud.qwen.one_draft_request.v1"
RES_SCHEMA = "nf.cloud.qwen.one_draft_result.v1"
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
ONE_REQUEST_LIMIT = 4096


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)


def denied(code, model=MODEL_NAME):
    emit({"schema": RES_SCHEMA, "status": "UNKNOWN", "error_code": code,
          "model": model, "automatic_retry_allowed": False,
          "execution_allowed": False})
    return 1


def _unique(items):
    value = {}
    for k, v in items:
        if k in value:
            raise ValueError("duplicate key")
        value[k] = v
    return value


def _validate(message):
    if (type(message) is not dict or set(message) !=
            {"schema", "task_id", "project_id", "objective", "model", "nonce"} or
            message["schema"] != REQ_SCHEMA or
            message["model"] not in MODELS or
            any(type(message[key]) is not str or not HEX32.fullmatch(message[key])
                for key in ("task_id", "project_id", "nonce")) or
            type(message["objective"]) is not str or
            not 15 <= len(message["objective"]) <= 1200 or
            any(ord(c) < 32 and c not in "\n\t"
                for c in message["objective"])):
        raise ValueError("invalid model request")
    return message


def _hash_model_once(model_name):
    hashed = sha256()
    model_path, expected_sha = MODELS[model_name]
    if not model_path.is_file() or model_path.is_symlink() or not LLAMA.is_file():
        raise RuntimeError("missing model")
    with model_path.open("rb") as file:
        while True:
            chunk = file.read(1 << 20)
            if not chunk:
                break
            hashed.update(chunk)
    if hashed.hexdigest() != expected_sha:
        raise RuntimeError("wrong model digest")
    return model_path, expected_sha


def _reserve_exactly_once(message):
    db = ROOT / "model-attempts.sqlite3"
    if not db.is_file() or db.is_symlink():
        raise RuntimeError("operator-provisioned ledger missing")
    with sqlite3.connect(db.as_uri() + "?mode=rw", uri=True, timeout=4) as con:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT INTO attempts(task_id, project_id, request_sha256, status) VALUES(?,?,?,?)",
                    (message["task_id"], message["project_id"],
                     sha256(json.dumps(message, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")).hexdigest(),
                     "UNKNOWN_NO_AUTO_RETRY"))
        con.commit()


def main():
    os.umask(0o077)
    if os.environ.get("SSH_ORIGINAL_COMMAND"):
        return denied("REMOTE_COMMAND_NOT_ALLOWED")
    if not ROOT.is_dir() or ROOT.is_symlink() or (ROOT.stat().st_mode & 0o077):
        return denied("SERVER_NOT_PROVISIONED")
    try:
        raw = sys.stdin.buffer.read(ONE_REQUEST_LIMIT + 1)
        if not 2 <= len(raw) <= ONE_REQUEST_LIMIT:
            return denied("REQUEST_SIZE")
        message = _validate(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique))
    except (UnicodeError, ValueError, KeyError, TypeError):
        return denied("BAD_REQUEST")
    lock_path = ROOT / "model-one-at-a-time.lock"
    try:
        with lock_path.open("a+b") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return denied("MODEL_BUSY_NO_RETRY")
            # Reserve before any model load; errors must NEVER repeat the same ID.
            try:
                _reserve_exactly_once(message)
            except (OSError, sqlite3.Error, RuntimeError):
                return denied("DUPLICATE_OR_LEDGER_UNAVAILABLE")
            try:
                model_path, model_sha = _hash_model_once(message["model"])
                prompt = (
                    "Ты помощник разработчика. Создай полезный краткий ЧЕРНОВИК ответа "
                    "на задачу пользователя. Ничего не запускай, не меняй файлы, "
                    "не утверждай, что задача выполнена. Верни только текст предложения.\n"
                    "Задача:\n" + message["objective"] + "\nОтвет:\n"
                )
                if message["model"] == MODEL_Q35_NAME:
                    # New 9B on 8 shared vCPU: capped context, single-request
                    # lock, no agent/tool authority and no internal reasoning
                    # spill into a user's saved draft. Existing 1.5B unchanged.
                    args = [str(LLAMA), "-m", str(model_path), "-p", prompt,
                            "-n", "160", "-c", "4096", "-t", "5", "-tb", "5",
                            "-ngl", "0", "--temp", "0.15",
                            "-st", "--no-display-prompt", "--no-warmup",
                            "--log-disable", "--color", "off",
                            "--jinja", "--reasoning", "off",
                            "--chat-template-kwargs", '{"enable_thinking":false}']
                    timeout = 180
                else:
                    args = [str(LLAMA), "-m", str(model_path), "-p", prompt,
                            "-n", "320", "-c", "2048", "-t", "3",
                            "-ngl", "0", "--temp", "0.15",
                            "-st", "--no-display-prompt", "--no-warmup",
                            "--log-disable", "--color", "off"]
                    timeout = 90
                completed = subprocess.run(
                    args,
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=timeout, check=False,
                )
                # llama-cli prints a spinner, terminal control codes and a
                # model banner BEFORE the echoed prompt, even with
                # --no-display-prompt. Those are never model text. Accept
                # only the span after our exact operator-constructed prompt
                # and before CLI metrics/footer. If the framing changes,
                # fail closed rather than accepting terminal escape codes.
                # The CLI prints a ONE-LINE abbreviated prompt with literal
                # escaped newlines and "... (truncated)" for long inputs.
                # Matching the whole prompt would ALWAYS fail for user tasks.
                # Anchor on the first 96 chars of our exact known fixed
                # prompt, then discard the ENTIRE echoed prompt line.
                marker = "\n> " + prompt[:96]
                position = completed.stdout.rfind(marker)
                if completed.returncode != 0 or position < 0:
                    return denied("MODEL_STDOUT_FORMAT_UNKNOWN")
                line_end = completed.stdout.find("\n", position + len(marker))
                if line_end < 0:
                    return denied("MODEL_STDOUT_FORMAT_UNKNOWN")
                output = completed.stdout[line_end + 1:]
                if "\n[ Prompt:" not in output:
                    return denied("MODEL_STDOUT_FORMAT_UNKNOWN")
                output = output.split("\n[ Prompt:", 1)[0]
                output = output.split("\n\nExiting...", 1)[0]
                output = output.replace("<|im_end|>", "").strip()
                if (not 2 <= len(output.encode("utf-8")) <= 10000 or
                        any(ord(c) < 32 and c not in "\n\t" for c in output)):
                    return denied("MODEL_RESULT_UNKNOWN")
                digest = sha256(output.encode("utf-8")).hexdigest()
                emit({
                    "schema": RES_SCHEMA, "status": "PROPOSED_UNVERIFIED",
                    "model": message["model"], "model_sha256": model_sha,
                    "task_id": message["task_id"], "nonce": message["nonce"],
                    "text": output, "response_sha256": digest,
                    "execution_allowed": False, "automatic_retry_allowed": False,
                    "owner_signed": False,
                })
                with sqlite3.connect((ROOT / "model-attempts.sqlite3").as_uri() +
                                     "?mode=rw", uri=True, timeout=4) as con:
                    con.execute("UPDATE attempts SET status='PROPOSED_UNVERIFIED',"
                                " response_sha256=? WHERE task_id=?",
                                (digest, message["task_id"]))
                    con.commit()
                return 0
            except (subprocess.TimeoutExpired, OSError, sqlite3.Error,
                    RuntimeError, ValueError):
                return denied("MODEL_RESULT_UNKNOWN")
    except OSError:
        return denied("MODEL_LOCK_UNAVAILABLE")


if __name__ == "__main__":
    raise SystemExit(main())
