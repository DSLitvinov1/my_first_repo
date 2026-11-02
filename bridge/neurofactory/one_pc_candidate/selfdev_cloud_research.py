"""Safe local-Qwen research proposals for NEUROFACTORY, NEVER auto-apply.

This is a constrained, unprivileged cloud-lab researcher, not a self-modifying
production agent. All prompt text is fixed in the trusted source. No code from
the model is executed, no Git modifications, no PRs and no tool calls by Qwen.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time

QWEN_MODEL_SHA256 = "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031"
LLAMA_CLI_SHA256 = "094d4c5499543584e8d253cb1c8b9a2e4bc6d15b71b299befd54184210db5bc0"
MODEL_NAME = "Qwen/Qwen3-0.6B-GGUF:Q8_0"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
TASKS = {
    "host_recovery": (
        "Проверь замысел защиты от повторов после сбоев: локальный "
        "неизменяемый журнал плюс независимый сервер highwater. "
        "Предложи ОДИН конкретный сценарий отказного тестирования."
    ),
    "selfdev_review": (
        "Предложи ОДИН конкретный способ выявить опасное изменение, "
        "предлагаемое моделью Qwen, ДО ручного одобрения человеком."
    ),
    "installer_rollback": (
        "Предложи ОДИН конкретный тест, показывающий, что обновление "
        "Windows-установщика не обходит подпись и защиту от отката."
    ),
}
PROMPT_HEAD = (
    "/no_think\nТы исследователь безопасности НЕЙРОЗАВОДА. "
    "Тебе НЕ предоставлены права на выполнение программ, изменение файлов, "
    "публикацию, подтверждение релиза, запуск HOST или использование сетевых инструментов. "
    "Ответ — недоверенное предложение для отдельного тестирования человеком. "
    "Не утверждай, что что-то уже проверено или установлено. "
    "Напиши по-русски не более 90 слов: риск, один проверяемый тест, критерий PASS/FAIL.\n"
)

class ResearchDenied(ValueError):
    pass

def _deny(reason):
    raise ResearchDenied("Qwen cloud research refused: " + reason)

def _digest_file(p: Path):
    h = sha256()
    with p.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def _checked(path, *, executable=False, directory=False):
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _deny("absolute unlinked local paths required")
    try:
        st = path.lstat()
    except OSError as exc:
        raise ResearchDenied("missing approved local file") from exc
    if directory:
        if not stat.S_ISDIR(st.st_mode):
            _deny("expected directory")
    elif not stat.S_ISREG(st.st_mode) or (executable and not os.access(path, os.X_OK)):
        _deny("expected regular executable/model file")
    if st.st_mode & 0o002:
        _deny("world-writable input denied")
    return path

def _git_head(repo):
    try:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=True)
        status = subprocess.run(
            ["/usr/bin/git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ResearchDenied("immutable local source not verified") from exc
    head = result.stdout.decode("ascii", "strict").strip()
    if not SHA40.fullmatch(head) or status.stdout:
        _deny("source SHA or clean tracked checkout required")
    return head

def extract_answer(stdout, prompt):
    if not isinstance(stdout, str) or len(stdout) > 22000:
        _deny("invalid model response size")
    # llama-cli prints the exact user prompt followed by output and the
    # independent performance footer. This is data, NEVER a shell command.
    marker = chr(10) + "> /no_think"
    start = stdout.rfind(marker)
    if start < 0:
        _deny("model request boundary not observed")
    tail = stdout[start:]
    anchor = tail.find(prompt)
    if anchor >= 0:
        body = tail[anchor + len(prompt):]
    else:
        # llama.cpp's interactive console abbreviates long ECHOED prompts
        # with a fixed literal; never treat truncated prompt as an answer.
        delim = " ... (truncated)" + chr(10)
        cut = tail.find(delim)
        if cut < 0:
            _deny("model request echo not verifiable")
        body = tail[cut + len(delim):]
    body = body.split("[ Prompt:", 1)[0]
    body = body.replace("\r", "").strip()
    if (not 15 <= len(body.encode("utf-8")) <= 5000 or
        "\x00" in body or any(ord(ch) < 9 for ch in body)):
        _deny("empty, oversized or control-character model answer")
    return body

def run_one(*, repo: Path, lab: Path, model: Path, executable: Path,
            task: str, timestamp=None, runner=None):
    """One read-only AI idea, saved as untrusted evidence in a private lab."""
    if os.name != "posix" or os.geteuid() == 0:
        _deny("non-root Linux lab only")
    if task not in TASKS or type(task) is not str:
        _deny("task not independently allowlisted")
    for folder in (repo, lab, model.parent, executable.parent):
        _checked(folder, directory=True)
    _checked(model)
    _checked(executable, executable=True)
    if repo.resolve().is_relative_to(lab.resolve()):
        _deny("Git checkout must not be inside writable evidence directory")
    if _digest_file(model) != QWEN_MODEL_SHA256:
        _deny("Qwen model checksum not independently pinned")
    if _digest_file(executable) != LLAMA_CLI_SHA256:
        _deny("CPU runtime checksum not independently pinned")
    head = _git_head(repo)
    prompt = PROMPT_HEAD + "Точный исходный Git SHA: " + head + "\nТема: " + TASKS[task]
    proc_args = [
        str(executable), "-m", str(model),
        "-c", "1024", "-n", "250", "-t", "3",
        "--temp", "0.1", "--simple-io", "--single-turn",
        "--no-display-prompt", "-p", prompt,
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(lab),
        "LD_LIBRARY_PATH": str(executable.parent),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    run = subprocess.run if runner is None else runner
    try:
        result = run(proc_args, cwd=str(lab), stdin=subprocess.DEVNULL,
                     capture_output=True, text=True, timeout=100, env=env,
                     check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ResearchDenied("local CPU inference failed; no candidate recorded") from exc
    if result.returncode != 0:
        _deny("inference exit code not successful")
    proposal = extract_answer(result.stdout, prompt)
    when = int(time.time()) if timestamp is None else timestamp
    if type(when) is not int or when <= 0:
        _deny("invalid evidence time")
    evidence = {
        "schema": "nf.selfdev.cloud_qwen_research_proposal.v1",
        "status": "UNTRUSTED_QWEN_RESEARCH_NO_APPLY",
        "task": task, "source_sha40": head, "created_unix": when,
        "model": MODEL_NAME,
        "model_sha256": QWEN_MODEL_SHA256,
        "runtime_sha256": LLAMA_CLI_SHA256,
        "prompt_sha256": sha256(prompt.encode("utf-8")).hexdigest(),
        "proposal": proposal,
        "proposal_sha256": sha256(proposal.encode("utf-8")).hexdigest(),
        "code_executed_from_model": False,
        "git_changed": False,
        "automatic_pr_created": False,
        "owner_reviewer_approval": False,
        "production_release_allowed": False,
        "host_task_effect_allowed": False,
    }
    name = "qwen-proposal-" + secrets.token_hex(16) + ".json"
    dest = lab / name
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    payload = (json.dumps(evidence, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))+"\n").encode("utf-8")
    fd = os.open(dest, flags, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(payload)
        out.flush()
        os.fsync(out.fileno())
    return dest, evidence

def main():
    a=argparse.ArgumentParser(description="One Qwen idea, never execution.")
    a.add_argument("--repo", type=Path, required=True)
    a.add_argument("--lab", type=Path, required=True)
    a.add_argument("--model", type=Path, required=True)
    a.add_argument("--executable", type=Path, required=True)
    a.add_argument("--task", choices=tuple(TASKS), required=True)
    opt=a.parse_args()
    destination, evidence=run_one(repo=opt.repo, lab=opt.lab,
        model=opt.model, executable=opt.executable, task=opt.task)
    print(json.dumps({"status":evidence["status"],"file":str(destination),
        "source_sha40":evidence["source_sha40"]},ensure_ascii=False))

if __name__ == "__main__":
    main()
