"""Local Qwen worker candidate for the CORE->PROVIDERS boundary.

This module never writes source files or approves proposals.  It only reads a
locally-installed Ollama model and returns an untrusted candidate + digests.
No model pulls, cloud API, subprocess, retries, or automatic publication.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from durable_budget import DurableBudget, DurableBudgetError
from local_qwen import (
    ALLOWED_MODELS, LocalQwenAdapter, LocalQwenConfig,
    LocalProviderDisabled, LocalProviderUnknownResult,
    _no_duplicate_pairs,
)

TAGS_URL = "http://127.0.0.1:11434/api/tags"
ONE_GIB = 1024 ** 3
MAX_TAG_BYTES = 65536
SCHEMA_REQUEST = "neurofactory.providers.request.v1"
SCHEMA_RESULT = "neurofactory.providers.result.v1"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
LOWER_SHA = re.compile(r"[0-9a-f]{64}\Z")


class PreflightBlocked(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PreflightBlocked("BLOCKED_REDIRECT")


def physical_free_memory_bytes() -> int:
    """Actual currently available physical RAM, or zero if unknown."""
    try:
        if os.name == "nt":
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            state = MEMORYSTATUSEX()
            state.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
                return 0
            return int(state.ullAvailPhys)
        page = os.sysconf("SC_PAGE_SIZE")
        available_pages = os.sysconf("SC_AVPHYS_PAGES")
        if type(page) is not int or type(available_pages) is not int:
            return 0
        return max(0, page * available_pages)
    except (OSError, ValueError, AttributeError):
        return 0


def installed_model_info(model: str) -> dict:
    """GET tags on literal IPv4 loopback; does not load or download models."""
    if model not in ALLOWED_MODELS:
        raise PreflightBlocked("BLOCKED_MODEL_NOT_ALLOWED")
    req = Request(TAGS_URL, method="GET")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=3) as response:
            if response.status != 200:
                raise PreflightBlocked("BLOCKED_OLLAMA_UNAVAILABLE")
            raw = response.read(MAX_TAG_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise PreflightBlocked("BLOCKED_OLLAMA_UNAVAILABLE") from exc
    if len(raw) > MAX_TAG_BYTES:
        raise PreflightBlocked("BLOCKED_OLLAMA_UNTRUSTED_TAGS")
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate_pairs)
    except (ValueError, UnicodeError) as exc:
        raise PreflightBlocked("BLOCKED_OLLAMA_UNTRUSTED_TAGS") from exc
    if type(data) is not dict or type(data.get("models")) is not list:
        raise PreflightBlocked("BLOCKED_OLLAMA_UNTRUSTED_TAGS")
    matches = [x for x in data["models"]
               if type(x) is dict and x.get("name") == model]
    if len(matches) != 1:
        raise PreflightBlocked("BLOCKED_MODEL_NOT_INSTALLED")
    entry = matches[0]
    size = entry.get("size")
    if type(size) is not int or not 1_000_000 <= size <= 30 * ONE_GIB:
        raise PreflightBlocked("BLOCKED_OLLAMA_UNTRUSTED_TAGS")
    # The model name is an exact local allowlist tag. A tags listing alone is
    # not independent proof of authentic model weights or genuine inference.
    return {"model": model, "model_disk_bytes": size}


def check_resources(model: str) -> dict:
    info = installed_model_info(model)
    available = physical_free_memory_bytes()
    # Deliberately conservative. Disk model size is only a proxy for memory.
    minimum = max(2 * ONE_GIB, (info["model_disk_bytes"] * 2) + 512 * 1024 ** 2)
    info["free_ram_bytes"] = available
    info["required_ram_bytes"] = minimum
    if not available or available < minimum:
        raise PreflightBlocked("BLOCKED_RESOURCE")
    return info


def validate_target(path: str) -> str:
    if type(path) is not str or not 1 <= len(path) <= 160:
        raise ValueError("bad target path")
    if "\\" in path or ":" in path or "\x00" in path or path.startswith("/"):
        raise ValueError("unsafe target path")
    posix = PurePosixPath(path)
    if (not path.startswith(("src/", "docs/", "bridge/neurofactory/development/core_owned/")) or
            any(not part or part in (".", "..") or part.startswith(".") for part in path.split("/")) or
            not re.fullmatch(r"[A-Za-z0-9_./-]+", path) or
            posix.suffix not in (".py", ".md", ".txt", ".json")):
        raise ValueError("target outside approved sandbox namespace")
    return path


@dataclass(frozen=True)
class ProviderTask:
    task_id: str
    project_id: str
    input_sha256: str
    target_path: str
    instruction: str
    schema: str = SCHEMA_REQUEST

    def __post_init__(self):
        if self.schema != SCHEMA_REQUEST:
            raise ValueError("unknown request schema")
        if not isinstance(self.task_id, str) or not SAFE_ID.fullmatch(self.task_id):
            raise ValueError("invalid task id")
        if not isinstance(self.project_id, str) or not SAFE_ID.fullmatch(self.project_id):
            raise ValueError("invalid project id")
        if not isinstance(self.input_sha256, str) or not LOWER_SHA.fullmatch(self.input_sha256):
            raise ValueError("invalid input digest")
        validate_target(self.target_path)
        if (type(self.instruction) is not str or
                not 1 <= len(self.instruction.strip()) <= 4000):
            raise ValueError("invalid instruction")

    @classmethod
    def from_json(cls, data: dict):
        if type(data) is not dict or set(data) != {
            "schema", "task_id", "project_id", "input_sha256",
            "target_path", "instruction"
        }:
            raise ValueError("unexpected request fields")
        return cls(**data)

    def prompt(self) -> str:
        return (
            "You are generating a PROPOSAL for a single harmless sandbox file. "
            "Do not run commands, install packages, or refer to external systems. "
            "Return exactly ONE JSON object, with keys 'path' and 'content', "
            "no markdown or comments outside JSON. "
            "The path must equal " + json.dumps(self.target_path) + ". "
            "File contents should be simple and self-contained.\n"
            "Task: " + self.instruction
        )


def _safe_proposal(text: str, expected_path: str) -> dict:
    if not isinstance(text, str) or len(text) > 16000:
        raise ValueError("invalid model answer")
    obj = json.loads(text, object_pairs_hook=_no_duplicate_pairs)
    if type(obj) is not dict or set(obj) != {"path", "content"}:
        raise ValueError("model response schema mismatch")
    if obj["path"] != expected_path or validate_target(obj["path"]) != expected_path:
        raise ValueError("model proposed unapproved path")
    content = obj["content"]
    if type(content) is not str or not content.strip() or len(content) > 12000 or "\x00" in content:
        raise ValueError("invalid proposed file")
    return {
        "relative_path": expected_path,
        "content": content,
        "content_sha256": sha256(content.encode("utf-8")).hexdigest(),
        "applied": False, "verified_by_core": False,
    }


def execute_one(task: ProviderTask, *, model: str, ledger_dir: Path,
                max_output_tokens: int = 256) -> dict:
    """One preflight + at most one local HTTP inference. Never writes project files."""
    common = {
        "schema": SCHEMA_RESULT,
        "task_id": task.task_id,
        "project_id": task.project_id,
        "input_sha256": task.input_sha256,
        "model": model,
        "provider": "ollama-loopback",
        "offline_mock": False,
        "api_cost_usd": 0,
        "review_approved": False,
        "published": False,
        "proposed_files": [],
        "response_sha256": None,
        "prompt_sha256": None,
        "error_code": None,
    }
    try:
        resources = check_resources(model)
    except PreflightBlocked as exc:
        return {**common, "status": "BLOCKED", "error_code": exc.code,
                "attempt_consumed": False}
    if not isinstance(ledger_dir, Path) or not ledger_dir.is_dir():
        return {**common, "status": "BLOCKED", "error_code": "BLOCKED_LEDGER",
                "attempt_consumed": False}
    # No recorded attempt if the model or RAM preflight is not satisfied.
    prompt = task.prompt()
    common["prompt_sha256"] = sha256(prompt.encode("utf-8")).hexdigest()
    common["resources"] = resources
    budget = DurableBudget(ledger_dir, max_attempts=1, max_reserved_units=50000)
    adapter = LocalQwenAdapter(LocalQwenConfig(
        enabled=True, model=model, timeout_seconds=60,
        max_output_tokens=max_output_tokens), budget)
    try:
        reply = adapter.generate(prompt, task_id=task.task_id)
    except (DurableBudgetError, LocalProviderDisabled, LocalProviderUnknownResult,
            ValueError, OSError) as exc:
        code = "BLOCKED_DUPLICATE_OR_LEDGER" if isinstance(exc, DurableBudgetError) else "UNKNOWN_INFERENCE"
        return {**common, "status": "BLOCKED", "error_code": code,
                "attempt_consumed": True}
    common["response_sha256"] = sha256(reply.text.encode("utf-8")).hexdigest()
    # A real Ollama answer is observed even if it fails the proposal schema.
    common["observed_local_reply"] = True
    try:
        proposal = _safe_proposal(reply.text, task.target_path)
    except (ValueError, UnicodeError, TypeError):
        return {**common, "status": "INVALID_MODEL_OUTPUT",
                "error_code": "UNVERIFIED_RESPONSE_FORMAT",
                "attempt_consumed": True}
    return {**common, "status": "PROPOSED_UNVERIFIED",
            "proposed_files": [proposal], "attempt_consumed": True}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--safe-smoke", action="store_true")
    parser.add_argument("--model", default="qwen2.5-coder:1.5b")
    args = parser.parse_args(argv)
    if args.diagnose == args.safe_smoke:
        parser.error("select exactly one of --diagnose or --safe-smoke")
    try:
        resources = check_resources(args.model)
    except PreflightBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "error_code": exc.code,
                          "model": args.model, "free_ram_bytes": physical_free_memory_bytes()}))
        return 2
    if args.diagnose:
        print(json.dumps({"status": "READY_FOR_ONE_LOCAL_CALL", **resources}))
        return 0
    ledger = Path.home() / ".neurofactory-providers-owned" / "qwen-one-shot-ledger"
    ledger.mkdir(parents=True, exist_ok=True, mode=0o700)
    task = ProviderTask(
        task_id="nf-providers-smoke-20261015-a",
        project_id="nf-provider-sandbox",
        input_sha256="0" * 64,
        target_path="src/local_smoke.py",
        instruction=("Write a Python function named add_two_numbers(a, b) "
                     "that returns a + b. Do not add dependencies."),
    )
    result = execute_one(task, model=args.model, ledger_dir=ledger)
    # Truncate proposed contents in CLI report: the CORE writer must obtain
    # the full exact proposal separately under a trusted authorized channel.
    if result["proposed_files"]:
        for file in result["proposed_files"]:
            file["content"] = None
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PROPOSED_UNVERIFIED" else 3


if __name__ == "__main__":
    sys.exit(main())
