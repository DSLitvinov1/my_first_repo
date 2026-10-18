"""Assemble a read-only ONE-Windows-PC candidate from exact immutable Git trees.

Does NOT install, run the trusted host, start a task, call models or merge PRs.
Files originate from pinned git objects, never from mutable checked-out paths.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCES = {
    "core": {
        "sha": "beb08eff32923d8ca364aabfde0458f380acf8e7",
        "prefix": "bridge/neurofactory/development/core_owned/",
        "files": ("one_task_core.py", "README.md"),
    },
    "host": {
        "sha": "546d566ecfe7cbf317f4b49042a9473d862d1f9b",
        "prefix": "bridge/neurofactory/trusted_host/",
        "files": (
            "windows_scm_sandbox_receiver.py", "windows_named_pipe_pilot_receiver.py",
            "windows_scm_ci_worker.py", "windows_scm_acl_crosscheck_ci.py",
            "ONE_WINDOWS_PC_LOCAL_PILOT_20261018_RU.md",
        ),
    },
    "ui": {
        "sha": "56a375a2f76bdaf56932f21b392a9d133f740913",
        "prefix": "bridge/neurofactory/control_ui/",
        "files": ("index.html", "styles.css", "app.js", "demo-data.js",
                  "demo-bundle.json", "README.md"),
    },
    "providers": {
        "sha": "827b654d9f7c6a10a9b90a9c97802e63116711b9",
        "prefix": "bridge/neurofactory/providers/",
        "files": ("ollama_worker.py", "local_qwen.py", "provider_interface.py",
                  "evidence_receipt.py", "durable_budget.py",
                  "coordinator_adapter.py", "README.md"),
    },
    "coordinator": {
        "sha": "ad82e853d9db2a0567c61e8d9a3f1e5f62905271",
        "prefix": "bridge/neurofactory/coordination/",
        "files": ("mvp_status_projection.py", "mvp_task_exchange.py",
                  "release_readiness.py", "MVP_READ_ONLY_INTERFACE_CONTRACT_20261015_RU.md"),
    },
}

MAX_BLOB_BYTES = 250_000
_SHA = re.compile(r"[a-f0-9]{40}\Z")


class AssemblyDenied(ValueError):
    pass


def _git(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True,
            check=False, timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssemblyDenied("Local immutable Git source unavailable") from exc
    if result.returncode:
        raise AssemblyDenied("Source commit or Git object unavailable")
    if len(result.stdout) > MAX_BLOB_BYTES + 512:
        raise AssemblyDenied("Unexpected oversized Git object")
    return result.stdout


def _safe_output(output: Path) -> Path:
    if not output.is_absolute():
        raise AssemblyDenied("Bundle output must be an absolute directory path")
    if output.exists() or output.is_symlink():
        raise AssemblyDenied("Refuse to replace an existing output")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise AssemblyDenied("Output parent must be an existing local directory")
    if os.name == "nt" and str(output).startswith("\\\\"):
        raise AssemblyDenied("UNC/network output is refused")
    return output


def _immutable_file(repo: Path, sha: str, repo_path: str) -> tuple[bytes, str]:
    tree = _git(repo, "ls-tree", "-z", sha, "--", repo_path)
    if tree.count(b"\0") != 1:
        raise AssemblyDenied("Pinned source file not found or ambiguous")
    row = tree.removesuffix(b"\0")
    meta, sep, name = row.partition(b"\t")
    if not sep or name != repo_path.encode("ascii"):
        raise AssemblyDenied("Unexpected Git path")
    parts = meta.split(b" ")
    if len(parts) != 3 or parts[0] != b"100644" or parts[1] != b"blob":
        raise AssemblyDenied("Symlinks and executable files are not bundled")
    blob = parts[2].decode("ascii", "strict")
    if not _SHA.fullmatch(blob):
        raise AssemblyDenied("Invalid Git blob identifier")
    raw = _git(repo, "show", sha + ":" + repo_path)
    if len(raw) > MAX_BLOB_BYTES:
        raise AssemblyDenied("Pinned file exceeds safe limit")
    return raw, blob


def assemble(checkouts: dict[str, Path], output: Path, launcher: Path) -> dict:
    """Only stage inert files and a local read-only console; never execute them."""
    if set(checkouts) != set(SOURCES):
        raise AssemblyDenied("All five immutable source checkouts are required")
    output = _safe_output(output)
    if launcher.is_symlink() or not launcher.is_file():
        raise AssemblyDenied("Read-only launcher missing")
    launcher_data = launcher.read_bytes()
    if not 100 < len(launcher_data) <= MAX_BLOB_BYTES:
        raise AssemblyDenied("Invalid launcher")
    for role, spec in SOURCES.items():
        repo = checkouts[role]
        if repo.is_symlink() or not repo.is_dir():
            raise AssemblyDenied("Local source checkout missing/linked")
        actual = _git(repo, "rev-parse", "HEAD").decode("ascii", "strict").strip()
        if actual != spec["sha"]:
            raise AssemblyDenied("Incorrect pinned source revision: " + role)

    directory = Path(tempfile.mkdtemp(prefix=".nf-onepc-stage-", dir=output.parent))
    finished = False
    try:
        evidence = []
        for role, spec in SOURCES.items():
            destination = directory / "components" / role
            destination.mkdir(parents=True)
            for name in spec["files"]:
                if "/" in name or "\\" in name or name in (".", ".."):
                    raise AssemblyDenied("Invalid pinned relative path")
                path = spec["prefix"] + name
                raw, blob = _immutable_file(checkouts[role], spec["sha"], path)
                (destination / name).write_bytes(raw)
                evidence.append({
                    "role": role, "file": name, "source_commit": spec["sha"],
                    "git_blob": blob, "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                })
        (directory / "local_preview.py").write_bytes(launcher_data)
        manifest = {
            "schema": "neurofactory.one_pc_candidate.v1",
            "release_approved": False,
            "live_execution_allowed": False,
            "handoff_active": False,
            "real_queue_enabled": False,
            "single_windows_pc_pilot": True,
            "independent_review_complete": False,
            "owner_pc_installed": False,
            "components_executable": False,
            "ui_is_demonstration": True,
            "provider_model_inference_verified_on_owner_pc": False,
            "remote_witness_independence": False,
            "assembly_trust": "pinned_git_objects_only_no_independent_review",
            "launcher_sha256": hashlib.sha256(launcher_data).hexdigest(),
            "files": evidence,
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (directory / "OPEN_FIRST.txt").write_text(
            "НЕЙРОЗАВОД — локальный кандидат для одного Windows ПК.\n"
            "Пока это изолированный комплект и демонстрационная панель, а НЕ установленная CRM/очередь или готовый ИИ-завод.\n"
            "Чтобы открыть интерфейс на этом ПК: python local_preview.py --bundle .\n"
            "Откройте http://127.0.0.1:8765 в браузере.\n"
            "Никакие службы, Qwen, реальные очереди, API или платные функции не включаются.\n"
            "Отдельно требуются установка с разрешения владельца, модельные испытания и независимая приёмка.\n",
            encoding="utf-8",
        )
        os.replace(directory, output)
        finished = True
        return manifest
    finally:
        if not finished:
            shutil.rmtree(directory, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Stage exact one-PC read-only candidate")
    for role in SOURCES:
        parser.add_argument("--" + role, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(argv)
    checkouts = {name: getattr(options, name) for name in SOURCES}
    launcher = Path(__file__).with_name("local_preview.py")
    result = assemble(checkouts, options.output, launcher)
    print(json.dumps({
        "bundle": "CREATED_UNRELEASED",
        "entries": len(result["files"]),
        "release_approved": False,
        "live_execution_allowed": False,
        "sources_verified_by_git_object": len(SOURCES),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
