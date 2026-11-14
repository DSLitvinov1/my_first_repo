"""One-click owner-session launcher for the portable Work ONE Windows app.

Runs the already verified local user app, not a service or privileged HOST.
Does not change PowerShell execution policy, create background schedules,
use credentials, allow arbitrary model-generated OS commands, or open ports.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

# Official embedded Python has isolated sys.path (_pth). Include ONLY this
# verified package directory for sibling modules, never user site-packages.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from private_preflight_one import verify_manifest
from qwen_planner_one import LocalOllamaQwen, LOCAL_APPROVED_MODELS


def owner_session_eligible():
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS"):
        return False
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        kernel.GetCurrentProcessId.restype = ctypes.c_ulong
        kernel.ProcessIdToSessionId.argtypes = [
            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
        ]
        session = ctypes.c_ulong(0)
        valid = kernel.ProcessIdToSessionId(
            kernel.GetCurrentProcessId(), ctypes.byref(session)
        )
        return bool(valid and session.value > 0 and not shell.IsUserAnAdmin())
    except (OSError, AttributeError, ValueError):
        return False


def _safe_private_folder(folder: Path):
    if folder.exists() or folder.is_symlink():
        info = folder.lstat()
        if (not folder.is_dir() or folder.is_symlink() or
                getattr(info, "st_file_attributes", 0) & 0x400):
            raise RuntimeError("PRIVATE_FOLDER_REPARSE_REFUSED")
    else:
        folder.mkdir(mode=0o700)


def prepare_state(profile: str) -> tuple[Path, Path]:
    if not profile:
        raise RuntimeError("PRIVATE_LOCALAPPDATA_REQUIRED")
    local = Path(profile)
    if not local.is_absolute() or local.is_symlink():
        raise RuntimeError("PRIVATE_LOCALAPPDATA_INVALID")
    base = local / "NeirozavodWorkONEPrivatePilot"
    workspace = base / "projects"
    state = base / "data"
    for folder in (base, workspace, state):
        _safe_private_folder(folder)
    return workspace, state


def local_qwen_detected():
    for model in LOCAL_APPROVED_MODELS:
        if LocalOllamaQwen(model=model).available():
            return True
    return False


def _launch():
    root = Path(__file__).resolve().parent
    report = verify_manifest(root)
    if report.get("state") != "verified" or not report.get(
        "portable_runtime_verified"
    ):
        raise RuntimeError("PRIVATE_PACKAGE_HASHES_INVALID")
    if not owner_session_eligible():
        raise RuntimeError("PRIVATE_INTERACTIVE_NONADMIN_WINDOWS_REQUIRED")
    if Path(sys.executable).resolve() != (
        root / "runtime" / "python" / "python.exe"
    ).resolve():
        raise RuntimeError("PRIVATE_EMBEDDED_PYTHON_REQUIRED")
    workspace, state = prepare_state(os.environ.get("LOCALAPPDATA", ""))
    cmd = [
        sys.executable, str(root / "work_server.py"),
        "--root", str(workspace), "--data", str(state),
        "--port", "18770", "--open-ui",
        "--browser-allow-hosts", "example.org,www.wikipedia.org,wikipedia.org",
    ]
    if local_qwen_detected():
        cmd.append("--qwen-local")
        print("Work ONE: existing local Qwen 3.5 discovered.")
    else:
        print("Work ONE: Qwen model is not connected; local features remain ready.")
    print("Work ONE: http://127.0.0.1:18770/")
    print("Work ONE: only your projects. No Windows service or admin rights.")
    return subprocess.call(cmd, cwd=str(root))


def main(argv=()):
    root = Path(__file__).resolve().parent
    if list(argv) == ["--verify-only"]:
        report = verify_manifest(root)
        print(json.dumps({
            "verified": report.get("state") == "verified" and
                        report.get("portable_runtime_verified") is True,
            "source_files": report.get("files"),
            "vendor_files": report.get("vendor_files"),
        }))
        return 0 if (report.get("state") == "verified" and
                     report.get("portable_runtime_verified")) else 2
    if argv:
        print("PRIVATE_LAUNCH_ARGUMENTS_REFUSED", file=sys.stderr)
        return 2
    try:
        return _launch()
    except (OSError, RuntimeError, ValueError) as error:
        message = str(error)
        if not message.startswith("PRIVATE_"):
            message = "PRIVATE_LOCAL_LAUNCH_FAILED"
        print(message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
