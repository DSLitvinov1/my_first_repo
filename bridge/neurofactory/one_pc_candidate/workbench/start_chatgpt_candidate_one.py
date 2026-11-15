"""Non-admin owner-only ChatGPT candidate, isolated from installed Work ONE.

Never touches the original pilot database, port 18770, services, browser cookies
or Windows security policy. Playwright extension pairing is performed by owner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

# Embedded Windows Python uses isolated sys.path; add only the verified package directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from private_preflight_one import verify_manifest
from start_work_one import owner_session_eligible, _safe_private_folder

HOSTS = (
    "potrebpravo.ru",
    "semya-yurist.ru",
    "metrika.yandex.ru",
    "webmaster.yandex.ru",
    "direct.yandex.ru",
    "search.google.com",
    "hosting.timeweb.ru",
    "b24-xlzm11.bitrix24.ru",
)
PORT = 18771
PILOT = "NeirozavodWorkONEChatGPTPilot"


def candidate_command(root: Path, appdata: Path) -> list[str]:
    if not appdata.is_absolute() or appdata.is_symlink():
        raise RuntimeError("CHATGPT_PRIVATE_APPDATA_REQUIRED")
    base = appdata / PILOT
    for folder in (base, base / "projects", base / "data"):
        _safe_private_folder(folder)
    return [
        str(root / "runtime" / "python" / "python.exe"),
        str(root / "work_server.py"),
        "--root", str(base / "projects"),
        "--data", str(base / "data"),
        "--port", str(PORT),
        "--open-ui",
        "--browser-allow-hosts", ",".join(HOSTS),
        "--desktop-enable",
        "--desktop-allow-apps", "notepad.exe,explorer.exe,chrome.exe",
    ]


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    root = Path(__file__).resolve().parent
    verified = verify_manifest(root)
    if argv == ["--verify-only"]:
        ok = verified.get("state") == "verified" and verified.get("portable_runtime_verified") is True
        print(json.dumps({"verified": ok, "isolated_candidate": True, "port": PORT}))
        return 0 if ok else 2
    if argv:
        print("CHATGPT_LAUNCH_ARGUMENTS_REFUSED", file=sys.stderr)
        return 2
    if not owner_session_eligible():
        print("CHATGPT_INTERACTIVE_NONADMIN_WINDOWS_REQUIRED", file=sys.stderr)
        return 2
    if verified.get("state") != "verified" or not verified.get("portable_runtime_verified"):
        print("CHATGPT_PACKAGE_INTEGRITY_REFUSED", file=sys.stderr)
        return 2
    if Path(sys.executable).resolve() != (root / "runtime" / "python" / "python.exe").resolve():
        print("CHATGPT_PINNED_PYTHON_REQUIRED", file=sys.stderr)
        return 2
    try:
        profile = os.environ.get("LOCALAPPDATA")
        if not profile:
            raise RuntimeError("CHATGPT_PROFILE_REQUIRED")
        command = candidate_command(root, Path(profile))
        print("ONE candidate: http://127.0.0.1:18771/")
        print("Owner approval is still required for GitHub pairing and Playwright Chrome tabs.")
        return subprocess.call(command, cwd=root)
    except (OSError, RuntimeError, ValueError) as exc:
        message = str(exc)
        print(message if message.startswith("CHATGPT_") else "CHATGPT_LAUNCH_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
