"""Render a local two-server MCP client configuration for the ONE Agent.

Configuration generation is NOT a remote-control grant, installation or
extension pairing. Only paths chosen by the local owner are accepted and no
network listener, task scheduler entry or Windows policy is modified.
"""
from __future__ import annotations

import argparse
import json
from pathlib import PureWindowsPath
import re

WINDOWS_PATH = re.compile(r"^[A-Za-z]:\\\\")
PROJECT_ID = re.compile(r"^[0-9a-f]{32}$")
APP_NAME = re.compile(r"^[a-z0-9_.-]{2,70}\\.exe$")
SHELL_APPS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "regedit.exe", "mmc.exe", "mshta.exe",
    "rundll32.exe", "schtasks.exe", "taskmgr.exe",
})


class ConfigDenied(ValueError):
    pass


def _winpath(s: str, *, suffix: str | None = None) -> str:
    if type(s) is not str or not 6 <= len(s) <= 480 or not WINDOWS_PATH.match(s):
        raise ConfigDenied("ABSOLUTE_WINDOWS_PATH_REQUIRED")
    p = PureWindowsPath(s)
    if (".." in p.parts or not p.is_absolute() or any(
        c in s for c in ("\n", "\r", "\t", '"', "'", "*", "?")
    ) or s.startswith("\\\\") or s.endswith("\\") and len(p.parts) <= 1):
        raise ConfigDenied("UNSAFE_WINDOWS_PATH")
    if suffix and p.name.lower() != suffix.lower():
        raise ConfigDenied("UNEXPECTED_FILE_NAME")
    return str(p)


def _apps(names: str) -> str:
    if type(names) is not str:
        raise ConfigDenied("APP_ALLOWLIST_REQUIRED")
    items = [x.strip().lower() for x in names.split(",")]
    if (not 1 <= len(items) <= 12 or any(
        not APP_NAME.fullmatch(a) or a in SHELL_APPS for a in items
    ) or len(set(items)) != len(items)):
        raise ConfigDenied("APP_ALLOWLIST_REFUSED")
    return ",".join(items)


def make_config(*, python_exe: str, workbench: str, playwright_config: str,
                root: str, data: str, project: str, apps: str) -> dict:
    python_exe = _winpath(python_exe, suffix="python.exe")
    workbench = _winpath(workbench)
    playwright_config = _winpath(playwright_config, suffix="playwright_owner_mcp.json")
    root = _winpath(root)
    data = _winpath(data)
    apps = _apps(apps)
    if project != "auto" and not (type(project) is str and PROJECT_ID.fullmatch(project)):
        raise ConfigDenied("EXACT_PROJECT_REQUIRED")
    desktop_script = str(PureWindowsPath(workbench) / "one_desktop_owner_mcp.py")
    return {
        "mcpServers": {
            "one-browser": {
                "command": "npx.cmd",
                "args": [
                    "@playwright/mcp@latest",
                    "--extension",
                    "--config", playwright_config
                ]
            },
            "one-desktop": {
                "command": python_exe,
                "args": [
                    desktop_script,
                    "--root", root,
                    "--data", data,
                    "--project", project,
                    "--apps", apps
                ]
            }
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True)
    parser.add_argument("--workbench", required=True)
    parser.add_argument("--playwright-config", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--project", default="auto")
    parser.add_argument("--apps", default="chrome.exe,notepad.exe,explorer.exe")
    args = parser.parse_args()
    config = make_config(python_exe=args.python, workbench=args.workbench,
                         playwright_config=args.playwright_config, root=args.root,
                         data=args.data, project=args.project, apps=args.apps)
    print(json.dumps(config, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
