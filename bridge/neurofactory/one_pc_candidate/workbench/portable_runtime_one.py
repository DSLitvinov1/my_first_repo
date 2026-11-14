"""Portable runtime discovery for the privately owned Windows Work ONE.

Only local program paths. No network, external commands, registry writes,
automatic downloads or privilege elevation. Fail closed on ambiguous paths.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys

def _exe(candidate: Path):
    try:
        if (candidate.is_symlink() or not candidate.is_file() or
                candidate.stat().st_size < 1024):
            return None
        return candidate.resolve()
    except (OSError,ValueError):
        return None


def find_python(root:Path, *,windows=None):
    windows=(os.name=="nt") if windows is None else windows
    if windows:
        result=_exe(Path(root)/"runtime"/"python"/"python.exe")
        if result is not None:
            return result
    # The launcher can fall back to a separately installed Python.
    current=_exe(Path(sys.executable))
    return current if current is not None else None


def find_node(root:Path, *,windows=None):
    windows=(os.name=="nt") if windows is None else windows
    choices=[]
    if windows:
        choices.extend([
            Path(root)/"runtime"/"node"/"node.exe",
            Path(os.environ.get("ProgramFiles",r"C:\Program Files"))/"nodejs"/"node.exe",
        ])
    system=shutil.which("node")
    if system:
        choices.append(Path(system))
    for candidate in choices:
        result=_exe(candidate)
        if result:
            return result
    return None


def find_browser(*,windows=None,localappdata=None,programfiles=None,
                 programfilesx86=None):
    windows=os.name=="nt" if windows is None else windows
    if not windows:
        return None
    pf=Path(programfiles or os.environ.get("ProgramFiles",r"C:\Program Files"))
    pf86=Path(programfilesx86 or os.environ.get(
        "ProgramFiles(x86)",r"C:\Program Files (x86)"))
    local=Path(localappdata or os.environ.get("LOCALAPPDATA",r"C:\Users\Public"))
    choices=[
        pf/"Google"/"Chrome"/"Application"/"chrome.exe",
        pf86/"Google"/"Chrome"/"Application"/"chrome.exe",
        local/"Google"/"Chrome"/"Application"/"chrome.exe",
        pf/"Microsoft"/"Edge"/"Application"/"msedge.exe",
        pf86/"Microsoft"/"Edge"/"Application"/"msedge.exe",
        pf/"Chromium"/"Application"/"chrome.exe",
    ]
    for path in choices:
        result=_exe(path)
        if result:
            return result
    return None


def bundled_dependencies_ready(root:Path,*,windows=None):
    windows=os.name=="nt" if windows is None else windows
    if not windows:
        return False
    modules=Path(root)/"node_modules"/"puppeteer-core"/"package.json"
    return modules.is_file() and not modules.is_symlink() and find_node(root,windows=True) is not None


def status(root:Path, *,windows=None):
    windows=os.name=="nt" if windows is None else windows
    python=find_python(root,windows=windows)
    node=find_node(root,windows=windows)
    browser=find_browser(windows=windows)
    return {
        "system":"windows" if windows else "other",
        "python":bool(python),
        "node":bool(node),
        "browser":bool(browser),
        "puppeteer":bundled_dependencies_ready(root,windows=windows),
        "desktop_worker":(Path(root)/"desktop_worker.ps1").is_file(),
        "browser_ready":bool(node and browser and bundled_dependencies_ready(root,windows=windows)),
        "qwen":"requires_existing_local_ollama_or_pinned_existing_provider",
        "external_accounts":"separate_owner_authorization_required",
    }
