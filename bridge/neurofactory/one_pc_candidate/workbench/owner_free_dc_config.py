"""Optional free local Desktop Commander MCP beside existing ONE and Playwright.

Configuration ONLY; no installation, privileges, browser pairing, or remote MCP.
"""
from __future__ import annotations
import argparse
import json
from pathlib import PureWindowsPath
from owner_dual_mcp_config import make_config, _winpath, ConfigDenied
from one_files_dc_mcp import verify_workspace


def make_free_config(*, python_exe: str, workbench: str, playwright_config: str,
                     root: str, data: str, project: str, apps: str,
                     workspace: str, allow_write: bool = False) -> dict:
    base = make_config(python_exe=python_exe, workbench=workbench,
                       playwright_config=playwright_config, root=root,
                       data=data, project=project, apps=apps)
    workbench = _winpath(workbench)
    workspace = verify_workspace(workspace)
    # Read-only until user's own explicit action and live acceptance.
    arguments = [str(PureWindowsPath(workbench) / 'one_files_dc_mcp.py'),
                 '--workspace', workspace]
    if allow_write:
        arguments += ['--allow-write']
    base['mcpServers']['one-files'] = {'command': _winpath(python_exe, suffix='python.exe'),
                                     'args': arguments}
    return base


def main():
    ap = argparse.ArgumentParser()
    for name in ('python', 'workbench', 'playwright-config', 'root', 'data', 'workspace'):
        ap.add_argument('--' + name, required=True)
    ap.add_argument('--project', default='auto')
    ap.add_argument('--apps', default='notepad.exe,chrome.exe')
    ap.add_argument('--allow-write', action='store_true')
    o = ap.parse_args()
    print(json.dumps(make_free_config(python_exe=o.python,
                    workbench=o.workbench, playwright_config=o.playwright_config,
                    root=o.root, data=o.data, workspace=o.workspace,
                    project=o.project, apps=o.apps, allow_write=o.allow_write),
                    ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
