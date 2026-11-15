"""Check the owner portable bundle includes every new ChatGPT/Playwright module.

No Windows access, external account access, installation or network calls.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent
BUILDER = ROOT / "build_ready_one.ps1"
MANDATORY = {
    "work_server.py", "work_core.py", "agent_one.py",
    "chatgpt_bridge_one.py", "desktop_goal_one.py", "yandex_one.py",
    "one_desktop_owner_mcp.py", "owner_dual_mcp_config.py",
    "playwright_access_policy.py", "playwright_owner_mcp.json",
    "playwright_stage_owner.ps1", "playwright_owner_readiness.ps1",
    "START_OWNER_DESKTOP_CONTROL.ps1", "START_CHATGPT_ONE.cmd",
    "start_chatgpt_candidate_one.py", "desktop_script_one.py",
    "desktop_one.py", "credentials_one.py", "START_PRIVATE_WORK_ONE.ps1",
}


def source_allowlist():
    text = BUILDER.read_text(encoding="utf-8-sig")
    match = re.search(r"\$names\s*=\s*@\((.*?)\)\s*if\s*\(\$names\.Count", text, re.S)
    if not match:
        raise AssertionError("BUNDLE_ALLOWLIST_MISSING")
    return re.findall(r"'([A-Za-z0-9_.-]+)'", match.group(1))


class BundleActivationClosure(unittest.TestCase):
    def test_no_missing_or_duplicate_sources(self):
        allowed = source_allowlist()
        self.assertEqual(len(allowed), 44)
        self.assertEqual(len(set(allowed)), len(allowed))
        self.assertTrue(MANDATORY.issubset(allowed))
        self.assertTrue(all((ROOT / name).is_file() for name in allowed))

    def test_local_python_import_closure(self):
        allowed = set(source_allowlist())
        for name in sorted(allowed):
            if not name.endswith(".py"):
                continue
            source = ast.parse((ROOT / name).read_text(encoding="utf-8-sig"), filename=name)
            modules = []
            for node in ast.walk(source):
                if isinstance(node, ast.Import):
                    modules.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    modules.append(node.module.split(".")[0])
            for module in modules:
                local = ROOT / (module + ".py")
                if local.is_file():
                    self.assertIn(local.name, allowed, f"{name} imports unbundled {local.name}")


if __name__ == "__main__":
    unittest.main()
