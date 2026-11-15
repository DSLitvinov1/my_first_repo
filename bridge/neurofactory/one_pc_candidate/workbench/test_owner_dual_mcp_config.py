"""Offline approval/config tests: never start Chrome, desktop worker or MCP."""
import unittest
from owner_dual_mcp_config import make_config, ConfigDenied

VALID=dict(
    python_exe=r"C:\Program Files\Python312\python.exe",
    workbench=r"C:\ChatGPTProjects\ONE-Candidate\workbench",
    playwright_config=r"C:\ChatGPTProjects\ONE-Playwright-Candidate-20261115\playwright_owner_mcp.json",
    root=r"C:\ChatGPTProjects\ONE-Candidate\projects",
    data=r"C:\ChatGPTProjects\ONE-Candidate\data",
    project="auto",
    apps="notepad.exe,chrome.exe",
)

class ConfigTests(unittest.TestCase):
    def test_generates_two_owner_local_stdio_mcp_servers(self):
        result=make_config(**VALID)
        self.assertEqual(set(result),{"mcpServers"})
        self.assertEqual(set(result["mcpServers"]),{"one-browser","one-desktop"})
        browser=result["mcpServers"]["one-browser"]
        self.assertEqual(browser["command"],"npx.cmd")
        self.assertIn("--extension",browser["args"])
        self.assertNotIn("--cdp-endpoint",browser["args"])
        self.assertEqual(browser["args"][-1],VALID["playwright_config"])
        desktop=result["mcpServers"]["one-desktop"]
        self.assertEqual(desktop["command"],VALID["python_exe"])
        self.assertEqual(desktop["args"][-1],"notepad.exe,chrome.exe")
        self.assertIn("one_desktop_owner_mcp.py",desktop["args"][0])
    def test_refuses_shell_or_privileged_app_names(self):
        for name in ["cmd.exe","powershell.exe","pwsh.exe","regedit.exe","mmc.exe",
                     "taskmgr.exe","schtasks.exe","notepad.exe,cmd.exe","python.exe"]:
            with self.assertRaises(ConfigDenied):
                make_config(**{**VALID,"apps":name})
    def test_refuses_unsafe_paths(self):
        for path in ["../workbench","/tmp/my_first_repo","\\\\host\\share\\x",
                     "C:\\foo\\..\\bar","C:\\work\\foo?.json","C:/users/name",
                     "C:\\\\evil\\\"arg","relative.exe"]:
            with self.assertRaises(ConfigDenied):
                make_config(**{**VALID,"workbench":path})
    def test_refuses_missing_or_invalid_project(self):
        for project in ["", "d"*31, "g"*32, "A"*32, "all","a"*33]:
            with self.assertRaises(ConfigDenied):
                make_config(**{**VALID,"project":project})
        # Valid project gets transported as a fixed argument, not shell text.
        args=make_config(**{**VALID,"project":"a"*32})["mcpServers"]["one-desktop"]["args"]
        self.assertEqual(args[args.index("--project")+1],"a"*32)
    def test_refuses_app_overflow_duplicates_and_injection(self):
        examples=["notepad.exe,notepad.exe",("a.exe,"*12)+"b.exe",
                  "notepad.exe;calc.exe","notepad.exe\\ncmd.exe","",
                  "chrome","notepad.exe,cmd.exe","explorer.exe,notepad.exe,explorer.exe"]
        for names in examples:
            with self.assertRaises(ConfigDenied):
                make_config(**{**VALID,"apps":names})
    def test_config_never_contains_authorization_or_credential_parameters(self):
        result=make_config(**VALID)
        import json
        raw=json.dumps(result).lower()
        for dangerous in ["--no-sandbox","--allow-unrestricted-file-access",
                          "--remote-debugging-port","powershell.exe","-executionpolicy",
                          "api_key","password","access_token"]:
            self.assertNotIn(dangerous,raw)

if __name__=="__main__":
    unittest.main()
