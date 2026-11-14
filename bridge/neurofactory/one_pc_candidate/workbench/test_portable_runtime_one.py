"""No network, registry, or real browser dependency in runtime unit tests."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from portable_runtime_one import (
    find_node,find_browser,bundled_dependencies_ready,status)

class PortableRuntimeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def test_no_windows_browser_on_other_system(self):
        self.assertIsNone(find_browser(windows=False))

    def test_autodiscover_allowlisted_edge_location(self):
        pf=self.root/"pf"
        pf86=self.root/"pf86"
        browser=pf86/"Microsoft"/"Edge"/"Application"/"msedge.exe"
        browser.parent.mkdir(parents=True)
        browser.write_bytes(b"x"*2048)
        found=find_browser(windows=True,programfiles=pf,programfilesx86=pf86,
                           localappdata=self.root/"local")
        self.assertEqual(found,browser.resolve())

    def test_reject_symlinked_browser(self):
        pf=self.root/"pf";pf86=self.root/"pf86"
        browser=pf86/"Microsoft"/"Edge"/"Application"/"msedge.exe"
        browser.parent.mkdir(parents=True)
        actual=self.root/"real.exe";actual.write_bytes(b"x"*2048)
        try:browser.symlink_to(actual)
        except (OSError,NotImplementedError):self.skipTest("Symlinks blocked")
        self.assertIsNone(find_browser(windows=True,programfiles=pf,
                            programfilesx86=pf86,localappdata=self.root/"local"))

    def test_bundled_node_is_preferred(self):
        node=self.root/"runtime"/"node"/"node.exe"
        node.parent.mkdir(parents=True)
        node.write_bytes(b"x"*2048)
        self.assertEqual(find_node(self.root,windows=True),node.resolve())

    def test_dependencies_require_puppeteer_and_node(self):
        node=self.root/"runtime"/"node"/"node.exe"
        node.parent.mkdir(parents=True)
        node.write_bytes(b"x"*2048)
        self.assertFalse(bundled_dependencies_ready(self.root,windows=True))
        dep=self.root/"node_modules"/"puppeteer-core"/"package.json"
        dep.parent.mkdir(parents=True);dep.write_text("{}")
        self.assertTrue(bundled_dependencies_ready(self.root,windows=True))

    def test_report_does_not_disclose_paths(self):
        report=status(self.root,windows=False)
        self.assertNotIn(str(self.root),str(report))
        self.assertIn("browser_ready",report)
        self.assertNotIn("token",str(report))

if __name__=="__main__":
    unittest.main()
