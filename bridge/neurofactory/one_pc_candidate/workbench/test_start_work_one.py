"""One-click Windows launcher safety checks with no interactive actions."""
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import start_work_one


class OneClickTests(TestCase):
    def test_no_unknown_cli_args(self):
        self.assertEqual(start_work_one.main(["--install-service"]),2)

    def test_reject_missing_profile(self):
        with self.assertRaisesRegex(RuntimeError,"PRIVATE_LOCALAPPDATA_REQUIRED"):
            start_work_one.prepare_state("")

    def test_isolated_data_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace,state=start_work_one.prepare_state(folder)
            self.assertTrue(workspace.is_dir())
            self.assertTrue(state.is_dir())
            self.assertEqual(workspace.parent,state.parent)

    def test_reject_linked_work_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)/"NeirozavodWorkONEPrivatePilot"
            base.mkdir()
            target=Path(folder)/"other";target.mkdir()
            try:
                (base/"projects").symlink_to(target,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest("Symlinks unavailable in this OS policy")
            with self.assertRaisesRegex(RuntimeError,"PRIVATE_FOLDER_REPARSE_REFUSED"):
                start_work_one.prepare_state(folder)

    def test_hosted_runner_never_becomes_user_desktop(self):
        with patch.dict("start_work_one.os.environ",{"GITHUB_ACTIONS":"true"}):
            self.assertFalse(start_work_one.owner_session_eligible())

    def test_do_not_launch_unverified_package(self):
        with patch("start_work_one.verify_manifest",return_value={"state":"invalid"}):
            with self.assertRaisesRegex(RuntimeError,"PRIVATE_PACKAGE_HASHES_INVALID"):
                start_work_one._launch()


if __name__=="__main__":
    import unittest
    unittest.main()
