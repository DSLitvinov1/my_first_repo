"""No-network, no-desktop acceptance for isolated ChatGPT candidate launcher."""
from pathlib import Path
import tempfile
import unittest

from start_chatgpt_candidate_one import candidate_command, HOSTS, PILOT, PORT


class ChatGPTCandidateStartTests(unittest.TestCase):
    def test_nonconflicting_owner_pilot_configuration(self):
        self.assertEqual(PORT, 18771)
        self.assertEqual(len(HOSTS), len(set(HOSTS)))
        self.assertNotIn("example.org", HOSTS)
        self.assertIn("direct.yandex.ru", HOSTS)
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch)
            app = profile / "verified-candidate"
            cmd = candidate_command(app, profile)
            self.assertIn("--port", cmd)
            self.assertEqual(cmd[cmd.index("--port") + 1], "18771")
            self.assertIn(str(profile / PILOT / "data"), cmd)
            self.assertNotIn("NeirozavodWorkONEPrivatePilot", " ".join(cmd))
            self.assertNotIn("18770", " ".join(cmd))
            self.assertIn("--open-ui", cmd)
            self.assertIn("--desktop-enable", cmd)
            self.assertTrue((profile / PILOT / "projects").is_dir())

    def test_bad_relative_profile_cannot_be_used(self):
        with self.assertRaises(RuntimeError):
            candidate_command(Path("C:/Candidate"), Path("relative/path"))


if __name__ == "__main__":
    unittest.main()
