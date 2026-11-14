"""Cloud-only Qwen9B selection: no live secrets, SSH calls, models or external writes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import start_work_one
import work_server

class CloudExistingQwenTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.profile=self.root/"NeurofactoryData"

    def test_missing_owner_key_refused_without_cloud_request(self):
        with patch.object(work_server,"OWNER_DATA",self.profile):
            with self.assertRaisesRegex(work_server.ServerDenied,
                                        "CLOUD_QWEN_EXISTING_SSH_IDENTITY_UNAVAILABLE"):
                work_server.model_module()

    def test_reuses_existing_pinned_host_without_key_copy_or_network(self):
        from cloud_ssh_draft_provider import HOST,HOST_ED25519
        cloud=self.profile/"cloud_qwen"
        cloud.mkdir(parents=True)
        key=cloud/"id_ed25519"
        key.write_text("synthetic-not-a-private-key")
        (cloud/"known_hosts").write_text(
            HOST+" ssh-ed25519 "+HOST_ED25519,encoding="ascii")
        osroot=self.root/"windows"
        ssh=osroot/"System32"/"OpenSSH"/"ssh.exe"
        ssh.parent.mkdir(parents=True)
        ssh.write_bytes(b"synthetic-disabled-executable")
        with patch.dict("os.environ",{"SystemRoot":str(osroot),
                                      "LOCALAPPDATA":str(self.root)}):
            with patch.object(work_server,"OWNER_DATA",self.profile):
                module=work_server.model_module()
                self.assertEqual(module.PRIMARY_MODEL,"qwen3.5:9b")
                self.assertTrue(module.available(self.profile))
                self.assertTrue(start_work_one.cloud_model_configured())
                self.assertFalse((self.root/"copied_id_ed25519").exists())

    def test_wrong_pinned_host_never_claims_configured(self):
        from cloud_ssh_draft_provider import HOST
        folder=self.profile/"cloud_qwen"
        folder.mkdir(parents=True)
        (folder/"id_ed25519").write_text("synthetic")
        (folder/"known_hosts").write_text(HOST+" ssh-ed25519 forged",encoding="ascii")
        osroot=self.root/"windows"; ssh=osroot/"System32"/"OpenSSH"/"ssh.exe"
        ssh.parent.mkdir(parents=True)
        ssh.write_bytes(b"fake")
        with patch.dict("os.environ",{"SystemRoot":str(osroot)}):
            with patch.object(work_server,"OWNER_DATA",self.profile):
                with self.assertRaises(work_server.ServerDenied):
                    work_server.model_module()

    def test_one_click_start_does_not_probe_ollama(self):
        import inspect
        source=inspect.getsource(start_work_one._launch)
        self.assertNotIn("qwen-local",source)
        self.assertNotIn("ollama pull",source)

if __name__=="__main__":
    unittest.main()
