"""Host-only POSIX DAC boundary smoke: synthetic temp dir, NO provider/model.

Runs only as root on an ephemeral GitHub-hosted Ubuntu test machine.
Shows another unprivileged uid cannot rename CORE-owned parent/write DB.
NOT a production attestation, protection from privileged root or same-UID actors,
or a claim that Windows ACL, cross-host leases or off-host signing work.
"""
import json
import os
import pathlib
import pwd
import subprocess
import sys
import unittest

import test_one_task_core
from one_task_core import CoreSafetyError


@unittest.skipUnless(os.name == "posix", "POSIX only")
@unittest.skipUnless(getattr(os, "geteuid", lambda: -1)() == 0,
                     "ephemeral host permission smoke needs root to drop uid")
class SeparateUidHostSmoke(unittest.TestCase):
    def test_untrusted_uid_cannot_move_core_parent_or_modify_db(self):
        attacker = pwd.getpwnam("nobody")
        self.assertNotEqual(attacker.pw_uid, os.geteuid())
        fixture = test_one_task_core.CoreOnceTests("test_one_file_real_offline_write_and_checkpoint")
        fixture.setUp()
        try:
            fixture.base.chmod(0o711)
            fixture.workspace.chmod(0o711)
            fixture.secure_parents(test_one_task_core.TARGET)
            parent = fixture.q.sandbox / test_one_task_core.TARGET
            parent = parent.parent
            outside = fixture.base / "attacker_destination"
            outside.mkdir(mode=0o777)
            outside.chmod(0o777)
            self.assertEqual(fixture.q.state.stat().st_mode & 0o777, 0o700)
            self.assertEqual(fixture.q.sandbox.stat().st_mode & 0o777, 0o700)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)

            attack = """import json, os, pathlib, sys
source, external, db = map(pathlib.Path, sys.argv[1:])
out = {"uid": os.geteuid()}
try:
    source.rename(external / "stolen")
except PermissionError:
    out["parent_move_denied"] = True
else:
    out["parent_move_denied"] = False
try:
    with db.open("rb") as stream:
        stream.read(1)
except PermissionError:
    out["db_read_denied"] = True
else:
    out["db_read_denied"] = False
try:
    with (source / "forged.py").open("wb") as stream:
        stream.write(b"unauthorized")
except PermissionError:
    out["sandbox_write_denied"] = True
else:
    out["sandbox_write_denied"] = False
print(json.dumps(out, sort_keys=True))
"""
            def drop_identity():
                os.setgroups([])
                os.setgid(attacker.pw_gid)
                os.setuid(attacker.pw_uid)
            result = subprocess.run(
                [sys.executable, "-B", "-c", attack,
                 str(parent), str(outside), str(fixture.q.db)],
                preexec_fn=drop_identity,
                capture_output=True, text=True, timeout=10,
                check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            outcome = json.loads(result.stdout)
            self.assertEqual(outcome["uid"], attacker.pw_uid)
            self.assertTrue(outcome["parent_move_denied"])
            self.assertTrue(outcome["db_read_denied"])
            self.assertTrue(outcome["sandbox_write_denied"])
            self.assertFalse((outside / "stolen").exists())
            self.assertFalse((parent / "forged.py").exists())

            fixture.admit()
            claim = fixture.q.claim("trusted-host", now=100, lease_seconds=10)
            receipt = fixture.q.apply_offline_test(fixture.spec["task_id"],
                                                   claim["token"],
                                                   fixture.proposal(), now=101)
            self.assertEqual(fixture.q.snapshot()["state"], "CHECKPOINTED_TEST")
            self.assertFalse(receipt["model_invoked"])
            self.assertFalse(receipt["published"])
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
