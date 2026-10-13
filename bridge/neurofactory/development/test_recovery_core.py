"""Production crash recovery invariants; only real Neurofactory task states."""
import pathlib
import unittest

import recovery_proposal as core

REFERENCE="""def resume_unfinished(task, now, max_attempts):
    item = task.copy()
    if item.get('state') == 'publishing':
        item['state'] = 'needs_receipt_check'
        return item
    if item.get('state') != 'running':
        return item
    lease = item.get('lease_until')
    if not isinstance(lease, int) or isinstance(lease, bool):
        item['state'] = 'needs_manual_review'
        return item
    if lease > now:
        return item
    attempts = item.get('attempts')
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
        item['state'] = 'needs_manual_review'
        return item
    if attempts >= max_attempts:
        item['state'] = 'retry_exhausted'
    else:
        item['state'] = 'queued'
    item['lease_until'] = None
    return item
"""

class RealRecoveryTests(unittest.TestCase):
    def test_real_interrupted_task_decisions(self):
        self.assertEqual(core.acceptance(REFERENCE),11)

    def test_forbidden_io_never_runs(self):
        dangerous=REFERENCE.replace("item = task.copy()","open('/tmp/secret','w'); item = task.copy()")
        with self.assertRaises(ValueError):
            core.check_source(dangerous)

    def test_forbidden_import_never_runs(self):
        with self.assertRaises(ValueError):
            core.check_source("import os\n"+REFERENCE)

    def test_writer_must_return_only_one_function(self):
        with self.assertRaises(ValueError):
            core.check_source(REFERENCE+"\ndef second(x):\n    return x\n")

    def test_writer_cannot_return_input_unchanged(self):
        wrong="""def resume_unfinished(task, now, max_attempts):
    return task
"""
        with self.assertRaises(ValueError):
            core.acceptance(wrong)

    def test_stage_four_real_state_active(self):
        from stage3_guard import read
        milestones={x["id"]:x for x in read()["milestones"]}
        self.assertEqual(milestones["NF-DEV-03"]["state"],"verified")
        self.assertEqual(milestones["NF-DEV-04"]["state"],"active")
        self.assertEqual(milestones["NF-DEV-02"]["state"],"deferred")

if __name__=="__main__":
    unittest.main(verbosity=2)
