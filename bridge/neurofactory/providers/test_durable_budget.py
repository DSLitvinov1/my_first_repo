import json
import os
import multiprocessing
import tempfile
import threading
from pathlib import Path
import unittest
from unittest.mock import patch

import durable_budget as d
import local_qwen as q
from fallback_controller import MockClaudeToLocalQwen
from offline_router import OfflineScriptedProvider, QuotaExhausted, Request


def reserve_in_child(root, task_id, queue):
    try:
        d.DurableBudget(Path(root), max_attempts=2, max_reserved_units=5000).reserve(2, task_id)
        queue.put("reserved")
    except (d.DurableBudgetError, ValueError):
        queue.put("stopped")


class DurableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='neurofactory-provider-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.budget=d.DurableBudget(self.root, max_attempts=2, max_reserved_units=5000)

    def test_persist_then_new_instance_detects_same_task(self):
        self.budget.reserve(4,"task-1")
        new=d.DurableBudget(self.root,max_attempts=2,max_reserved_units=5000)
        with self.assertRaises(d.DuplicateTask):new.reserve(4,"task-1")
        self.assertEqual(new.snapshot()['attempts'],1)
        self.assertEqual(new.snapshot()['reserved_units'],4)

    def test_second_task_within_limit(self):
        self.budget.reserve(100,"task-1")
        self.budget.reserve(200,"task-2")
        self.assertEqual(self.budget.snapshot()['reserved_units'],300)
        self.assertEqual(self.budget.snapshot()['attempts'],2)
        with self.assertRaises(d.DurableLimitExceeded):self.budget.reserve(1,"task-3")

    def test_no_repeat_side_effect_after_transport_failure(self):
        adapter=q.LocalQwenAdapter(q.LocalQwenConfig(enabled=True),self.budget)
        with patch.object(q,'_loopback_post',side_effect=q.LocalProviderUnknownResult('timeout')) as send:
            with self.assertRaises(q.LocalProviderUnknownResult):adapter.generate('hello',task_id='same-job')
            with self.assertRaises(d.DuplicateTask):adapter.generate('hello',task_id='same-job')
            self.assertEqual(send.call_count,1)
        self.assertEqual(self.budget.snapshot()['attempts'],1)

    def test_task_id_required_before_any_effect(self):
        adapter=q.LocalQwenAdapter(q.LocalQwenConfig(enabled=True),self.budget)
        with patch.object(q,'_loopback_post') as send:
            with self.assertRaises(ValueError):adapter.generate('hello')
            send.assert_not_called()
        self.assertEqual(self.budget.snapshot()['attempts'],0)

    def test_duplicate_task_with_different_prompt_stopped(self):
        self.budget.reserve(1,'same')
        with self.assertRaises(d.DuplicateTask):self.budget.reserve(3,'same')

    def test_lock_remaining_after_interrupted_process_stops(self):
        (self.root/'reservation.lock').mkdir()
        with self.assertRaises(d.DurableBudgetError):self.budget.reserve(1,'task01')
        self.assertTrue((self.root/'reservation.lock').is_dir())

    def test_pending_state_blocks_and_preserves_lock(self):
        (self.root/'reservations.pending').write_text('{unfinished')
        with self.assertRaises(d.DurableBudgetError):self.budget.reserve(1,'task01')
        self.assertTrue((self.root/'reservation.lock').is_dir())

    def test_tampered_json_stops(self):
        (self.root/'reservations.json').write_text('{"version":1,"version":1}')
        with self.assertRaises(d.DurableBudgetError):self.budget.reserve(1,'task01')

    def test_changed_limits_cannot_reset_counters(self):
        self.budget.reserve(1,'task01')
        wrong=d.DurableBudget(self.root,max_attempts=99,max_reserved_units=5000)
        with self.assertRaises(d.DurableBudgetError):wrong.reserve(1,'task02')

    def test_boolean_state_cannot_bypass(self):
        self.budget.reserve(1,'task01')
        state=json.loads((self.root/'reservations.json').read_text())
        state['attempts']=True
        (self.root/'reservations.json').write_text(json.dumps(state))
        with self.assertRaises(d.DurableBudgetError):self.budget.reserve(1,'task02')

    def test_symlink_directory_rejected(self):
        symlink=self.root/'link'
        try: symlink.symlink_to(self.root,target_is_directory=True)
        except (OSError,NotImplementedError):self.skipTest('symlinks unavailable')
        with self.assertRaises(ValueError):d.DurableBudget(symlink)

    def test_symlink_state_rejected(self):
        other=self.root/'outside.json'
        other.write_text('{}')
        try:(self.root/'reservations.json').symlink_to(other)
        except (OSError,NotImplementedError):self.skipTest('symlinks unavailable')
        with self.assertRaises(d.DurableBudgetError):self.budget.reserve(1,'task01')

    def test_concurrent_threads_one_owns_one_task(self):
        results=[]
        barrier=threading.Barrier(12)
        def worker():
            barrier.wait()
            try:self.budget.reserve(10,'single-task');results.append('yes')
            except d.DurableBudgetError:results.append('no')
        workers=[threading.Thread(target=worker) for _ in range(12)]
        for w in workers:w.start()
        for w in workers:w.join()
        self.assertEqual(results.count('yes'),1)
        self.assertEqual(self.budget.snapshot()['attempts'],1)

    def test_concurrent_processes_one_owns_same_task(self):
        ctx=multiprocessing.get_context('spawn')
        out=ctx.Queue()
        children=[ctx.Process(target=reserve_in_child,args=(str(self.root),'same-task',out)) for _ in range(3)]
        for c in children:c.start()
        for c in children:c.join(15)
        self.assertTrue(all(c.exitcode==0 for c in children))
        results=[out.get(timeout=3) for _ in children]
        self.assertEqual(results.count('reserved'),1)
        self.assertEqual(self.budget.snapshot()['attempts'],1)

    def test_fail_closed_on_fs_write_error(self):
        # Failure before a durable state commit leaves a lock for operator inspection.
        with patch.object(d.os,'replace',side_effect=OSError('storage unavailable')):
            with self.assertRaises(OSError):self.budget.reserve(10,'task01')
        self.assertTrue((self.root/'reservation.lock').exists())
        self.assertTrue((self.root/'reservations.pending').exists())
        with self.assertRaises(d.DurableBudgetError):self.budget.reserve(10,'task02')

    def test_mock_fallback_to_durable_local_still_idempotent(self):
        adapter=q.LocalQwenAdapter(q.LocalQwenConfig(enabled=True),self.budget)
        controller=MockClaudeToLocalQwen(OfflineScriptedProvider('claude',[QuotaExhausted('free limit'),QuotaExhausted('again')]),adapter)
        data=b'{"model":"qwen3:4b","response":"OK","done":true}'
        with patch.object(q,'_loopback_post',return_value=data) as send:
            a=controller.run(Request('task01','hello'))
            self.assertTrue(a.local_fallback)
            with self.assertRaises(d.DuplicateTask):controller.run(Request('task01','hello'))
            self.assertEqual(send.call_count,1)

    def test_unknown_receipt_after_process_reopen(self):
        self.budget.reserve(20,'aborted-job')
        reopened=d.DurableBudget(self.root,max_attempts=2,max_reserved_units=5000)
        with self.assertRaises(d.DuplicateTask):reopened.reserve(20,'aborted-job')

    def test_no_automatic_unlock_after_incorrect_policy(self):
        self.budget.reserve(1,'task01')
        mismatched=d.DurableBudget(self.root,max_attempts=3,max_reserved_units=5000)
        with self.assertRaises(d.DurableBudgetError):mismatched.reserve(1,'task02')
        self.assertTrue((self.root/'reservation.lock').exists())

    def test_zero_unit_no_io(self):
        with self.assertRaises(ValueError):self.budget.reserve(0,'task01')
        self.assertFalse((self.root/'reservation.lock').exists())

    def test_empty_task_id_no_io(self):
        with self.assertRaises(ValueError):self.budget.reserve(1,'')
        self.assertFalse((self.root/'reservation.lock').exists())

    def test_prohibited_path_no_autocreate(self):
        with self.assertRaises(ValueError):d.DurableBudget(self.root/'absent')
        self.assertFalse((self.root/'absent').exists())


if __name__=='__main__':unittest.main()
