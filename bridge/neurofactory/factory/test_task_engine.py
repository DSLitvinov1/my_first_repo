"""Deterministic independent tests of the reusable bounded factory queue."""
import copy,datetime as dt,unittest
import task_engine as f
TIME=dt.datetime(2026,10,12,12,0,tzinfo=dt.timezone.utc)
BRIEF="Сделать учебную CRM с добавлением заявок, поиском, изменением статусов и сохранением в локальном JSON."
def item(name="test_crm"):
    return {"id":name,"scope":"public_synthetic_only","branch":"neurofactory-crm-autonomous-20261012",
            "brief":BRIEF,"stage":"queued","attempts":0,"files":["storage.py","crm.py","main.py"],
            "updated_at":TIME.isoformat(),"published":False}
class SafeFactoryQueue(unittest.TestCase):
    def test_01_queue_validation(self):
        self.assertTrue(f.validate_queue({"paid_services":False,"working_projects":False,"tasks":[item()]}))
    def test_02_denies_private_projects(self):
        a=item();a["scope"]="client_private"
        with self.assertRaises(ValueError):f.validate_task(a)
    def test_03_denies_path_traversal(self):
        a=item();a["files"]=["../secret.py","crm.py"]
        with self.assertRaises(ValueError):f.validate_task(a)
    def test_04_denies_duplicate_ids(self):
        q={"paid_services":False,"working_projects":False,"tasks":[item(),item()]}
        with self.assertRaises(ValueError):f.validate_queue(q)
    def test_05_full_verified_lifecycle(self):
        a=item()
        f.transition(a,"begin",TIME);self.assertEqual(a["attempts"],1)
        f.transition(a,"advance",TIME);self.assertEqual(a["stage"],"coding")
        f.transition(a,"advance",TIME);self.assertEqual(a["stage"],"testing")
        for stage in ("review","publishing","completed"):
            f.transition(a,"advance",TIME,proof={"ok":True,"evidence":"independent tests"})
            self.assertEqual(a["stage"],stage)
        self.assertTrue(a["published"])
        with self.assertRaises(ValueError):f.transition(a,"advance",TIME)
    def test_06_cannot_approve_without_proof(self):
        a=item();f.transition(a,"begin",TIME)
        f.transition(a,"advance",TIME);f.transition(a,"advance",TIME)
        with self.assertRaises(ValueError):f.transition(a,"advance",TIME)
    def test_07_memory_pause_keeps_attempt(self):
        a=item();f.transition(a,"begin",TIME);f.transition(a,"memory_wait",TIME)
        self.assertEqual(a["stage"],"waiting_memory")
        f.transition(a,"resume",TIME)
        self.assertEqual(a["stage"],"planning");self.assertEqual(a["attempts"],1)
    def test_08_error_retry_limit(self):
        a=item()
        f.transition(a,"begin",TIME);f.transition(a,"fail",TIME)
        self.assertEqual(a["stage"],"queued")
        f.transition(a,"begin",TIME);f.transition(a,"fail",TIME)
        self.assertEqual(a["stage"],"failed")
        self.assertEqual(a["attempts"],2)
    def test_09_stale_in_progress_recovery(self):
        a=item();f.transition(a,"begin",TIME)
        q={"tasks":[a]};later=TIME+dt.timedelta(hours=1)
        self.assertEqual(f.restore_stale(q,later),1);self.assertEqual(a["stage"],"queued")
    def test_10_stale_exhausted_does_not_replay(self):
        a=item();a.update(stage="coding",attempts=2)
        q={"tasks":[a]};self.assertEqual(f.restore_stale(q,TIME+dt.timedelta(hours=2)),1)
        self.assertEqual(a["stage"],"failed")
    def test_11_do_not_start_concurrent_tasks(self):
        a=item();b=item("another_job")
        f.transition(a,"begin",TIME)
        q={"paid_services":False,"working_projects":False,"tasks":[a,b]}
        self.assertIsNone(f.next_task(q))
    def test_12_select_first_queued(self):
        q={"paid_services":False,"working_projects":False,"tasks":[item(),item("next_job")]}
        self.assertEqual(f.next_task(q)["id"],"test_crm")
    def test_13_audit_bounded(self):
        a=item()
        a["audit"]=[{"event":"old"}]*100
        f.transition(a,"begin",TIME)
        self.assertLessEqual(len(a["audit"]),80)
    def test_14_client_brief_does_not_execute(self):
        a=item();a["brief"]="Сделайте только фиктивную учебную программу " + "x"*100
        self.assertTrue(f.validate_task(a))
    def test_15_reject_wrong_branch(self):
        a=item();a["branch"]="main"
        with self.assertRaises(ValueError):f.validate_task(a)
if __name__=="__main__":
    unittest.main(verbosity=2)
