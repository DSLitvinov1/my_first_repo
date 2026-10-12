"""Offline tests for durable serial queue state transitions and safety boundaries."""
import copy
import hashlib
import unittest
import queue_core as q

H=lambda t: hashlib.sha256(t.encode()).hexdigest()
CRM="Создай учебную мини CRM для вымышленных заявок без интернета"
PACK="Создай учебный калькулятор упаковки и коробок без интернета"
COST="Сделай калькулятор стоимости заказа для учебных данных"

class QueueTests(unittest.TestCase):
    def setUp(self):
        self.queue=q.new_queue()
    def add(self,brief=CRM):
        return q.add_task(self.queue,brief)
    def evidence(self,stage,**kwargs):
        return {"verified_by_runner":True,"stage":stage,"outcome":"pass",**kwargs}
    def test_01_accept_russian_crm(self):
        self.assertEqual(self.add(),"NFQ-0001")
    def test_02_route_packaging(self):
        i=self.add(PACK);self.assertEqual(self.queue["tasks"][0]["kind"],"packaging_calculator")
    def test_03_route_cost(self):
        self.add(COST);self.assertEqual(self.queue["tasks"][0]["suite_size"],10)
    def test_04_serial_dispatch(self):
        self.add();self.add(PACK)
        x=q.next_action(self.queue);y=q.next_action(self.queue)
        self.assertEqual(x["task_id"],y["task_id"])
    def test_05_forbid_links(self):
        with self.assertRaises(q.QueueError):self.add(CRM+" https://example.com")
    def test_06_forbid_emails(self):
        with self.assertRaises(q.QueueError):self.add(CRM+" real@example.com")
    def test_07_forbid_secrets(self):
        with self.assertRaises(q.QueueError):self.add(CRM+" с токеном")
    def test_08_require_russian(self):
        with self.assertRaises(q.QueueError):self.add("Make a great Python application")
    def test_09_forbid_paid_policy(self):
        self.queue["paid_services"]=True
        with self.assertRaises(q.QueueError):q.validate_queue(self.queue)
    def test_10_block_unknown_without_suite(self):
        i=self.add("Сделай учебную игру на случайных числах")
        self.assertIsNone(q.next_action(self.queue))
        self.assertEqual(self.queue["tasks"][0]["state"],"blocked")
    def test_11_require_trusted_evidence(self):
        i=self.add();q.next_action(self.queue)
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,{"stage":"writer","outcome":"pass"})
    def test_12_require_unique_module_hashes(self):
        i=self.add();q.next_action(self.queue)
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("writer",source_hashes={"a":H("x"),"b":H("x")}))
    def test_13_require_20_tests(self):
        i=self.add();q.next_action(self.queue)
        q.accept_evidence(self.queue,i,self.evidence("writer",source_hashes={"a":H("a"),"b":H("b")}))
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("testing",total=20,passed=19))
    def test_14_reject_wrong_reviewer(self):
        i=self.add();q.next_action(self.queue)
        q.accept_evidence(self.queue,i,self.evidence("writer",source_hashes={"a":H("a"),"b":H("b")}))
        q.accept_evidence(self.queue,i,self.evidence("testing",total=20,passed=20))
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("reviewing",reviewer="same_writer",verdict="REVIEW_OK"))
    def test_15_require_publication_proof(self):
        i=self.add();q.next_action(self.queue)
        q.accept_evidence(self.queue,i,self.evidence("writer",source_hashes={"a":H("a"),"b":H("b")}))
        q.accept_evidence(self.queue,i,self.evidence("testing",total=20,passed=20))
        q.accept_evidence(self.queue,i,self.evidence("reviewing",reviewer="qwen3:4b",verdict="REVIEW_OK"))
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("publishing",manifest_sha256="bad"))
    def test_16_advance_to_next_after_verified(self):
        one=self.add();two=self.add(PACK)
        q.next_action(self.queue)
        q.accept_evidence(self.queue,one,self.evidence("writer",source_hashes={"storage":H("storage"),"crm":H("crm"),"main":H("main")}))
        q.accept_evidence(self.queue,one,self.evidence("testing",passed=20,total=20))
        q.accept_evidence(self.queue,one,self.evidence("reviewing",reviewer="qwen3:4b",verdict="REVIEW_OK"))
        q.accept_evidence(self.queue,one,self.evidence("publishing",manifest_sha256=H("published")))
        self.assertEqual(q.next_action(self.queue)["task_id"],two)
        self.assertEqual(q.progress(self.queue)["verified"],1)
    def test_17_failure_retry_and_cap(self):
        i=self.add();q.next_action(self.queue)
        for n in range(3):
            q.accept_evidence(self.queue,i,{"verified_by_runner":True,"stage":"writer","outcome":"fail","reason":"synthetic failure"})
        self.assertEqual(self.queue["tasks"][0]["state"],"failed")
        self.assertIsNone(q.next_action(self.queue))
    def test_18_reject_duplicate_id(self):
        i=self.add();self.queue["tasks"].append(copy.deepcopy(self.queue["tasks"][0]))
        with self.assertRaises(q.QueueError):q.validate_queue(self.queue)
    def test_19_reject_parallel_jobs(self):
        self.add();self.add(PACK)
        for t in self.queue["tasks"]:t["state"]="writing"
        with self.assertRaises(q.QueueError):q.validate_queue(self.queue)
    def test_20_forbid_out_of_order_review(self):
        i=self.add();q.next_action(self.queue)
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("reviewing",reviewer="qwen3:4b",verdict="REVIEW_OK"))
    def test_21_no_replay_done(self):
        i=self.add();q.next_action(self.queue)
        q.accept_evidence(self.queue,i,self.evidence("writer",source_hashes={"a":H("a"),"b":H("b")}))
        q.accept_evidence(self.queue,i,self.evidence("testing",total=20,passed=20))
        q.accept_evidence(self.queue,i,self.evidence("reviewing",reviewer="qwen3:4b",verdict="REVIEW_OK"))
        q.accept_evidence(self.queue,i,self.evidence("publishing",manifest_sha256=H("proof")))
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("publishing",manifest_sha256=H("proof")))
    def test_22_count_progress(self):
        self.add();self.add(PACK);self.add("Сделай игру с угадыванием числа")
        self.assertEqual(q.progress(self.queue),{"total":3,"verified":0,"failed":0,"blocked":1,"remaining":2})
    def test_23_queue_limit(self):
        for _ in range(q.MAX_TASKS):self.add()
        with self.assertRaises(q.QueueError):self.add()
    def test_24_source_digest_validity(self):
        i=self.add();q.next_action(self.queue)
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("writer",source_hashes={"a":"fake","b":H("b")}))
    def test_25_reject_cross_stage_evidence(self):
        i=self.add();q.next_action(self.queue)
        with self.assertRaises(q.QueueError):q.accept_evidence(self.queue,i,self.evidence("testing",passed=20,total=20))

if __name__=="__main__":
    unittest.main(verbosity=2)
