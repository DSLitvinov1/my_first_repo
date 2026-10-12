"""Offline regression and interruption recovery tests; never start a model or network."""
import copy
import hashlib
import os
import tempfile
import unittest
from unittest import mock
import queue_core as q
import queue_runner as runner
import new_app_factory as factory

NEW_ONE = "Создай учебный конвертер температуры Цельсия и Фаренгейта без интернета"
NEW_TWO = "Создай учебный расчёт топлива для поездки с расходом и ценой за литр"

class FactoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.object(factory, "OUTPUT", __import__("pathlib").Path(self.tmp.name))
        patch.start()
        self.addCleanup(patch.stop)
    def source(self, kind, module):
        cfg = factory.SPECS[kind]["modules"][module]
        return "def " + module + "(" + ", ".join(cfg["args"]) + "):\n    return " + cfg["formula"] + "\n"
    def fixture(self, kind, task_id):
        spec = factory.SPECS[kind]
        for module in spec["modules"]:
            factory.source_file(task_id, module + ".py").write_text(self.source(kind,module), "utf-8")
        factory.source_file(task_id,"main.py").write_text(factory.trusted_main(kind), "utf-8")
        factory.source_file(task_id,"test_app.py").write_text(factory.trusted_tests(kind), "utf-8")
        factory.source_file(task_id,"README.md").write_text("Offline fixture\n","utf-8")
        names = [m + ".py" for m in spec["modules"]] + ["main.py", "test_app.py", "README.md"]
        proof = {"status":"two_models_reviewed","task_id":task_id,"kind":kind,
                 "writer":factory.WRITER,"reviewer":factory.REVIEWER,
                 "review_verdict":"REVIEW_OK","tests_passed":10,
                 "sha256":{name:hashlib.sha256(factory.source_file(task_id,name).read_bytes()).hexdigest()
                           for name in names}}
        import json
        factory.source_file(task_id,"verification-manifest.json").write_text(
            json.dumps(proof)+"\n","utf-8")
        return proof
    def test_01_new_temperature_route(self):
        self.assertEqual(q.route(NEW_ONE),"temperature_converter")
    def test_02_new_fuel_route(self):
        self.assertEqual(q.route(NEW_TWO),"fuel_trip_estimator")
    def test_03_new_temperature_contracts(self):
        for mod in factory.SPECS["temperature_converter"]["modules"]:
            self.assertEqual(factory.verify(self.source("temperature_converter",mod),
                                            "temperature_converter",mod),4)
    def test_04_new_fuel_contracts(self):
        for mod in factory.SPECS["fuel_trip_estimator"]["modules"]:
            self.assertEqual(factory.verify(self.source("fuel_trip_estimator",mod),
                                            "fuel_trip_estimator",mod),4)
    def test_05_temperature_10_real_offline_tests(self):
        self.fixture("temperature_converter","NFQ-0001")
        self.assertEqual(factory.acceptance("temperature_converter","NFQ-0001"),10)
    def test_06_fuel_10_real_offline_tests(self):
        self.fixture("fuel_trip_estimator","NFQ-0002")
        self.assertEqual(factory.acceptance("fuel_trip_estimator","NFQ-0002"),10)
    def test_07_manifest_integrity(self):
        self.fixture("temperature_converter","NFQ-0001")
        self.assertEqual(factory.verify_published_candidate("temperature_converter","NFQ-0001")["tests_passed"],10)
    def test_08_tamper_denied(self):
        self.fixture("temperature_converter","NFQ-0001")
        factory.source_file("NFQ-0001","celsius_to_fahrenheit.py").write_text("def hacked():return 1\n","utf-8")
        with self.assertRaises(ValueError):
            factory.verify_published_candidate("temperature_converter","NFQ-0001")
    def test_09_injected_command_denied(self):
        with self.assertRaises(ValueError):
            factory.verify("def fuel_cost(liters, price_per_liter):\n    return __import__('os').system('pwd')\n",
                           "fuel_trip_estimator","fuel_cost")
    def test_10_network_call_denied(self):
        with self.assertRaises(ValueError):
            factory.verify("def fuel_cost(liters, price_per_liter):\n    return open('secrets')\n",
                           "fuel_trip_estimator","fuel_cost")
    def test_11_wrong_task_id_denied(self):
        with self.assertRaises(ValueError):
            factory.safe_id("../../other-project")
    def test_12_proof_for_wrong_task_denied(self):
        self.fixture("fuel_trip_estimator","NFQ-0002")
        saved=factory.source_file("NFQ-0002","verification-manifest.json").read_bytes()
        factory.source_file("NFQ-0001","verification-manifest.json").write_bytes(saved)
        with self.assertRaises(ValueError):
            factory.verify_published_candidate("fuel_trip_estimator","NFQ-0001")
    def test_13_can_replay_published_proof_without_model(self):
        state=q.new_queue()
        t=q.add_task(state,NEW_ONE)
        q.next_action(state)
        manifest=self.fixture("temperature_converter",t)
        receipt=hashlib.sha256(b"proof").hexdigest()
        with mock.patch.object(runner,"verified_remote_receipt",return_value=(manifest,receipt)), \
             mock.patch.object(runner,"run_writer",side_effect=AssertionError("must not rerun AI")), \
             mock.patch.object(runner,"write_queue",return_value="newsha") as saved:
            self.assertEqual(runner.handle_task(state,"oldsha",{
                "task_id":t, "kind":"temperature_converter","stage":"writer"}),"newsha")
        self.assertEqual(state["tasks"][0]["state"],"verified_done")
        saved.assert_called_once()
    def test_14_crash_before_publication_resets_to_writer(self):
        state=q.new_queue()
        t=q.add_task(state,NEW_ONE)
        q.next_action(state)
        manifest=self.fixture("temperature_converter",t)
        runner.commit_proof_states(state,t,manifest)
        self.assertEqual(state["tasks"][0]["state"],"publishing")
        # simulate interrupted publisher: durable queue resumes without model source
        with mock.patch.object(runner,"verified_remote_receipt",return_value=None), \
             mock.patch.object(runner,"write_queue",return_value="sha2"), \
             mock.patch.object(runner,"run_writer",side_effect=RuntimeError("simulated network interruption")):
            with self.assertRaises(RuntimeError):
                runner.handle_task(state,"oldsha",{
                   "task_id":t, "kind":"temperature_converter","stage":"publishing"})
        self.assertEqual(state["tasks"][0]["state"],"writing")
        self.assertEqual(state["tasks"][0]["attempts"],1)
    def test_15_sequential_two_different_new_tasks(self):
        state=q.new_queue()
        first=q.add_task(state,NEW_ONE)
        second=q.add_task(state,NEW_TWO)
        self.assertEqual(q.next_action(state)["task_id"],first)
        proof=self.fixture("temperature_converter",first)
        runner.commit_proof_states(state,first,proof)
        q.accept_evidence(state,first,{"verified_by_runner":True,"stage":"publishing",
                                       "outcome":"pass","manifest_sha256":hashlib.sha256(b"commit").hexdigest()})
        self.assertEqual(q.next_action(state)["task_id"],second)
        self.assertEqual(q.progress(state)["verified"],1)
    def test_16_duplicate_module_safe_stop(self):
        proof=self.fixture("temperature_converter","NFQ-0001")
        other="fahrenheit_to_celsius.py"
        proof["sha256"][other]=proof["sha256"]["celsius_to_fahrenheit.py"]
        import json
        factory.source_file("NFQ-0001","verification-manifest.json").write_text(json.dumps(proof),"utf-8")
        with self.assertRaises(ValueError):
            factory.verify_published_candidate("temperature_converter","NFQ-0001")

if __name__=="__main__":
    unittest.main(verbosity=2)
