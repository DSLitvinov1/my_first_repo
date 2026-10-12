"""Independent acceptance tests: not part of model-written CRM source."""
import importlib, json, os, pathlib, subprocess, sys, tempfile, unittest

TEST_ROOT=pathlib.Path(os.environ["CRM_TARGET"]).resolve()
sys.path.insert(0,str(TEST_ROOT))
from crm import CRM

class CRMContract(unittest.TestCase):
    def setUp(self):
        self._tmp=tempfile.TemporaryDirectory(prefix="neurofactory_crm_")
        self.addCleanup(self._tmp.cleanup)
        self.path=pathlib.Path(self._tmp.name)/"cases.json"
        self.crm=CRM(str(self.path))
    def _sample(self):
        a=self.crm.add("Иван Тестовый","000-111","Звонок утром")
        b=self.crm.add("Мария Учебная","000-222","Запрос стоимости")
        return a,b
    def test_01_empty(self): self.assertEqual(self.crm.all(),[])
    def test_02_new_returns_dict(self):
        d=self.crm.add("Иван","123","Комментарий")
        self.assertIsInstance(d,dict);self.assertIsInstance(d.get("id"),int)
        self.assertEqual(d["status"],"new")
    def test_03_add(self): self.assertEqual(len(self._sample() and self.crm.all()),2)
    def test_04_ids(self):
        a,b=self._sample();self.assertNotEqual(a["id"],b["id"])
    def test_05_content(self):
        a,_=self._sample();self.assertEqual(a["name"],"Иван Тестовый")
        self.assertEqual(a["phone"],"000-111");self.assertEqual(a["note"],"Звонок утром")
    def test_06_search_name(self):
        self._sample();self.assertEqual(len(self.crm.search("ИВАН")),1)
    def test_07_search_phone(self):
        self._sample();self.assertEqual(len(self.crm.search("222")),1)
    def test_08_search_note(self):
        self._sample();self.assertEqual(len(self.crm.search("стоимости")),1)
    def test_09_search_missing(self):
        self._sample();self.assertEqual(self.crm.search("несуществующий"),[])
    def test_10_status(self):
        a,_=self._sample()
        self.crm.set_status(a["id"],"in_progress")
        self.assertEqual(self.crm.search("Иван")[0]["status"],"in_progress")
    def test_11_complete(self):
        a,_=self._sample();self.crm.set_status(a["id"],"done")
        self.assertEqual(self.crm.all()[0]["status"],"done")
    def test_12_edit_name(self):
        a,_=self._sample();self.crm.edit(a["id"],name="Пётр")
        self.assertEqual(len(self.crm.search("Пётр")),1)
    def test_13_edit_phone_note(self):
        a,_=self._sample();self.crm.edit(a["id"],phone="000-999",note="Готово")
        self.assertEqual(self.crm.search("Пётр"),[])
        self.assertEqual(self.crm.search("999")[0]["note"],"Готово")
    def test_14_save_exists(self):
        self._sample();self.assertTrue(self.path.is_file())
        raw=json.loads(self.path.read_text(encoding="utf-8"))
        self.assertIsNotNone(raw)
    def test_15_restore(self):
        self._sample();fresh=CRM(str(self.path));self.assertEqual(len(fresh.all()),2)
    def test_16_restore_changes(self):
        a,_=self._sample();self.crm.edit(a["id"],note="Обновлён")
        self.assertEqual(CRM(str(self.path)).search("Обновлён")[0]["id"],a["id"])
    def test_17_status_restore(self):
        a,_=self._sample();self.crm.set_status(a["id"],"done")
        self.assertEqual(CRM(str(self.path)).search("Иван")[0]["status"],"done")
    def test_18_next_id_after_reopen(self):
        a,_=self._sample();third=CRM(str(self.path)).add("Третий","000-333")
        self.assertNotIn(third["id"],[x["id"] for x in self.crm.all()])
    def test_19_no_collateral_edit(self):
        a,b=self._sample();self.crm.edit(a["id"],note="Изменено")
        untouched=next(x for x in self.crm.all() if x["id"]==b["id"])
        self.assertEqual(untouched["name"],"Мария Учебная")
    def test_20_cli_present(self):
        self.assertTrue((TEST_ROOT/"main.py").is_file())
        result=subprocess.run([sys.executable,"-S",str(TEST_ROOT/"main.py"),"--help"],
               text=True,capture_output=True,timeout=8,cwd=self._tmp.name,
               env={"PATH":os.environ.get("PATH",""),"HOME":self._tmp.name,
                    "PYTHONIOENCODING":"utf-8"})
        self.assertEqual(result.returncode,0,msg=result.stderr[-400:])

if __name__=="__main__":
    unittest.main(verbosity=2)
