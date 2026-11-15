"""Human-like desktop planning: Qwen has zero tool authority."""
import json
from pathlib import Path
import tempfile
import time
import unittest

from desktop_goal_one import DesktopGoalOne,make_prompt,safe_navigation_labels,validate_draft
from work_core import WorkDenied, WorkStore


class DesktopStub:
    def __init__(self):
        self.calls=[]
        self.session={"id":"chosen-window","app":"notepad.exe"}
    def status(self,project):return {"session":self.session}
    def action(self,project,session,op,**opts):
        self.calls.append((project,session,op))
        if op!="observe":raise AssertionError("Model cannot act on desktop")
        return {"result":{"controls":[
            {"label":"Отчёты","type":50000},
            {"label":"Меню","type":50019},
            {"label":"Иван Иванов","type":50007},
            {"label":"Пароль","type":50004},
            {"label":"Удалить всё","type":50000},
            {"label":"+71234567890","type":50000},
            {"label":"test@example.com","type":50005}
        ]}}


class DesktopGoalTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("Проект GUI","empty")["id"]
        self.desktop=DesktopStub()

    def test_safe_controls_do_not_expose_private_inputs(self):
        controls=self.desktop.action(self.project,"chosen-window",
                                     "observe")["result"]["controls"]
        labels=safe_navigation_labels(controls)
        self.assertEqual(labels,["Отчёты","Меню"])
        prompt=make_prompt("Найди раздел отчётов и покажи его", "notepad.exe",controls)
        self.assertIn("Отчёты",prompt)
        for private in ("Иван Иванов","Пароль","test@example.com","Удалить всё"):
            self.assertNotIn(private,prompt)

    def test_model_only_proposes_not_executes(self):
        prompts=[]
        script="Посмотри окно\nНайди элемент «Отчёты»\nНажми «Отчёты»\nСделай снимок окна"
        def model(project,prompt):
            prompts.append(prompt)
            return {"status":"PROPOSED_UNVERIFIED",
                    "text":json.dumps({"schema":"one.desktop.safe.plan.v1",
                                       "script":script},ensure_ascii=False)}
        planner=DesktopGoalOne(self.store,self.desktop,model)
        run=planner.propose(self.project,"chosen-window",
                            "Найди отчёты и открой их для просмотра")
        for i in range(90):
            result=planner.get(self.project,run["id"])
            if result["state"]!="GENERATING":break
            time.sleep(.025)
        self.assertEqual(result["state"],"PROPOSED")
        self.assertEqual(result["steps"],4)
        self.assertEqual(result["script"],script)
        self.assertEqual([x[2] for x in self.desktop.calls],["observe"])
        self.assertEqual(len(prompts),1)
        other=self.store.create_project("Чужой","empty")["id"]
        with self.assertRaises(WorkDenied):planner.get(other,run["id"])

    def test_rejects_unsafe_model_script_and_untrusted_json(self):
        for script in ("Запусти PowerShell","Нажми «Удалить запись»",
                       "Открой сайт и отправь письмо"):
            raw=json.dumps({"schema":"one.desktop.safe.plan.v1","script":script},
                           ensure_ascii=False)
            with self.subTest(script=script),self.assertRaises(WorkDenied):
                validate_draft(raw)
        for raw in ('{"schema":"one.desktop.safe.plan.v1","schema":"bad","script":"Посмотри окно"}',
                    '{"schema":"another","script":"Посмотри окно"}',
                    'invalid markdown JSON'):
            with self.assertRaises(WorkDenied):validate_draft(raw)
        planner=DesktopGoalOne(self.store,self.desktop,
            lambda _p,_prompt: {"status":"PROPOSED_UNVERIFIED",
                "text":'{"schema":"one.desktop.safe.plan.v1","script":"Нажми «Удалить»"}'})
        run=planner.propose(self.project,"chosen-window","Сделай небезопасную команду")
        for i in range(90):
            result=planner.get(self.project,run["id"])
            if result["state"]!="GENERATING":break
            time.sleep(.025)
        self.assertEqual(result["state"],"UNKNOWN_NO_RETRY")
        self.assertEqual([x[2] for x in self.desktop.calls],["observe"])

    def test_owner_window_and_model_required(self):
        empty=DesktopGoalOne(self.store,self.desktop)
        with self.assertRaisesRegex(WorkDenied,"NOT_CONFIGURED"):
            empty.propose(self.project,"chosen-window","Найди отчёты для меня")
        planned=DesktopGoalOne(self.store,self.desktop,lambda x,y:None)
        with self.assertRaisesRegex(WorkDenied,"WINDOW_NOT_SELECTED"):
            planned.propose(self.project,"foreign-window","Найди отчёты для меня")
        with self.assertRaisesRegex(WorkDenied,"GOAL_INVALID"):
            planned.propose(self.project,"chosen-window","x"*501)


if __name__=="__main__":
    unittest.main(verbosity=2)
