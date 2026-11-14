"""Offline regression for owner-authorized desktop tasks, no real GUI calls."""
import time
import unittest

from desktop_script_one import DesktopScriptOne, parse_safe_desktop_script
from work_core import WorkDenied


PROJECT = "e" * 32
SESSION = "f" * 32


class FakeStore:
    def project(self, name):
        if name != PROJECT:
            raise WorkDenied("PROJECT_NOT_FOUND")


class FakeDesktop:
    def __init__(self):
        self.store = FakeStore()
        self.attached = {"id": SESSION, "app": "notepad.exe"}
        self.calls = []
        self.fail_after = None

    def status(self, project):
        self.store.project(project)
        return {"session": self.attached}

    def action(self, project, session, op, **kwargs):
        self.store.project(project)
        if not self.attached or session != self.attached["id"]:
            raise WorkDenied("DESKTOP_SESSION_REFUSED")
        if self.fail_after is not None and len(self.calls) >= self.fail_after:
            raise WorkDenied("DESKTOP_TARGET_CHANGED")
        self.calls.append((op, kwargs))
        return {"result": {"ok": True}}


class DesktopScriptTests(unittest.TestCase):
    def test_grammar_safe_multistep(self):
        script = ('Нажми кнопку «Главная»\nПрокрути вниз на 2 шага\n'
                  'Введи в поле «Название» текст «Новая задача»\n'
                  'Нажми Ctrl+F\nСделай снимок')
        steps = parse_safe_desktop_script(script)
        self.assertEqual([x["op"] for x in steps],
                         ["click_label", "scroll", "type_label", "key", "frame"])
        self.assertEqual(steps[1]["steps"], 2)
        self.assertEqual(steps[3]["key"], "ctrl_f")

    def test_focused_editor_unicode_safe_grammar(self):
        script = ('Нажми кнопку «Открыть тест»\nНажми Tab\n'
                  'Напечатай «ONE проверка»\nСделай снимок')
        steps = parse_safe_desktop_script(script)
        self.assertEqual([x["op"] for x in steps],
                         ["click_label", "key", "type", "frame"])
        self.assertEqual(steps[2]["text"], "ONE проверка")
        for bad in ("Напечатай «»", "Напечатай «a\\nb»",
                    "Напечатай «" + "a"*501 + "»"):
            with self.subTest(bad=bad[:20]),self.assertRaises(WorkDenied):
                parse_safe_desktop_script(bad)

    def test_unsafe_commands_never_enter_plan(self):
        for command in (
            "Удалить всю почту", "Отправь сообщение",
            "Нажми кнопку «Удалить»", "Нажми кнопку «Отправить»",
            "Нажми кнопку «Save»", "Нажми кнопку «Pay now»",
            "Введи в поле «Пароль» текст «12345»",
            "Введи в поле «Token» текст «private»",
            "Нажми Ctrl+S", "Нажми Enter",
            "Нажми кнопку «Выйти»\n".join(["Сделай снимок"] * 9),
            "Прокрути вниз на 7 шага", "Запусти PowerShell",
            "Нажми кнопку «Удалить»\nСделай снимок",
        ):
            with self.subTest(command=command[:40]), self.assertRaises(WorkDenied):
                parse_safe_desktop_script(command)

    def test_approval_is_exact_one_time_and_window_bound(self):
        desktop = FakeDesktop()
        runner = DesktopScriptOne(desktop)
        script = "Нажми кнопку «Файл»\nПрокрути вниз на 2 шага\nСделай снимок"
        plan = runner.prepare(PROJECT, SESSION, script)
        self.assertEqual(plan["state"], "READY")
        with self.assertRaises(WorkDenied):
            runner.start(PROJECT, SESSION, plan["id"], script + "\nНажми Tab")
        with self.assertRaises(WorkDenied):
            runner.start("a"*32, SESSION, plan["id"], script)
        started = runner.start(PROJECT, SESSION, plan["id"], script)
        self.assertEqual(started["state"], "RUNNING")
        with self.assertRaises(WorkDenied):
            runner.start(PROJECT, SESSION, plan["id"], script)
        until = time.monotonic() + 3
        while time.monotonic() < until and runner.get(PROJECT, plan["id"])["state"] == "RUNNING":
            time.sleep(.03)
        result = runner.get(PROJECT, plan["id"])
        self.assertEqual(result["state"], "DONE")
        self.assertEqual(result["completed"], 3)
        self.assertEqual([x[0] for x in desktop.calls], ["click_label", "scroll", "frame"])

    def test_early_stop_is_not_replayed(self):
        desktop = FakeDesktop()
        desktop.fail_after = 1
        runner = DesktopScriptOne(desktop)
        script = "Сделай снимок\nНажми Tab\nПрокрути вверх"
        plan = runner.prepare(PROJECT, SESSION, script)
        runner.start(PROJECT, SESSION, plan["id"], script)
        until = time.monotonic() + 2
        while time.monotonic() < until and runner.get(PROJECT, plan["id"])["state"] == "RUNNING":
            time.sleep(.02)
        self.assertEqual(runner.get(PROJECT, plan["id"])["state"], "STOPPED")
        self.assertEqual(runner.get(PROJECT, plan["id"])["error"], "DESKTOP_TARGET_CHANGED")
        self.assertEqual(len(desktop.calls), 1)
        with self.assertRaises(WorkDenied):
            runner.start(PROJECT, SESSION, plan["id"], script)

    def test_attach_required_and_not_cross_project(self):
        desktop = FakeDesktop()
        desktop.attached = None
        runner = DesktopScriptOne(desktop)
        with self.assertRaises(WorkDenied):
            runner.prepare(PROJECT, SESSION, "Сделай снимок")
        desktop.attached = {"id": SESSION, "app": "notepad.exe"}
        plan = runner.prepare(PROJECT, SESSION, "Сделай снимок")
        desktop.attached = None
        with self.assertRaises(WorkDenied):
            runner.start(PROJECT, SESSION, plan["id"], "Сделай снимок")
        with self.assertRaises(WorkDenied):
            runner.get("a"*32, plan["id"])


if __name__ == "__main__":
    unittest.main()
