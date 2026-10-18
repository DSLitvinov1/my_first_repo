"""Browser E2E against REAL localhost SQLite workspace integrated into the existing RU UI.
CI-only ephemeral data, no execution/queue, no Ollama calls except optional inventory.
"""
from __future__ import annotations
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import sys
from playwright.sync_api import sync_playwright
from local_workspace import WorkspaceStore, handler

def main():
    ui=Path(__file__).resolve().parent.parent/"control_ui"
    with TemporaryDirectory(prefix="nf-ui-local-e2e-") as temp:
        root=Path(temp)
        store=WorkspaceStore(root/"data")
        token="browser-suite-ci-only-ephemeral"
        server=ThreadingHTTPServer(("127.0.0.1",0),handler(store,ui,token,0))
        # Actual port is allocated by OS. Handler must pin the exact observed port.
        server.server_close()
        server=ThreadingHTTPServer(("127.0.0.1",0),handler(store,ui,token,0))
        # Replace handler after knowing the bound port, before starting serve_forever.
        server.RequestHandlerClass=handler(store,ui,token,server.server_port)
        host=f"http://127.0.0.1:{server.server_port}"
        worker=Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    for name,size in (("desktop",{"width":1440,"height":900}),
                                      ("mobile",{"width":390,"height":844})):
                        page=browser.new_page(viewport=size)
                        errors=[]
                        requests=[]
                        page.on("pageerror",lambda e:errors.append(str(e)))
                        page.on("request",lambda r:requests.append(r.url))
                        try:
                            response=page.goto(host+"/",wait_until="load",timeout=30000)
                            assert response and response.status==200
                            page.get_by_role("button",name="Локальная база").click()
                            page.get_by_role("heading",name="Рабочая база проектов").wait_for()
                            assert "Настоящее сохранение SQLite" in page.locator("#main-content").inner_text()
                            forms=page.locator("#main-content form")
                            form=forms.filter(has=page.get_by_role("button",name="Создать проект"))
                            form.locator("input").wait_for(timeout=8000)
                            assert form.count()==1, "project creation form missing"
                            form.locator("input").fill("Реальный проект "+name)
                            form.locator("textarea").fill("Изолированная тестовая задача")
                            form.get_by_role("button",name="Создать проект").click()
                            page.get_by_text("Реальный проект "+name,exact=True).first.wait_for()
                            page.get_by_role("heading",name="Новые задания").wait_for()
                            task_form=page.locator("#main-content form").filter(has=page.get_by_role("button",name="Сохранить задание"))
                            task_form.locator("textarea").fill(
                                "Подготовить безопасный текст без исполнения и публикации, "+name)
                            task_form.get_by_role("button",name="Сохранить задание").click()
                            page.get_by_text("Ожидает разрешения",exact=False).first.wait_for()
                            page.reload(wait_until="load")
                            page.get_by_role("button",name="Локальная база").click()
                            page.get_by_text("Реальный проект "+name,exact=True).first.wait_for()
                            page.get_by_text("Ожидает разрешения",exact=False).first.wait_for()
                            assert not page.locator("#main-content").get_by_role(
                                "button",name="Запустить ИИ").count()
                            page.get_by_role("button",name="Создать резервную копию").click()
                            page.get_by_text("Резервная копия сохранена:",exact=False).wait_for()
                            assert len(list((root/"data"/"backups").glob("*.sqlite3")))>=1
                            assert page.evaluate(
                                "document.documentElement.scrollWidth <= window.innerWidth + 2")
                            assert not errors,errors
                            assert requests and all(x.startswith(host+"/") for x in requests),requests
                            print(f"NF_LOCAL_BROWSER_{name.upper()}_HTTP_SQLITE_BACKUP=PASS_DRAFT_ONLY")
                        finally:
                            page.close()
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=4)
        assert len(store.list_projects())==2
        assert len(store.list_tasks())==2
        assert all(x["state"]=="DRAFT_PENDING_OWNER_AUTH" for x in store.list_tasks())
        print("NF_LOCAL_BROWSER_REAL_PERSISTED_RECORDS=2_PROJECTS_2_UNQUEUED_TASKS")

if __name__=="__main__":
    main()
