"""Focused real-HTTP Chromium/WebKit smoke for isolated, non-live NEUROFACTORY UI.

This script starts only an ephemeral loopback HTTP server and makes no GitHub,
provider, queue, or production requests. Designed for GitHub-hosted Linux.
"""
from __future__ import annotations

import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent


class QuietHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, *_args):
        return


def check(browser, origin: str, name: str, width: int, height: int) -> None:
    page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=3 if name == "webkit_mobile" else 1, is_mobile=name == "webkit_mobile", has_touch=name == "webkit_mobile")
    requested: list[str] = []
    loaded: dict[str, int] = {}
    errors: list[str] = []
    page.on("request", lambda request: requested.append(request.url))
    page.on("response", lambda response: loaded.__setitem__(response.url, response.status))
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        response = page.goto(origin + "/index.html", wait_until="load", timeout=30000)
        assert response is not None and response.status == 200, "main HTML did not load over HTTP"
        page.get_by_role("heading", name="Центр наблюдения").wait_for(timeout=8000)
        for asset in ("index.html", "styles.css", "demo-data.js", "app.js"):
            assert loaded.get(origin + "/" + asset) == 200, ("asset not served", asset, loaded)
        assert page.evaluate("document.styleSheets.length") >= 1, "CSS did not load"
        assert page.locator("#navigation button").count() == 9, "missing navigation sections"
        assert "Демонстрационные данные" in page.locator(".warning-strip").inner_text()
        assert "UNKNOWN" in page.locator("#main-content").inner_text()
        for nav, heading in (
            ("Проекты", "Проекты и направления"),
            ("Очередь заданий", "Очередь заданий"),
            ("Исполнители", "Исполнители"),
            ("Ошибки и блокировки", "Ошибки и блокировки"),
            ("Контрольные точки", "Контрольные точки"),
            ("Независимая проверка", "Независимая проверка"),
            ("Карточка задания", "Карточка конкретного задания"),
            ("Новый проект", "Создание демо-проекта"),
        ):
            page.locator("#navigation button").filter(has_text=nav).click()
            page.get_by_role("heading", name=heading, exact=True).wait_for(timeout=4000)
        page.locator("#candidate-name").fill("HTTP браузерный тест")
        page.locator("#candidate-note").fill("Только локальная память")
        page.get_by_role("button", name="Сохранить локального кандидата").click()
        assert "HTTP браузерный тест" in page.locator("#main-content").inner_text()
        page.reload(wait_until="load")
        assert "HTTP браузерный тест" not in page.locator("#main-content").inner_text(), "candidate persisted unexpectedly"
        assert "Демонстрационные данные" in page.locator(".warning-strip").inner_text()
        # Accessibility regression: Import must be reachable by keyboard and launch
        # the native file chooser (also when its visible text is hidden on mobile).
        import_button = page.get_by_role("button", name="Импорт JSON")
        assert import_button.count() == 1, "import cannot be found as a button"
        page.locator("#reset-btn").focus()
        page.keyboard.press("Shift+Tab")
        assert page.evaluate("document.activeElement.id") == "import-btn", "import skipped in keyboard tab order"
        with page.expect_file_chooser(timeout=8000) as chooser:
            page.keyboard.press("Enter")
        chooser.value.set_files(str(ROOT / "demo-bundle.json"))
        page.get_by_text("Неподтверждённый локальный снимок", exact=False).wait_for(timeout=4000)
        with TemporaryDirectory() as tmp:
            base = json.loads((ROOT / "demo-bundle.json").read_text(encoding="utf-8"))
            malicious = json.loads(json.dumps(base))
            malicious["actions_allowed"]["publish"] = True
            p = Path(tmp) / "forged.json"
            p.write_text(json.dumps(malicious), encoding="utf-8")
            page.locator("#toast").evaluate("(el) => { el.hidden=true; el.textContent=''; }")
            page.locator("#file-input").set_input_files(str(p))
            page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')", timeout=4000)
            duplicate = Path(tmp) / "duplicate-keys.json"
            duplicate.write_text('{"schema":1,"schema":1}', encoding="utf-8")
            page.locator("#toast").evaluate("(el) => { el.hidden=true; el.textContent=''; }")
            page.locator("#file-input").set_input_files(str(duplicate))
            page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')", timeout=4000)
        assert "Неподтверждённый локальный снимок" in page.locator(".warning-strip").inner_text()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "horizontal overflow"
        assert not errors, errors
        assert requested and all(url.startswith(origin + "/") for url in requested), requested
        # Everything is loopback and 200. Do not use actual services, APIs, or credentials.
        assert not any("/api/" in url for url in requested), requested
        page.screenshot(path=str(ROOT / ("http_" + name + ".png")), full_page=True)
        print(f"HTTP {name} PASS, assets served: 4, requests: {len(requested)}, errors: {len(errors)}", flush=True)
    finally:
        page.close()


def main(engine: str) -> None:
    if engine not in ("chromium", "webkit"):
        raise ValueError("Unsupported browser engine")
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        with sync_playwright() as play:
            browser_type = getattr(play, engine)
            launch_options = {"headless": True}
            if engine == "chromium":
                launch_options["args"] = ["--no-sandbox"]
            browser = browser_type.launch(**launch_options)
            try:
                check(browser, origin, engine + "_desktop", 1440, 900)
                check(browser, origin, engine + "_mobile", 390, 844)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Offline UI HTTP smoke; no live APIs")
    parser.add_argument("--engine", choices=("chromium", "webkit"), default="chromium")
    main(parser.parse_args().engine)
