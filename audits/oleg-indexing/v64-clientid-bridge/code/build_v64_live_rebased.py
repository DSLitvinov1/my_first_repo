#!/usr/bin/env python3
"""V64 offline-only patch. Never writes Timeweb or Bitrix24."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

ROOT = Path("/home/cloudagent/projects/oleg-seo-v26-clientid-bridge-20261120")
SITES = ROOT / "live-rebased"
SCRIPT = (ROOT / "code/oleg-clientid-bridge-v1.js").read_bytes()
TARGETS = {
    "potrebpravo.ru": (114249897, "crm_form_fhi3n"),
    "semya-yurist.ru": (114251443, "crm_form_ep5fd"),
}

def patch_one(host: str) -> dict:
    counter, form = TARGETS[host]
    site = SITES / host / "public_html"
    path = site / "assets/oleg-analytics-v1.js"
    analytics = path.read_text(encoding="utf-8")
    assert analytics.count("oleg.analytics.choice.v1") == 2, (host, "consent markers")
    assert f"const counter = {counter};" in analytics, host
    assert "webvisor: false" in analytics, host
    text = "Разрешить Яндекс Метрику для анализа посещаемости? Она использует cookie и технические сведения о посещении. Вебвизор и запись заполнения форм отключены."
    extended = ("Разрешить Яндекс Метрику для анализа посещаемости и связи обращения "
                "с посещением сайта? При открытии формы Битрикс24 может передаваться "
                "псевдонимный идентификатор посетителя ClientID для оценки результатов "
                "обращений. Cookie используются только после разрешения; "
                "Вебвизор и запись ввода в формы отключены.")
    assert text in analytics, (host, "consent copy changed")
    analytics = analytics.replace(text, extended, 1)
    analytics = analytics.replace("oleg.analytics.choice.v1", "oleg.analytics.choice.v2")
    # The form-open event remains an intent goal even when a valid ClientID adds a query string.
    old = "if (frame.src === intended) send('oleg_crm_form_open');"
    new = ("try { var actual = new URL(frame.src); "
           "if (actual.origin === new URL(intended).origin && "
           "actual.pathname === new URL(intended).pathname) "
           "send('oleg_crm_form_open'); } catch (_) {}")
    assert analytics.count(old) == 1, host
    analytics = analytics.replace(old, new, 1)
    path.write_text(analytics, encoding="utf-8")
    client_script = site / "assets/oleg-clientid-bridge-v1.js"
    client_script.write_bytes(SCRIPT)
    # Preserve the original, already working iframe form; augment only the URL
    # immediately before user-initiated form opening.
    assistant = site / "assets/legal-assistant-v4.js"
    js = assistant.read_text(encoding="utf-8")
    assert js.count("oleg.analytics.choice.v1") == 1, (host,"assistant consent marker")
    js = js.replace("oleg.analytics.choice.v1", "oleg.analytics.choice.v2")
    assert js.count("if (!frame.src) frame.src = formUrl;") == 1, host
    js = js.replace("if (!frame.src) frame.src = formUrl;",
         "if (!frame.src) frame.src = window.__olegClientIdBridgeV1 ? window.__olegClientIdBridgeV1.augment(formUrl) : formUrl;")
    assistant.write_text(js, encoding="utf-8")
    html_files = 0
    source_re = re.compile(r'(<script\b[^>]*\bsrc="[^"]*/assets/oleg-analytics-v1\.js\?v=[^"]+"[^>]*></script>)', re.I)
    script_tag = '<script defer src="/assets/oleg-clientid-bridge-v1.js?v=64"></script>'
    for file in sorted(site.rglob("*.html")):
        page = file.read_text(encoding="utf-8")
        if "/assets/oleg-analytics-v1.js" not in page: continue
        assert script_tag not in page, str(file)
        assert len(source_re.findall(page)) == 1, str(file)
        page = source_re.sub(lambda m: m.group(1)+script_tag, page, count=1)
        if file.name == "privacy.html":
            disclosure = ('<p>При новом согласии на аналитику технический идентификатор '
             'посетителя Яндекс Метрики (ClientID) может передаваться в '
             'Битрикс24 только вместе с вашим переходом к форме обращения, '
             'для сопоставления источника обращения с посещением этого сайта. '
             'Без разрешения идентификатор в форму не передаётся. '
             'Идентификатор не является содержимым заявления или юридической консультации. '
             'Вы можете отказаться от аналитики кнопкой «Настройки аналитики».</p>')
            assert "<h2>Основания" in page, str(file)
            page = page.replace("<h2>Основания", disclosure+"<h2>Основания", 1)
        file.write_text(page, encoding="utf-8")
        html_files += 1
    return {"site":host,"counter":counter,"form":form,"html_changed":html_files,
            "client_bridge_sha256":hashlib.sha256(client_script.read_bytes()).hexdigest(),
            "analytics_changed":True,"assistant_changed":True}

if __name__ == "__main__":
    result = {"mode":"V64_REBASED_ON_ACTUAL_TIMEWEB_SOURCE_OFFLINE_ONLY","production_modified":False,"sites":[]}
    for host in TARGETS: result["sites"].append(patch_one(host))
    (ROOT/"evidence/build-manifest.json").write_text(
        json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False))
