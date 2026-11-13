"""Work ONE private-use readiness assessment.

This is a capability diagnostic, not a security certification. It performs
no network calls or mutations and intentionally excludes secrets, account
details, file paths, window titles, and user content from the result.
"""
from __future__ import annotations

import os

STATE_READY = "ready"
STATE_MISSING = "needs_setup"
STATE_VERIFY = "needs_live_test"


def _dict(value):
    return value if type(value) is dict else {}


def _bool(value):
    return value is True


def assess_private_readiness(*, browser=None, desktop=None, qwen=None,
                             google=None, bitrix_connected=False,
                             services=None, platform=None):
    """Summarize what a single owner can safely try next, without side effects.

    Passing a configured adapter does not prove that a real account operation
    has succeeded: live external writes require an additional test.
    """
    browser, desktop, qwen = map(_dict, (browser, desktop, qwen))
    google, services = map(_dict, (google, services))
    platform = os.name if platform is None else platform
    if platform not in ("nt", "posix"):
        platform = "unknown"

    scopes = google.get("connected_scopes")
    scopes = scopes if type(scopes) is list else []
    configured = _dict(services.get("configured"))
    model_ok = _bool(qwen.get("configured"))
    browser_ok = _bool(browser.get("configured"))
    desktop_ok = platform == "nt" and _bool(desktop.get("configured"))
    google_ok = "tasks" in scopes and _bool(configured.get("google.tasks"))
    bitrix_ok = _bool(bitrix_connected) and _bool(configured.get("bitrix.tasks"))

    checks = [
        {"id": "qwen", "status": STATE_READY if model_ok else STATE_MISSING,
         "detail": "Qwen доступна этому экземпляру Work" if model_ok else
                   "Подключить Qwen именно к этому экземпляру Work"},
        {"id": "browser", "status": STATE_READY if browser_ok else STATE_MISSING,
         "detail": "Разрешённый браузер подключён" if browser_ok else
                   "Указать браузер и список разрешённых HTTPS-сайтов"},
        {"id": "desktop", "status": STATE_READY if desktop_ok else STATE_MISSING,
         "detail": "Управление Windows разрешено" if desktop_ok else
                   "Запустить локальный Work в интерактивной Windows-сессии с разрешёнными программами"},
        {"id": "google_tasks", "status": STATE_VERIFY if google_ok else STATE_MISSING,
         "detail": "Google Tasks подключён, требуется реальная пробная запись" if google_ok else
                   "Авторизовать отдельный тестовый Google-аккаунт"},
        {"id": "bitrix24", "status": STATE_VERIFY if bitrix_ok else STATE_MISSING,
         "detail": "Bitrix24 подключён, требуется реальная пробная запись" if bitrix_ok else
                   "Подключить отдельный тестовый портал Bitrix24"},
    ]

    return {
        "mode": "personal_single_owner",
        "assessment": "configuration_only_not_security_audit",
        "private_network": "loopback_required",
        "read_only_web_task_ready": bool(model_ok and browser_ok),
        "desktop_test_ready": desktop_ok,
        "external_write_verified": False,
        "checks": checks,
        "ready_count": sum(x["status"] == STATE_READY for x in checks),
        "next": [x["detail"] for x in checks if x["status"] != STATE_READY],
        "not_required_for_private_use": [
            "коммерческий установщик", "публичный сервер",
            "биллинг", "многопользовательские организации",
        ],
        "still_required": [
            "контроль доступа и секретов",
            "подтверждение внешних изменений",
            "резервная копия пользовательских файлов",
            "проверка реальной операции и её результата",
        ],
    }
