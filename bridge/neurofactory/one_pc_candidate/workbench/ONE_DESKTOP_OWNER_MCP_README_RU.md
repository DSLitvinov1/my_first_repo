# ONE Agent — управление окнами Windows через локальный MCP

Дата: 15 ноября 2026. Дополнение к существующей ветке ONE Agent, а не новая установка. Не изменяет CORE9/HOST и не запускает рекламу.

## Назначение

**Playwright MCP** управляет разрешёнными вкладками браузера Chrome после подтверждения владельца расширения. **ONE Desktop MCP** — отдельный локальный процесс Windows, управляющий разрешёнными приложениями через уже существующий безопасный `DesktopOne`/`DesktopScriptOne`. Ни один из них не предоставляет произвольную административную власть над Windows. Модель никогда не получает ключи, куки, clipboard, браузерный профиль или доступ к shell.

MCP Windows предоставляет: статус, список разрешённых окон без заголовков, прикрепление после физического подтверждения, проверку безопасных навигационных элементов, короткий сценарий действий после нового локального подтверждения, получение квитанции, завершение сеанса.

Любое окно должно быть уже запущено пользователем и присутствовать в заранее заданном allow-list EXE. Модель не запускает процессы и не меняет allow-list. Подтверждения — **нативные** диалоговые окна Windows с кнопкой «Нет» по умолчанию.

## Использование

1. Не устанавливать в CORE/HOST, не запускать от администратора, SYSTEM или службы. Убедиться, что текущая версия ONE в `C:\Program Files\NeurofactoryWork` сохранена и есть копия данных.
2. Установить этот модуль вместе с его тестом только в изолированную тестовую копию рабочей папки ONE. Нужен существующий `desktop_one.py`, `desktop_script_one.py`, `desktop_goal_one.py`, `desktop_worker.ps1` и `work_core.py` этой же проверенной версии.
3. В настройках локальных MCP-серверов приложения ChatGPT добавить отдельный сервер «one-desktop» типа STDIO с командой **python.exe** и аргументами:

   `one_desktop_owner_mcp.py --root C:\NeurofactoryProjects\projects --data C:\NeurofactoryProjects\.work-data --project auto --apps notepad.exe,explorer.exe`

   Рабочая директория — папка безопасной тестовой версии ONE; первый аргумент должен быть **полным путём** к скрипту. Путь к Python тоже использовать абсолютный и закреплённый. Если проектов несколько — указать конкретный 32-символьный ID вместо `auto`. Приложения добавляются владельцем вручную в allow-list.
4. Перезапустить ChatGPT. Перед работой через Playwright отдельно подтвердить подключение расширения Chrome. Наличие двух включённых серверов не доказывает живое соединение — нужны отдельные проверки.
5. Проверка приёмки: открыть тестовый Блокнот; запросить список разрешённых окон; подтвердить подключение; изучить список кнопок; подготовить простую навигацию; увидеть локальный запрос согласия; проверить действие на окне и квитанцию. Убедиться, что чужие окна и удаления блокируются, отмена работает, а повтор не происходит.
6. Только после реальных испытаний на тестовой Windows-сессии планировать новую установку. Настоящие CRM, почта, сайты, платежи и рекламные кабинеты требуют отдельных согласований и тестов.

## Ограничения и риски

- Это **кандидат, прошедший офлайн-тесты с имитацией Windows**, а не реально установленный сервис. Интерактивную мышь/клавиатуру и полную сквозную работу в браузере на ПК владельца нужно проверить отдельно.
- `--project auto` применим только когда в локальном хранилище ONE существует **ровно один** проект. Не создаёт проектов и не изменяет файлов.
- Разрешения на вкладки Playwright не передаются автоматически системному агенту. Нельзя использовать удалённый отладочный порт Chrome как способ обойти авторизацию.
- Нет доступа к UAC, системным настройкам безопасности, служебным учётным данным, файловым операциям произвольного пути, внешним финансовым операциям, массовой отправке сообщений и автозапуску рекламы.
- При неизвестном результате операция не повторяется. Для отката/аварийного завершения достаточно закрыть локальный MCP-клиент: его собственный desktop worker закрывается, приложения остаются открытыми.

## Проверка кода

`python -m unittest -v test_one_desktop_owner_mcp` — офлайн проверки протокола, разрешений, запретов и однократного выполнения; **это не тест реального UI**.

Контрольный код в отдельной ветке GitHub, без автоматического объединения и установки. Реальный Windows E2E обязателен перед включением в основной агент.

## Объединение Playwright и Windows MCP — проверка 15.11.2026

- `owner_dual_mcp_config.py` формирует единую **локальную клиентскую** конфигурацию с двумя STDIO MCP-серверами: `one-browser` (`@playwright/mcp --extension`) и `one-desktop` (`one_desktop_owner_mcp.py`). Это конфигурация для совместимого MCP-клиента, **не автоматическое подключение этого чата ChatGPT**.
- Генератор принимает только абсолютные Windows-пути, ровно один локальный проект ONE (`auto`) либо конкретный 32-символьный ID, до 12 уникальных разрешённых .exe; прямые оболочки, интерпретаторы и административные приложения блокируются.
- Он только **печатает JSON**, не устанавливает/не запускает службы, не подключает расширения, не копирует cookies, не выдаёт UAC/административные права.
- Тесты `test_owner_dual_mcp_config.py` совместно с `test_one_desktop_owner_mcp.py` проходят на Windows и Linux: [Actions #43735794541](https://github.com/DSLitvinov1/my_first_repo/actions/runs/43735794541) — **PASS обе платформы** на коммите `50ca35764c823d3b9335221a5b9626d817cfa4b5`.
- Отдельно в ветке `workone-human-ui-chatgpt-bridge-20261115` есть проверенный Windows-синтаксис локального `START_OWNER_DESKTOP_CONTROL.ps1` ([Actions #43735408420](https://github.com/DSLitvinov1/my_first_repo/actions/runs/43735408420)), но **две ветки не объединять автоматически**, пока не выполнена безопасная физическая приёмка.

### Настоящее состояние Windows

- Windows компьютер `WIN-LIDC05TBOQD` ранее подтверждён онлайн. Chrome запущен в сессии пользователя 2, GitHub runner работает в неинтерактивной сессии 0.
- Ранее локальные **неактивные** файлы Playwright MCP были проверенно размещены в `C:\ChatGPTProjects\ONE-Playwright-Candidate-20261115` (без установки сервера или подключения вкладок).
- Новый `one_desktop_owner_mcp.py` из этого PR **ещё не установлен и не проверен на реальном рабочем столе**. Доступ к управляемому браузеру не предоставлен текущему ChatGPT чату.
- Последний read-only запрос Windows через резервный GitHub runner `#43735108959` остановлен из-за загрязнённой общей рабочей директории и отсутствующего task-файла в checkout. Не повторять через этот грязный checkout. Для следующих физических проверок использовать отдельный clean worktree или иной авторизованный безопасный канал, не удаляя посторонние изменения.
- **Полное системное администрирование Windows не является функцией Playwright.** Для действий с ОС в будущем потребуются отдельные локальные подтверждения, проверка прав, резервные копии и журнал; постоянный unrestricted admin запрещён.

### Точка продолжения

1. В изолированной пользовательской Windows-копии проекта проверить реальные пути Python/ONE и запустить read-only диагностику, не затрагивая установленный ONE и CORE/HOST.
2. В интерактивном (не SYSTEM/не admin) сеансе Windows запустить ONE Desktop MCP. В Chrome Playwright Extension выбрать вкладки, которые владелец действительно разрешает автоматизировать.
3. Импортировать сгенерированную локальную MCP-конфигурацию в **поддерживаемый MCP-клиент** и физически проверить синтетический Блокнот, правильные границы окон, отмену подтверждений и отсутствие повторов.
4. В ChatGPT Work использовать предусмотренное продуктом управление браузером/компьютером. Наличие стороннего Playwright MCP в локальном Windows-клиенте **не добавляет автоматически новые инструменты текущему чату**.
5. После подтверждённого подключения вернуться к сайтам Олега (Метрика, Вебмастер, Timeweb, Битрикс24) и выполнять записи только после проверки прав и конкретных объектов. Яндекс Директ не запускать.

## Playwright extension service access — 15.11.2026 (current request)

- User expressly wants to edit existing authorized tabs for Yandex Metrika, Yandex Webmaster, Yandex Direct, Google Search Console and Timeweb, using Playwright rather than a cloud browser. Do not start Direct paid ads.
- Current Chat-mode `Browser.list_tabs` sees all relevant account tabs, but `Browser.get_tab_context` returns `Extension manifest must request permission to access the respective host` for Metrika/Webmaster/Direct/GSC. This Browser tool has no click/fill/write action; its permission setting cannot grant capabilities it does not expose.
- Remote Desktop Commander quota is `0%` available; Opera connector `list_tabs` timed out. The GitHub bridge is separate and runs in Windows service Session 0, while owner Chrome runs in interactive Session 2; do not use unapproved CDP or Session 0 GUI escalation to bypass this boundary.
- **Fix implemented:** `playwright_owner_mcp.json` now lists `https://direct.yandex.ru` plus required Yandex/Google official origins; `playwright_access_policy.py` recognizes Direct as a paired domain but still rejects `start_ads`, payments and unsafe operations.
- **Windows/Linux PASS**: [GitHub Actions #43737598360](https://github.com/DSLitvinov1/my_first_repo/actions/runs/43737598360) at commit `72105674f5104ce95bfcc7bf409b971b099805ef`, exercising the strict domain policy, desktop MCP, and unified client configuration.
- Created a separate, self-contained ZIP in the current ChatGPT conversation named `ONE_Playwright_Connect_2026-11-15.zip` with `START-ONE-PLAYWRIGHT.cmd`, verified local JSON, read-only Node JSONRPC MCP client, Russian guide, tests and SHA-256 manifest. Four mock unit tests PASS. This ZIP is a chat artifact, not automatically present on the owner's PC, and not a persistent GitHub release.
- The one-shot check spawns pinned `@playwright/mcp@0.0.84 --extension`, shows the owner the extension connection request, reads **only** `browser_tabs {action:'list'}`, and writes a host-only local receipt. No site settings changed; no cookies/PII exported. The owner must install Microsoft Playwright Extension (if missing) and approve the specific tab group in Chrome.
- If owner completes pairing, the probe creates local `%LOCALAPPDATA%\\Neirozavod\\PlaywrightOwner\\mcp-client.json` for integration into an actual compatible client. **There is no live Playwright MCP tool attached to the current Chat-mode tool list**, so physical pairing alone will not enable browser-write calls from this particular chat. A separately connected local ONE MCP client or supported Work computer control is required.
- Critical pending acceptance: interactive owner Windows pairing and client registration; then read-only tab enumeration, UI snapshots for all five services, exact domain/property checks, one approved harmless draft write and read-back, then per-site production operations under guarded approval. Maintain full rollback and no paid campaign launch.
