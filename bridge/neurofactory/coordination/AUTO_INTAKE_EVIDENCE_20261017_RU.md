# НЕЙРОЗАВОД — подписанный приём новых проектов и задач (локальный кандидат)

Дата 17.10.2026. Исполнитель: COORDINATOR, Issue #3. Состояние: **локальный функциональный кандидат, не подключён к живой очереди**.

## Реально реализовано

- `offline_autointake.py`: принимает и проверяет HMAC-SHA256 на исходных байтах сообщения, жёстко ограничивает размер, типы полей и Unicode, запрещает повторяющиеся ключи JSON. Источники: нативное GitHub Issues `opened`, собственный авторизованный API и подписанный импорт.
- `offline_intake_gateway.py`: только явный старт на `127.0.0.1` и автоматически выбранном порту; HTTP POST на три локальных адреса `/intake/github/issues`, `/intake/api/tasks`, `/intake/import`. HTTP без TLS — **категорически не выставлять в Интернет**; настоящий ingress требует отдельно защищённый TLS/аутентифицированный reverse proxy. Нет daemon, webhook регистрации, планировщика, ChatGPT API, Telegram или стороннего сервиса.
- После проверки подписи событие связывается с явно предварительно заданным проектным справочником (repository→project/owner/source allowlist/mode/profile). Внешнее событие не может назначить собственные права, owner, модель или расширить область Git. Для неизвестного проекта создаётся только карточка `PENDING_OWNER_APPROVAL`.
- Проекты с заранее заданным справочником получают только `ADVISORY_READY_NO_EXECUTION`, включая режим `AUTOMATIC`. **Это не центральная очередь и не основание для файловых изменений**. В ответе каждое разрешение execution/queue/publish/paid=false, HANDOFF не запускается.
- SQLite-схема `nf_coord_intake_v1` делает атомарную регистрацию уникального события/доставки, повтор того же тела возвращает DUPLICATE, конфликтующие payload/ID запрещены. Это локальный advisory store, не защищённая от DB owner central CAS, не распределённое exactly-once.

## Контракты будущего подключения

**GitHub Issues:** нативный JSON GitHub webhook `action=opened`, `repository.full_name`, `issue.number`, `issue.state=open`, `issue.title`; заголовки `X-Hub-Signature-256`, `X-GitHub-Event=issues`, `X-GitHub-Delivery`. Секрет получает администратор отдельно, хранение вне GitHub, исходная подпись HMAC проверяется до обработки. Использование GitHub webhook потребует разрешения владельца репозитория и безопасного доступного HTTPS ingress; само подключение НЕ выполнялось.

**API/импорт:** JSON с `schema=neurofactory.intake.event.v1`, `event_id`, `kind=TASK_CREATED|PROJECT_CREATED`, `repository`, `project_id`, `description`; HMAC SHA256 в `X-NF-Signature-256` и уникальный `X-NF-Delivery`. Секреты в тестах синтетические. Импорт новой карточки НЕ приводит к созданию репозитория и к доступу к нему.

**Режимы:** MANUAL, SEMI_AUTOMATIC, AUTOMATIC хранятся как советующие метаданные. Реальное право автоматического запуска должна независимо проверять система TRUSTED HOST по разрешению владельца, политике, источнику, проекту, commit, lease, исполнителю, fencing, idempotency и reviewer gate непосредственно перед конечным эффектом. До этого никакой downstream потребитель не должен трактовать `ADVISORY_READY_NO_EXECUTION` как полномочие.

## Доказательства из GitHub

Последний исполняемый кандидат COORD commit `5a8d3e6bae8a4deb42fb5bef61b9b33688bd9504`.
Исходники: intake Git blob `0bb458a8bcdad2c9772d34f3c614288b8246eaf5`, локальный gateway `46b701dbcd92f4442bc66003b64c494f82222ca2`.
Тесты: 24 автономных сценария и 11 настоящих localhost HTTP сценариев.
GitHub-hosted Ubuntu24.04 Actions [№38983357524](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38983357524), job 117249078208, **35/35 PASS (24+11)**; реальные журналы проверены.
Отдельный предыдущий [№38983134603](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38983134603) был RED из-за некорректного тестового примера с Unicode, не из-за разрешённого обхода подписи; исправлен, [№38983179236](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38983179236) 24/24 PASS.
Независимый REVIEW точных новых исходников **НЕ ПРОВЕДЁН**, независимый оператор ключей и production ingress **НЕ ДОПУЩЕНЫ**.

## Реальные препятствия к общей системе

1. В TRUSTED HOST отсутствуют развёрнутые независимый issuer/signing identity, защищённый вне PostgreSQL монотонный корень и централизованный получатель эффекта с обязательным epoch/fence/idempotency. Текущая `offline_effect_reservation.py` — тестовый механизм, не дающий полномочия на запись.
2. Действующий CORE writer допускает отдельный тестовый callback, а реальный receiver-side fenced permit ещё не введён в обязательный путь записи. CORE владеет изменением своих файлов, HOST — своими.
3. Нужны одобренные сетевой ingress/компьютеры, разрешение на хост, внешний независимый reviewer и сквозной E2E двух реально разных машин.
4. Локальная модель, OPS/UI/SKILLS/HANDOFF не активируются из этого модуля. Никакой установки на Windows, платного API, merge, live queue, автоматического запуска чужих проектов и публикации.

**Глобальный вердикт:** только локальный безопасный приём данных, общий выпуск REJECT LIVE.
