# НЕЙРОЗАВОД — задание №5: совместный CORE ↔ TRUSTED HOST тест одной задачи

Дата: 2026-10-16. OWNER: COORDINATOR. Только одноразовый исполняемый CI-fixture; НЕ сервер и НЕ производственная очередь.

## Точная проверенная исходная база

- TRUSTED HOST DRAFT PR #15 точный исходный коммит `02646ccb71b3892dc08f68a76525937cfe2ed194` с настоящим `bridge/neurofactory/trusted_host/offline_cas.py` и `schema_v1.sql`, никакой копии реализации.
- CORE ветка `neurofactory-core-queue-owned-20261013`, exact `ce6191153d0a0c1d742de6233897186a0b46896b`, настоящий `bridge/neurofactory/development/core_owned/one_task_core.py`.
- Новая COORD test-only harness `bridge/neurofactory/coordination/test_pinned_core_host_one_task.py` проверяет оба отдельным `git rev-parse HEAD` и импортирует соответствующие исходники с двух exact-pinned Git checkout.
- CI-скрипт `.github/workflows/neurofactory-coordination-pinned-one-task.yml` запускает только GitHub-hosted Ubuntu 24.04 и одноразовый PostgreSQL 16 `nf_test`, изолированное временное Python-окружение. Не использует self-hosted Windows, пользовательские директории, рабочий CORE SQLite, реальный Qwen/Ollama, внешние команды публикации, системные ключи, HANDOFF или платные API.

## Проверенные сценарии

Собственный GitHub-hosted [Actions #38889687189](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38889687189), job `116935883610` на координационном SHA `d0468825b84c57e718e00811e5c5fc1bd44e6b78`: `Ran 6 tests`, `OK`, в точном журнале:

1. Реальный `nf_task` insert в ephemeral PostgreSQL и два отдельных клиентских подключения с одновременным вызовом HOST `OfflineCAS.claim()`: **один CLAIMED, один NOT_CLAIMED**, epoch ровно 1.
2. CORE `OneTaskCore.enqueue()` с явно синтетическим тестовым callback на временном Git-коммите, затем `claim()` единственного победителя и `apply_offline_test()` с инертным Python-текстом в одноразовой директории sandbox. Файл реально существует, SHA256 совпал с CORE receipt, статус `CHECKPOINTED_TEST`, attempts 1, model_invoked=false, published=false, review_approved=false, api_cost_usd=0. Попытки повторного CORE claim/apply отклонены.
3. HOST fixture `fixture_authorized=false` → BLOCKED, CORE с test callback false → отказ и 0 файлов.
4. POSTGRES mark_unknown() с точным epoch/токеном → UNKNOWN, повторное claim запрещено, нет CORE файла.
5. Повтор request_id → BLOCKED без повторной выдачи host fencing token.
6. Подменённый SHA40 реального Git preimage, даже при намеренно положительном тестовом callback → CORE DENY. Сам HOST CAS test fixture не удостоверяет approval, `actions_allowed=false`, release BLOCKED.

**Ранее полученный RED:** [Actions #38889571997](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38889571997), job 116935513969, failed BEFORE TESTS на недостатке прав pip для системного `/usr/local/lib/python3.12/dist-packages`; исправлена только CI установка psycopg[binary]==3.2.6 во временный Python virtualenv. После исправления все 6 адресных интеграционных тестов PASS; неизменённые старые матрицы не повторялись.

## Строгие ограничения результата

**Это не защищённый производственный TRUSTED HOST и не фактический end-to-end двух физических машин.** Оба Postgres соединения находятся на одном GitHub-hosted runner. В PostgreSQL поле `fixture_authorized` выставлено самим тестом; для CORE используется локальный callback, возвращающий True только для точно заданного тестового объекта. Они НЕ подписаны настоящим владельцем, не независимая авторизация, не постоянный issuer. HOST lease token и CORE local token — разные не связанные защищённым endpoint полномочия; центральный HOST CAS пока не является обязательным receiver-side fenced admission для реального CORE. Внешняя публикация/эффект/модель не разрешены. Тестовый файл не является пользовательской задачей. Не реализованы защищённое от DB owner монотонное хранилище, иной OS principal для signer, доверенная сеть HTTPS API, внешнее исполнение на втором ПК, реальный физически изолированный CORE sandbox, idempotent конечный получатель или независимый release signer.

Состояние **REJECT_LIVE**, `HANDOFF=PAUSED_BY_USER`, PR #12/#15 остаются DRAFT, никаких merge/деплоя/моделей или секретов.

## Следующий обязательный owner-specific результат

- TRUSTED HOST #14: отдельный уполномоченный operator и другой custodial signer, защита настоящего issuer private key вне DB owner/CORE/CI, подписанное owner/task/source/policy разрешение, внешне закреплённый append-only monotonic head и production authenticated CAS HTTPS API с receiver-side lease_epoch/fencing/idempotency. Только HOST владеет своим исходником.
- CORE #9: по отдельному допуску подключить реальный fenced recipient/callback и Linux OS writer isolation против same-UID перемещения предка sandbox; до этого разрешена только synthetic fixture на GitHub.
- REVIEW #11: точно на новых HOST и CORE SHA провести отдельные негативные испытания spoofed owner, DB rollback, stale epoch и crash UNKNOWN; отдельная внешняя идентичность reviewer.
- COORDINATOR #3: только описание совместного контракта/доказательств без самовыдачи разрешения.
- После развёртывания на двух реально разрешённых физических хостах доказать ровно одну учебную транзакцию до/после имитации сбоев, без модели и публикации, и получить официальный release verdict. HANDOFF остаётся PAUSED.
