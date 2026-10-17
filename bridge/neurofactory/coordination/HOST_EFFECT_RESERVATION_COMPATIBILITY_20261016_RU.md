# НЕЙРОЗАВОД — результат новой HOST PRE_EFFECT фикстуры и её совместимости с CORE
Дата: 2026-10-16. COORDINATOR; только изолированная офлайн-приёмка. LIVE RELEASE: REJECT.

## Точные исходники и выполненные испытания
- HOST DRAFT PR #15 branch `neurofactory-trusted-host-owned-20261015`; новый тестовый исходник exact Git commit `5c0132d1c53d3d569dd66967915203069e2a25e8`; четыре HOST-owned новых файла: `offline_effect_reservation.py`, `offline_effect_reservation_schema.sql`, `test_offline_effect_reservation.py`, отдельный prefixed workflow. Предыдущие HOST source files не переписывались.
- HOST author-owned GitHub Actions https://github.com/DSLitvinov1/my_first_repo/actions/runs/38959994211 job `117172339701`, Ubuntu 24.04, ephemeral PostgreSQL 16 `nf_test`. Фактический job log: `Ran 13 tests`, `OK`, завершён `success`, exact HEAD pinned. Это не независимая приёмка.
- CORE рабочая ветка `neurofactory-core-queue-owned-20261013`, exact `ce6191153d0a0c1d742de6233897186a0b46896b`, всё ещё без нового потребителя HOST PRE_EFFECT.
- COORD test-only joint runner pinned exactly to обеим версиям, source commit `1b18db66a26add49d576c8f62c64d8b6f620af11`, `test_pinned_host_effect_core_contract.py`; GitHub Actions https://github.com/DSLitvinov1/my_first_repo/actions/runs/38960295197, job `117173353199`, `Ran 7 tests`, `OK`, full job log verified, success. No пользовательских исходников, живой очереди или автоматической публикации.

## Что уже действует в новом HOST только для nf_test
`OfflineEffectReservation.reserve_once` атомарно читает заблокированную запись HOST lease и отдельно заранее подготовленный fixture-scope и записывает уникальный `nf_effect_intent` с `ON CONFLICT DO NOTHING`.

Сравнивает task_id, project_id, source Git SHA40, file SHA256, task SHA256, target, policy SHA256, worker_id, lease_epoch, SHA256 fencing token, время окончания аренды и idempotency_key. Bool вместо lease_epoch, поддельный токен, неверный целевой путь, несовпадающая политика и source не допускаются. Резервирование одной и той же операции повторно отказывается, в том числе двумя конкурирующими реальными DB соединениями одного hosted runner.

Пять адресных негативных границ на HOST:
1. Не выдана HOST аренда/отказ в claim -> нет PRE_EFFECT reservation.
2. HOST `UNKNOWN` -> отказ.
3. lease expiry -> отказ.
4. проигравший либо stale worker/epoch/fence -> отказ.
5. повторная доставка, duplicate task/idempotency -> отказ.

Отдельно проверены scope/source/policy mismatches и type attacks. Даже положительное тестовое резервирование возвращает `execution_allowed=false`, `publication_allowed=false`, `real_owner_authenticated=false` и `real_recipient_fencing=false`.

## КРИТИЧЕСКИЙ незакрытый разрыв
HOST предоставляет **тестовую транзакционную фиксацию намерения**, а не действительное разрешение файла. `nf_effect_scope_fixture` и `nf_task.fixture_authorized` создаются собственным тестом; подписанный внешний владелец, приватный issuer key, закреплённый независимо от DB highwater и защищённый сетевой сервер отсутствуют.

Точное реальное `OneTaskCore.apply_offline_test(self,task_id,token,proposal,*,now=None)` (CORE SHA указан выше) принимает локальный SQLite-токен, НЕ требует результата нового HOST PRE_EFFECT, signed task source, remote epoch или idempotency-key. Это подтверждено отдельным COORD точечным тестом `NF_CORE_NEW_HOST_EFFECT_NOT_CONSUMED=CONFIRMED_TEST_ONLY`. Поэтому пять отрицательных проверок новой HOST фикстуры **не доказывают отсутствие записи в нынешнем CORE**: ранее доказанное отсутствие общего receiver-side fence всё ещё возможно.

HOST PostgreSQL `nf_effect_intent` не может атомарно гарантировать exactly-once внешний файловый эффект, даже если intent уникален: после записи файла, но до завершения receipt может быть UNKNOWN. Требуется идемпотентность и проверка lease непосредственно у защищённого конечного получателя, другая OS-identity, защищённый root, независимый signer и реальный owner+repo allowlist.

## Чёткое следующее задание владельцам
**HOST #14:** отдельный действительный оператор, защищённые signer/root/highwater, подлинная авторизация исходного проекта, защищённый HTTPS API и транзакционно согласованный с получателем PRE_SIDE_EFFECT/receipt. Кандидат `OfflineEffectReservation` не переносить в production как есть. Подготовить exact SHA, negative tests с настоящими отдельными неадминистративными identities и evidence.

**CORE #9:** не принимать флаг или JSON `RESERVED_OFFLINE_TEST_ONLY` в качестве полномочий; дождаться HOST с подтверждённой подлинностью. Требовать валидное текущее разрешение у защищённого получателя до записи, включая полный owner/task/source/target/worker/epoch/idempotency scope; отказ/UNKNOWN/expired/stale/loser/replay -> 0 эффекта. Выдавать новый exact SHA.

**REVIEW #11:** независимая техпроверка нового HOST exact source `5c0132d1...` и будущей CORE интеграции с собственными негативными тестами; автор с одним GitHub identity не является независимым reviewer для production. Вердикт APPROVE-NARROW/REJECT/INCONCLUSIVE отдельно от prod signoff.

**COORD #3:** допуска только по новому exact SHAs и реальному operator/user authorization; test-only 13+7 green не превращают release в ready. План двух физически разных хостов `TWO_PHYSICAL_HOSTS_ACCEPTANCE_PLAN_20261016_RU.md` остаётся PREPARED_NOT_EXECUTED, реальные машины/сервисы не запускались.

No automatic merge, user project effects, Windows bridge, live model/Qwen, paid API, HANDOFF or publication.
