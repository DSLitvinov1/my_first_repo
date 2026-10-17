# НЕЙРОЗАВОД — доказанный разрыв между центральным HOST CAS и локальным CORE получателем
Дата: 2026-10-16. Область: COORDINATOR, только тестовая синтетическая интеграция. RELEASE: REJECT LIVE.

## Точная база
- CORE `ce6191153d0a0c1d742de6233897186a0b46896b` из ветки `neurofactory-core-queue-owned-20261013`.
- TRUSTED HOST `02646ccb71b3892dc08f68a76525937cfe2ed194` из `neurofactory-trusted-host-owned-20261015`.
- Первое совместное GitHub-hosted испытание: https://github.com/DSLitvinov1/my_first_repo/actions/runs/38889687189 (6/6).
- Новые два COORDINATOR-owned интеграционные сценария: коммит `b7574c37d517e55ddcc15b9da7d3d246878656a1`, `test_pinned_core_host_one_task.py`.
- GitHub-hosted Ubuntu 24.04 с одноразовой PostgreSQL16 `nf_test`: https://github.com/DSLitvinov1/my_first_repo/actions/runs/38890797714, job `116939549656`, **8/8 PASS** с проверкой полного job log, 0 FAIL/ERROR.
- Логи точно содержат `NF_INTEGRATION_GAP_HOST_BLOCK_CORE_LOCAL_TEST_WROTE=CONFIRMED` и `NF_INTEGRATION_GAP_HOST_UNKNOWN_CORE_LOCAL_TEST_WROTE=CONFIRMED`.

## Что реально обнаружено
HOST `OfflineCAS.claim` и CORE `OneTaskCore.enqueue/claim/apply_offline_test` имеют ДВЕ НЕЗАВИСИМЫЕ тестовые цепочки полномочий. В дополненных тестах CORE получает произвольный ПОЗИТИВНЫЙ TEST callback, который намеренно НЕ подтверждён центральным HOST.

1. `fixture_authorized=false` => HOST `BLOCKED`, но синтетически одобренный локальный CORE может выполнить локальную `OFFLINE_TEST` запись файла.
2. HOST после `mark_unknown` => `UNKNOWN` и запрещает повторный claim; отдельно положительный тестовый callback CORE по-прежнему допускает запись.

Это воспроизводит **отсутствие общего receiver-side fencing**, необходимого до включения настоящего исполнителя, а не обход развернутой production-защиты: production API, реальный независимый issuer/owner, signing-key custody, OS segregation, живой writer и публичная публикация здесь ОТСУТСТВУЮТ. Все новые тесты остаются зелёными намеренно: они фиксируют ОТСУТСТВИЕ границы безопасности и запрещают неверную отметку «интеграция завершена».

## Реальные требования на исправление
**TRUSTED HOST, Issue #14, один владелец:** создать подлинный аутентифицированный API с независимым operator/owner authorization, доверенным key provenance/highwater и атомарным receiver-side решением. Договор эффектов должен связывать task_id, project/repository allowlist, immutable input SHA40/file/task/policy hashes, canonical target, авторизованное действие, worker identity, lease_epoch/fencing token, idempotency_key и подлинное происхождение подписи; форматные совпадения не эквивалентны аутентификации. Deny on invalid/unknown/stale/replayed/expired; UNKNOWN запрещает автоповтор. Ключ подписи и контроль отката не в той же доступной DB/writer scope.

**CORE, Issue #9, один владелец:** до любой записи требовать проверенное HOST-подтверждение именно конкретного эффекта текущего epoch, проверенное из TRUSTED источника, а не отдельный позитивный локальный callback, `fixture_authorized` или строку APPROVE. Проверить целевой путь и защищённую границу OS sandbox. При недоступности HOST — STOP, без произвольного retry. Конечная фиксация результата должна быть идемпотентной; один central claim без atomically fenced receiver не обеспечивает exactly once.

**REVIEW, Issue #11:** на новых EXACT HOST+CORE SHAs воспроизвести HOST BLOCKED / UNKNOWN / stale epoch / wrong worker / wrong task / wrong target / forged approval / rollback / duplicate idempotency; запрещать реальный эффект. Нужна отдельная реальная авторизованная identity для внешнего выпуска: ChatGPT-чаты под одним GitHub-пользователем не являются внешним sign-off.

**COORDINATOR, Issue #3:** сохранять release BLOCKED, центральные тестовые fixtures НЕ считать аутентифицированным двухкомпьютерным E2E. Выделить действительные разрешённые физические машины и signer/operator только после соответствующих прав.

## Критерий закрытия именно этого разрыва
На точных обновлённых исходниках HOST/CORE повторить адресный тест: центральный отказ, UNKNOWN, старый epoch и несовпадающие разрешения не позволяют локальному получателю изменить файл; валидная синтетическая цепь в отдельном тесте допускает ровно один проверенный учебный эффект. Затем нужна отдельная независимая security-проверка и тест двух реально разных авторизованных компьютеров. Старые 8/8 — регрессионная база для ДО исправления, не довод RELEASE READY.

## Запреты
Нет реальных моделей, платных API, пользовательских проектов, реальной очереди, публикации, автоматического merge, Windows writer или возобновления HANDOFF. Этот документ не является разрешением на запуск.

## Дополнительная проверка истёкшей центральной аренды / 2026-10-16
- COORD-only исходник `test_pinned_core_host_one_task.py` после третьего negative case exact commit `9b24d8bd19ce177ba6adbc0fc5c631a166a105ae`, test physical Git blob `8b6bd47bd710984a0f76f0139f44f880277f40a0`; CORE/HOST executable SHA unchanged.
- GitHub-hosted run https://github.com/DSLitvinov1/my_first_repo/actions/runs/38893361829, job `116947929993`, actual completed/success, `Ran 9 tests`, `OK` (not a system release audit).
- Third negative: in **ephemeral** PostgreSQL `nf_test`, test fixture advances `lease_deadline` into the past; existing HOST `OfflineCAS.claim()` correctly refuses a replacement client while status remains LEASED and epoch stays 1; an independent synthetic positive CORE callback can still cause one local OFFLINE_TEST file write, without consulting HOST deadline. Confirmed log `NF_INTEGRATION_GAP_HOST_EXPIRED_CORE_LOCAL_TEST_WROTE=CONFIRMED`.
- This does NOT demonstrate acceptance of a stale token by a real API because no such integrated receiver exists. The missing central-to-CORE per-effect authorization is still BLOCKED; expected production remedy remains unchanged. No live user effect, secret, model, publication or deployment.
- Operator-authorized TWO-PHYSICAL-HOST acceptance plan: `bridge/neurofactory/coordination/TWO_PHYSICAL_HOSTS_ACCEPTANCE_PLAN_20261016_RU.md` (prepared, NOT executed; no machine/operator assigned).

## Новый точный сценарий: другой CORE worker / повторная доставка / 16.10.2026
- CORE and HOST branch tips physically rechecked immediately before this run: CORE `ce6191153d0a0c1d742de6233897186a0b46896b` and HOST `02646ccb71b3892dc08f68a76525937cfe2ed194`. Neither has received the required authenticated per-effect receiver implementation. COORD test-only fixture remains exact-source-pinned and checks physical Git HEADs.
- Two added targeted negative tests to unchanged CORE and HOST source in `test_pinned_core_host_one_task.py`; tested COORD exact commit `b713d7a12dc55117d4fca43a42ebd601f7037be7`, physical Git blob `3af2b854e664388e1c81f28f1592173fcc2e00a7`. Own GitHub-hosted Ubuntu24.04/ephemeral PostgreSQL16 run https://github.com/DSLitvinov1/my_first_repo/actions/runs/38924047235, job `117050927654`: actual log `Ran 11 tests`, `OK`, 11/11 PASS, 0 FAIL.
- HOST winning claimant gets `CLAIMED`, losing claimant gets `NOT_CLAIMED` without a fencing token. Yet a DISTINCT LOCAL SQLite/sandbox instance of genuine CORE code can accept a synthetic positive callback from an independently untrusted fixture and create a file for losing client. Log: `NF_INTEGRATION_GAP_HOST_LOSER_LOCAL_TEST_WROTE=CONFIRMED`.
- HOST duplicate request_id returns `BLOCKED` and issues no second fencing token; first local CORE writes a fixture, a SECOND NEW local CORE SQLite/sandbox instance still accepts the same task via a separate test-only callback and creates another file in its distinct workspace. Log: `NF_INTEGRATION_GAP_CROSS_WORKSPACE_REDELIVERY_TEST_WROTE_TWICE=CONFIRMED`.
- These are two local workspaces **on one GitHub runner**, NOT two physical hosts; no real signer/owner, client authenticators, HTTPS API, intended multi-PC network or production side effect was exercised. This is NOT proof of a production race or remote exploit. It demonstrates why local single-task SQLite exclusivity is insufficient for distributed exactly-once effect admission in the absence of a shared fenced recipient.
- Full baseline was 6/6 PASS (38889687189), after BLOCKED/UNKNOWN tests 8/8 PASS (38890797714), after expired lease 9/9 PASS (38893361829), and NOW 11/11 PASS with five explicit gap witnesses. The positive PASS signifies reproducible test assertions, **NOT closure**. Current release status remains `REJECT LIVE`.
- Owner fix requirement unchanged: HOST #14 must provide source-authenticated task-specific protected admission/fencing and independently anchored authorization root; CORE #9 must consume and enforce that decision at side-effect receiver before any file mutation. Reviewer #11 independently repeats targeted denial on exact NEW SHA and future truly distinct authorized physical machines, not this runner.
