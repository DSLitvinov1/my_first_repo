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
