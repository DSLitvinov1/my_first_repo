# CORE→HOST→witness: pinned cross-branch one-operation sandbox proof

18 октября 2026 года. Инициатор: самостоятельная разработка HOST-кандидата по поручению пользователя. Только отдельная ветка `neurofactory-host-core-e2e-sandbox-20261018`, накопление поверх DRAFT PR #20 на зафиксированном базовом HEAD `3574ea089f79e19b4f8a2269d8c31141c20dc265`. Не менять существующие HEAD CORE или HOST и не делать merge.

## Версии и независимые области владения

- HOST source candidate `sandbox_atomic_effect_candidate.py` Git blob `c067e86ce03f5999f59c187d2bece325d9ba3cbc`; исходный тестовый signed+PG preflight PR #18 базируется на `4221aaea1d549dd872fe189b551879b873bc4e47`.
- CORE owner source `four_party_sandbox_client.py` вынесен в собственную отдельную ветку `neurofactory-core-four-party-sandbox-adapter-20261018`, pinned commit `441e6c9790ba9c3a776904ac530915871a598ad1`, Git blob `5fea9af13ea8bd45463f06d9cbfc832218450728`. Запуск HOST CI делает `git fetch` зафиксированной ветки, проверяет FETCH_HEAD равным pinned SHA и Git object hash извлечённого адаптера равным pinned blob. Никогда не подменяет чужую область владения.
- Новый test module `test_core_four_party_held_sql_e2e.py` и отдельный `neurofactory-host-pinned-core-e2e-sandbox.yml`. HOST читает CORE test adapter как внешнюю импортируемую библиотеку в созданной GitHub-runner временной директории. Все secret roles генерируются только для CI и никогда не берутся из реальных секретов пользователя.

## Реальная функциональность в одноразовой среде

CORE local task.v1 fixture проверяет свою CLAIMED аренду, token, worker, project, pinned исходный SHA40, digest исходного файла, target и digest содержимого. Затем HOST проверяет четыре настоящие тестовые Ed25519 подписи с operator-supplied test-only публичными ключами, действующую PostgreSQL16 центральную аренду, удерживает FOR UPDATE NOWAIT строковые блокировки через резервирование witness, тестовый эксклюзивный файловый effect O_EXCL/O_NOFOLLOW+fsync, обновляет receipt UNKNOWN→COMPLETED и lease CLAIMED→COMPLETED одной transaction.

Сквозной положительный тест создаёт реальный новый файл только внутри `/tmp/nf-atomic-ci-*` и записывает проверенную квитанцию. Отрицательные тесты: чужой CORE token, устаревшая локальная аренда, поддельная owner подпись, истёкшая центральная аренда PostgreSQL, сбой после fsync, повторный клиент CORE при уже завершённой операции, возврат БД к старому SQL состоянию при неперематываемой test witness памяти и отмене локального файла. Инициирующий CORE клиент не владеет файловым дескриптором и при неизвестном исходе не разрешает повтор.

## Подтверждение испытаний

**[GitHub Actions run 39109952023](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39109952023)**, job `117623731422`, exact tested commit `fa073719a08f581a283bdc05b39d4bf552dffa0a`, logs проверены, **35 PASS, 0 FAIL**. Это 8 новых CORE→HOST сквозных сценариев и 27 импортированных тестов существующих подписей и базы данных. Лог также содержит `CORE_ADAPTER_EXACT_SOURCE_PIN_VERIFIED=PASS`. Отдельный [CORE Actions 39109729320](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39109729320) 12/12 PASS, checked CORE SHA `441e6c9790ba9c3a776904ac530915871a598ad1`.

## Строгие ограничения

1. «Внешний свидетель» остаётся простым test double внутри одного процесса на disposable GitHub runner, НЕ настоящим независимо физически размещённым или защищённым сетевым сервисом. Нельзя считать этот тест доказательством невозможности совместного отката оборудования.
2. Локальная строка CORE `_row` имитирует проверяемую схему OneTaskCore, но в данном E2E не развёрнута настоящая CORE SQLite очередь; сквозное интеграционное поведение работает на интерфейсном уровне с реальным HOST PostgreSQL/file effect. Авторизацию ключа владельца/оператора вне fixture нельзя подтверждать этими тестами.
3. Нет реального межмашинного TLS listener, отдельного owner/operator enrollment, прочного off-host highwater, OS reboot или независимого signed REVIEW на этих SHA. Параллельный Windows local MVP PR #19 остаётся отдельным draft — один Windows PC не равен независимому witness. У Linux нет эксклюзивного требования для ограниченного Windows sandbox pilot.
4. Ветви не объединять до независимой проверки, HANDOFF не возобновлять, платные модели не запускать, производственную очередь и реальные файлы не трогать. Любой результат `live_execution_allowed=false`, все неизвестные outcomes требуют ручной остановки.

## План отдельной независимой приёмки

REVIEW Issue #11 должен сам сверить HEAD/хэши CORE и HOST, повторить отрицательные сценарии и проверить отсутствие обхода текущих owner/grant/lease, особенно в старых fixture API. Затем отдельно оператор подтверждает реальное изолированное место для HOST и внешнего witness (Linux либо отдельный Windows или независимо управляемый сервис), сетевые доверенные корни, реальные публичные pin identities, невыгружаемые ключи/разделение ролей и журнал highwater с отдельным правом администратора. Без этого — выпуск REJECT LIVE.
