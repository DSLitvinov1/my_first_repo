# НЕЙРОЗАВОД: проверенная точка продолжения главного координационного чата №3

Дата сверки: 18 октября 2026 года. Источник: прежний чат «Продолжение проекта разработка», GitHub Issue #3, координационный реестр и просмотр действующих GitHub PR и REVIEW.

## Назначение
Этот документ обеспечивает продолжение проекта без перезапуска или замены завершённых этапов. Единственный владелец координационных записей — COORDINATOR. Этот документ — read-only сводка, не разрешение на исполнение, запуск или изменение прав.

Основной репозиторий: https://github.com/DSLitvinov1/my_first_repo
Координация: https://github.com/DSLitvinov1/my_first_repo/issues/3
Канонический реестр: bridge/neurofactory/coordination/integration-evidence-registry-20261015.json
Правила владельцев: bridge/neurofactory/coordination/chat-assignments-and-handoff-pause-20261014.json

## Проверенные на момент записи ветки
- COORDINATOR: draft PR #12, neurofactory-coordinator-mvp-status-20261015, исходный просмотренный SHA 7738d4c235c03a9b705e3512ba2e27c353435c54. Этот SHA предшествует коммиту настоящей записки.
- CORE: Issue #9, SHA beb08eff32923d8ca364aabfde0458f380acf8e7. Авторизованный owner grant обязателен у собственного offline receiver client; реальная production очередь не активирована.
- TRUSTED HOST: Issue #14, draft PR #15, SHA 02972424eefabcd61d21100611e3eace4c6c3d5e. Существуют защищённый OS receiver, TLS 1.3/mTLS тестовый транспорт, отдельно защищённый свидетель, проверка двух подписанных owner/issuer полномочий внутри witness до записи и V4 disposable file effect; всё тестовое, не установленный production.
- Дополнительный HOST preflight: draft PR #17 SHA 2521034b0effe85022f5cf7223b0b2e15294eaad; результат установки сознательно BLOCKED.
- Дополнительный HOST четыре роли и PostgreSQL операторская схема: draft PR #18 SHA 99f9d2d20ab994a84a316849ae5f8e824f407413, криптографическая проверка не выдаёт live разрешение и не может заменить внешнее хранилище highwater.
- REVIEW: Issue #11, реестр SHA dfed53bbe9587e2644ccfc2799a0583508e88b66. Независимого подписанного вердикта RELEASE APPROVE нет.
- OPS: Issue #6, реестр SHA e32acaba8a3c6b5dc724cc08c84ad033190b9efe, read-only, независимая приёмка ожидается.
- UI: Issue #10, реестр SHA 56a375a2f76bdaf56932f21b392a9d133f740913, локальный демонстрационный интерфейс без live управления.
- PROVIDERS: Issue #5, реестр SHA 827b654d9f7c6a10a9b90a9c97802e63116711b9, draft PR #13: выполнена отдельная реальная CPU-генерация Qwen2.5-0.5B на GitHub-hosted runner; не модель пользователя и не разрешённый live исполнитель.
- SKILLS: https://github.com/DSLitvinov1/lesson3.1/pull/558, SHA e15970bf9c18e99217fe5d6e9fbe63f1f836dcf8, 12 кандидатов отключены, 19 профилей подготовлены; независимой приёмки установки нет.
- HANDOFF: PAUSED_BY_USER, не возобновлять автоматически.
- GOD MODE: пересечение областей владения, не активировать без согласованного изолированного объёма.

## Проверенные доказательства HOST последнего этапа
- Scope/owner/issuer подписи: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39074104015 — 15/15 PASS.
- Взаимный TLS и отдельный witness: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39074332366 — 12/12 PASS.
- Применение тестового файла V4: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39074238180 — 4/4 PASS.
- Регрессия изменённого receiver: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39074323132 — 32/32 PASS.
- Дополнительный HOST четырёхролевая проверка https://github.com/DSLitvinov1/my_first_repo/actions/runs/39074199375 — 25/25 PASS; временная PostgreSQL16 операторская схема https://github.com/DSLitvinov1/my_first_repo/actions/runs/39073799970 — 9/9 PASS.

ВНИМАНИЕ: эти результаты получены в изолированном GitHub-hosted Linux с временными ключами/ролями; не доказывают физически разнесённые устройства и не являются независимой человеческой приёмкой. Внешняя защита от отката PostgreSQL на другом физическом узле отсутствует как подтверждённый production сервис.

## Неподтверждённые обязательные условия
1. Отдельно авторизованный физический Linux HOST и второй независимый физический узел witness.
2. Реальные полномочия владельца, защищённое хранение долгоживущих ключей owner/operator/HOST/witness, права репозитория и безопасный отзыв.
3. Сетевой постоянный защищённый recipient с независимым off-host highwater и проверкой актуального lease/fencing в границе записи.
4. Реальный reboot Linux HOST и восстановление из более старой базы без повторного эффекта, при живом witness на другом компьютере.
5. Пять реальных отрицательных испытаний и одна безвредная успешная транзакция между двумя отдельными физическими устройствами.
6. Подписанный отдельным уполномоченным ревизором REVIEW verdict на точных коммитах.
7. Соблюдение запрета на запуск очереди, HANDOFF, объединение PR, платные API, продакшен без допуска.

## Резервный доступ
История главного Issue #3 сообщает: единственный Windows WIN-LIDC05TBOQD отвечал на ping через Remote Desktop Commander, но месячная квота удалённых команд исчерпана. Не обходить лимит. Резервный GitHub self-hosted Windows read-only статус run https://github.com/DSLitvinov1/my_first_repo/actions/runs/39074665194: при последней проверке в GitHub job ещё queued. Это не проверка команд на ПК и не второй физический узел.

## Режим продолжения
- Читать актуальные SHAs перед изменениями; каждый исходный коммит/тест/REVIEW привязывать к своей точной версии.
- Координатор изменяет только собственные coordination/ файлы, чужие направления — только read-only.
- Успешные лабораторные тесты не обозначать как рабочую производственную установку.
- Если авторизованного второго компьютера нет, выполнять только безопасные изолированные доработки и адресные тесты, не имитировать физическую приёмку.
- Следующий безопасный этап — независимо проверить и согласовать финальный HOST↔CORE↔witness контракт, подготовить безопасный операторский пакет до внешней установки. Физический этап только после отдельных полномочий, ключей и двух реально независимых устройств.
- Общий статус: BLOCKED / REJECT LIVE. HANDOFF PAUSED_BY_USER. Ни один PR не объединять автоматически.

Основные ссылки: https://github.com/DSLitvinov1/my_first_repo/pull/12 ; https://github.com/DSLitvinov1/my_first_repo/pull/15 ; https://github.com/DSLitvinov1/my_first_repo/pull/17 ; https://github.com/DSLitvinov1/my_first_repo/pull/18 ; https://github.com/DSLitvinov1/my_first_repo/issues/11
