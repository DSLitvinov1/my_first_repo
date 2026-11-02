# НЕЙРОЗАВОД — 02.11.2026. Точная проверяемая интеграция CORE→HOST→подписанный внешний свидетель и НЕЗАВИСИМАЯ приёмка

## 1. Проверенное происхождение

Исходная ветка: [DRAFT PR #76](https://github.com/DSLitvinov1/my_first_repo/pull/76), точный SHA `e6fb350d117f020aec70d86979a2ac120f17214d`. Новая изолированная ветка `neurofactory-p0-core-lease-signed-witness-bind-20261102`. **Не объединена** ни с main, ни с другим PR; не опубликована как production.

В прежней сборке уже существовали подтверждённые Ed25519 подписи владельца/ревизора, signed mTLS witness remote-ACK, локальный durable UNKNOWN журнал перед запросом и реально проверенный CORE SQLite queue. **Не было общего механизма сравнения одного leased task CORE и одного подписанного OWNER+REVIEWER task scope до обращения к внешнему witness**.

## 2. Что реализовано

`core_readonly_observer.py` теперь выводит только **source_sha40**, прочитанный из действительной local CORE task spec после сверки её canonical SHA, наряду с существующим task_id/project_id, типом модели и сроком lease. Это только локальное чтение, не выдача ключа/token или полномочий.

Добавлен `protected_host_core_witness_binding.py`. Он:
1. Берёт **существующую локальную CORE SQLite** через уже действующий `observe_core`, без создания новой базы.
2. Отказывает ещё до сети, если отсутствует единственная задача `CLAIMED`, её `task_id`, `project_id`, `source_sha40` расходятся с подписанным claim, срок lease истёк, запись об изменении результатов уже есть либо статус не является однозначным.
3. Только после этого обращается к существующему `OneShotHostWitnessBridge`, который проверяет **реальные независимые Ed25519 тестовые подписи** OWNER/REVIEWER, операторский scoped task, persistent local UNKNOWN и подписанную квитанцию mTLS witness. Отдельный сетевой ответ в адресном CI **моделируется**, не свидетельствует о реально работающем VPS.
4. Повторно читает локальную CORE SQLite после квитанции. Если lease/состояние изменились — `UNKNOWN_NO_RETRY`; **никаких эффектов**. Возвращает только `LOCAL_CORE_SCOPE_MATCHED_AND_SIGNED_REMOTE_ACK_TEST_NO_EFFECT` с явно установленными FALSE: `actual_core_lease_transaction_attested`, `production_file_effects_allowed`, `physically_independent_witness_attested`, `windows_scm_sid_acl_attested`, `automatic_retry_allowed`, `production_release_approved`.
5. Не открывает очередь, не вызывает Qwen, не устанавливает SCM, не пишет проектные файлы, не публикует изменения. Защита от race здесь **не является настоящим транзакционным разрешением эффекта**; нужны реальный ограниченный Windows HOST и защищённый оператором lease/fencing.

Добавлен тест `test_protected_host_core_witness_binding.py`, использующий **реальную временную OneTaskCore SQLite**, реальные несвязанные Ed25519 ключи, реально выданную CORE аренду и полноценную криптографическую проверку после смоделированной TCP квитанции. Неправильная задача/проект/source/время/владелец и смена CORE после ACK отвергаются, без повторного сетевого обращения и без файловых эффектов.

## 3. Доказанные тесты и конкретный пакет

- [Linux и Windows CI #41482456911](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41482456911): source/test SHA `4cc38adcbf502d4fc965bdfc8e55add1d1ab47fa`. **28/28 PASS** на каждом из двух типов runner (включая 6 новых сценариев + 4 унаследованные CORE интеграционные + 14 существующих signed auth). Отдельно исполнено на пользовательском облачном Linux в изолированной лаборатории. Первый Ubuntu run #41482228967 остановился на SYSTEM Python pip permissions, не на HOST; исправлено тестовое окружение venv, успешный запуск указан выше.
- [Windows Inno machine installer CI #41482345828](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41482345828) на source SHA `5eb9ba6a6ec33d78f1c5e20f37aea119762fc4d4`: SUCCESS, 15 immutable pinned CORE/HOST components, 78 staged файлов, реальная временная machine-wide установка, verify SHA manifest, отказ от регистрации production SCM, удаление PASS.
- Точный **UNSIGNED, REVIEW-ONLY, NOT PRODUCTION** Windows EXE SHA256: `A5A1E49C648C9B4882C63CEACABAAC2DF8005BC749EB40A5D19A94F09C9E8F73`.
- GitHub artifact `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, ID `13160203369`, [скачивать через run](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41482345828), истекает 2026-11-09T16:33:28Z.
- Установщик содержит **инертные исходники** нового bound verifier, а не включённую службу, и не снабжён Authenticode.
- `Get-Service -Name '*Neurofactory*'` был выполнен только для чтения на подключённом Windows-компьютере владельца `WIN-LIDC05TBOQD` (02.11.2026). Сервисов с этим именем не обнаружено. ПК не менялся, права администратора не использовались.

## 4. Независимый REVIEW — критерии реального APPROVE, не прошедшие ещё приёмку

**Сейчас ни один из пунктов ниже не имеет подтверждённого независимого уполномоченного подписанта. Ветки DRAFT и production запрещён.** Нельзя считать автоматизированный GitHub runner, автора PR, ChatGPT или Qwen независимым человеком-ревизором.

Отдельно назначенный, уполномоченный ревизор должен:
1. Проверить право независимого назначения reviewer и separation of duties, свою identity, отдельное хранение ключа подписи. Назначение и ключ не должны создаваться авторами проекта вместо ревизора.
2. Сверить exact source SHA, installer SHA-256, installed manifest SHA, содержимое всех pinned комплектов, непредвиденные сетевые эффекты и изменения прав на Windows. Считать отсутствие Authenticode **BLOCKER**.
3. Получить **настоящие** подписанные OWNER, REVIEWER и WITNESS release/task scopes, подлинные OS-pinned public keys и отдельный операторский trust/TPM/DPAPI. Запрещено передавать приватные ключи в чат/GitHub.
4. Проверить физически/организационно независимый VPS witness: отдельный key custodian, mTLS, живой TTL, persistent highwater, сервис после реального restart, отказ от replay/rollback и проверяемую запись до HOST network effect.
5. Проверить на *действительно защищённой установленной Windows SCM* полный CORE leased effect transaction, restricted SID, protected DACL и файлы без права записи у worker/model. Реально пройти cold Windows OS reboot, crash during effect, rollback/recovery/update. Лабораторный read-only gate не является таким доказательством.
6. Оформить явное signed **APPROVE** или **REJECT/INCONCLUSIVE** на точные source SHA + bytes подписанного EXE + манифест + версию внешнего сервера. Автор/бот не может выдавать собственный коммит, автоматизированные PASS или шаблон за независимое одобрение.

Только после независимого APPROVE на exact signed release и отдельного допуска владельца — возможность установки на пользовательскую Windows и включения production SCM/HANDOFF.

## 5. Результат и точка продолжения

**Статус: код CORE local CLAIMED → signed owner/reviewer → remote witness bound VERIFY-ONLY собран и проверен; физическая protected SCM и независимый свидетель в production НЕ РАЗВЁРНУТЫ; независимое одобрение НЕ ПОЛУЧЕНО.** 

Безопасные ограничения: `DRAFT`, `NO_MERGE`, `PRODUCTION_QUEUE_OFF`, `HANDOFF_PAUSED`, `NO_PAID_API`, `NO_SKILLS_ACTIVATION`, `NO_USER_PC_INSTALL`. Отчёт отдельного автора — внутренний аудит, не независимый.
