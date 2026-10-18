# НЕЙРОЗАВОД — Windows-пилот защищённого внешнего свидетеля: доказательства и ограничения

Дата: 18 октября 2026. Репозиторий `DSLitvinov1/my_first_repo`. Отдельная ветка `neurofactory-windows-external-witness-pilot-20261018`, stacked DRAFT на Windows PR #19, самостоятельный DRAFT PR #24. Исходные Windows/HOST, CORE и другие владельческие ветки не перезаписаны и не объединены. Никаких действий на пользовательском ПК.

## Точная реализация

- `windows_external_witness_pilot.py`, Git blob `cd84f7097b5db2a92e3f0179ad5cb8ddfe01b5df` — тестовый mTLS TLS1.3 сервис с закреплённым сертификатом второго конца, CA verification, проверкой подписи Ed25519 ACK; строго один запрос через loopback Windows test, без постоянного запуска, автоустановки или производственного режима.
- Защищённое резервирование: SQLite `synchronous=FULL`, транзакция `BEGIN IMMEDIATE`, уникальные task_id, operation_id и target_sha256, проверяемая монотонная последовательность и SHA chain; данные переживают реальный **перезапуск процесса свидетеля**. При потере ответа UNKNOWN/NO RETRY, даже если сервер сохранил запись.
- `windows_named_pipe_pilot_receiver.py`, Git blob `fe4c7cca8ea25fc9ed461eede097aea2669f550f` — только в отдельной тестовой ветке добавлена опциональная привязка типизированного mTLS свидетеля перед инертной файловой записью; test flag позволяет требовать witness, отсутствие/ложный ACK не допускают файл. Старая ветка Windows PR #19 не менялась. Не объявлять это production: предыдущий локальный test-only маршрут остаётся в старом режиме без внешнего свидетеля, при промышленной приёмке это должно быть закрыто.
- `test_windows_external_witness_pilot.py`, blob `7bb30470774bb91130e6ca09889e8361550788d1`, 12 самостоятельных тестов протокола/перезапуска.
- `test_windows_witness_named_pipe_e2e.py`, blob `8e7101bdc788e52f026ba24349b15ecb6d7674e2`, 7 Windows E2E сценариев с реальным изолированным OneTaskCore SQLite/Git и Win32 Named Pipe, отдельным дочерним процессом свидетеля и временным файлом.

## Подтверждённые GitHub Actions — точный исполнявшийся коммит

**Окончательный проверенный код+тесты SHA `006bdc8cdc2f3070709698d478bc148be1a66323`**. Два независимых тестовых workflow по этому exact SHA:

1. [Windows witness protocol run 39112219373](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39112219373), job `117630584115`: **12/12 PASS, 0 failures**. Тесты: настоящая mTLS пара, сертификат/Ed25519 signer pinning, уникальные транзакции и цели, потеря ACK после commit, сохранившийся SQLite journal после **перезапуска процесса**, ненастоящий receiver rollback и блокирование повтора, подавление чужого клиента и запрет запуска без test gate.
2. [Windows CORE→Named Pipe→mTLS witness→file run 39112219363](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39112219363), job `117630584151`: **12/12 standalone witness + 7/7 E2E PASS = 19/19 PASS**. Один реальный инертный файл в private temporary directory; шесть отказных кейсов: forged owner Ed25519, истёкшая настоящая CORE SQLite lease, неверный TLS server cert pin, неправильная привязка task/target, обрыв witness ACK после резервирования, восстановление старого состояния receiver с повтором. Восстановление сделано на уровне файлов *учебного получателя*, не настоящим OS reboot/DB physical snapshot.

Промежуточный run `39111440606` был неуспешен из-за утечки открытых SQLite файловых дескрипторов в тестах Windows; исправлено. Промежуточный сквозной run `39111916942` завершился ошибками гонки запуска Named Pipe и неверного суммирования двух ответов в одном тесте; исправлено. Окончательные два run 39112219373 и 39112219363 успешны. Обе ошибки сохранены в CI history; не выдавать промежуточные failure за успех.

## Строгий уровень доказательства

Выполнены реальные тесты сетевого mTLS *между процессами на одном runner*, реальные SQLite journal commits/fsync и реальная тестовая Windows Named Pipe/файловая запись. **Не выполнены**: два отдельно авторизованных физических устройства, независимый администратор/невыгружаемые ключи/CNG/TPM, независимая защищённая от полного отката машины witness-сторона, внешнее сетевое развёртывание, настоящая служба Windows Service с отдельными SID/DACL, перезагрузка физической Windows машины, восстановление из фактического полного backup, REVIEW с внешней подписью. Тестовые ключи экспортируемы, в CI процессы разделены, но не ОС пользователи/не администраторы; IP loopback. Из одного ПК нельзя доказать защиту от snapshot rollback ВСЕГО компьютера; локальный SQLite FULL не антивзломный WORM.

На момент проверки доступен один Windows `WIN-LIDC05TBOQD` online, Desktop Commander remote_call allowance 0%. Ни попыток установки, ни обхода ограничений, ни перезагрузки не выполнялось.

Точная инструкция для 5 физических отрицательных и одной положительной транзакции после авторизации отдельной инфраструктуры: [WINDOWS_WITNESS_TWO_PHYSICAL_NODES_ACCEPTANCE_20261018_RU.md](./WINDOWS_WITNESS_TWO_PHYSICAL_NODES_ACCEPTANCE_20261018_RU.md).

## Статус независимой приёмки

По состоянию на запись нет отдельного подписанного REVIEW для exact новых CORE/HOST/WITNESS SHAs; это только авторские CI доказательства. Потребовать от независимого ревизора Issue #11 отдельно посмотреть exact SHA кодов и контроль публичных ключей, настоящие противодействия replay после физического snapshot, OS reboot, роли Windows Service SID, доверие к out-of-band TPM/highwater, отсутствие небезопасных fallback. До ответа `REVIEW_PENDING`, `RELEASE_BLOCKED`, `HANDOFF_PAUSED_BY_USER`, `PRODUCTION_QUEUE_OFF`; PR #24 остаётся DRAFT и не объединяется.
