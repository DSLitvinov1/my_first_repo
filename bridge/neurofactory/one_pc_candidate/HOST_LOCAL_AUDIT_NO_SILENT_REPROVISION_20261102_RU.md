# НЕЙРОЗАВОД — 02.11.2026, новый найденный дефект локального журнала HOST

## Основание
Дополнительное read-only исследование после [PR #82](https://github.com/DSLitvinov1/my_first_repo/pull/82) обнаружило в `resident_host_audit_journal.py` создание отсутствующей SQLite базы через обычный `sqlite3.connect(path)` и `CREATE TABLE IF NOT EXISTS` при каждом append после HOST checkpoint. В отличие от `inspect()`, который уже отказался бы при исчезнувшем файле, `append_after_core_checkpoint` мог принять старый результат в новую пустую историю с прежней последовательностью. Это **отдельная локальная вспомогательная цепочка**, не `protected_host_attempt_ledger.py` с запретом удалённого replay. Никаких производственных прав этот модуль не выдаёт.

## Сделано
В [`resident_host_audit_journal.py`](resident_host_audit_journal.py) добавлен явный initial operator-only `provision_empty_local_audit_offline(path)`: создание только отсутствующего файла внутри приватной папки, exclusive `O_EXCL`, отдельная создание неизменной схемы. Рутинный `append_after_core_checkpoint` использует только `mode=rw` для существующего файла, проверяет размер, строгую схему и `PRAGMA quick_check`; отсутствие, усечение или повреждение дают `LocalAuditDenied`, не создают файл и не выполняют резервирования. Соединение закрывается явно, в том числе Windows. Испытания и только CI сценарий подписанного Windows SCM HOST дополнены явной инициализацией отдельно от runtime.

## Доказательства
- Изолированная Linux лаборатория на exact кодовом SHA `6fe017fcd406a17a2be9e67c5b64b0b6cac38ae6`: 7/7 тестов.
- [Windows+Linux GitHub Actions #41520465081](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41520465081) exact tested code+CI SHA `003cb1332f71e45d1b6c0b05357d30827f073404`: Windows 2025 PASS / Ubuntu 24.04 PASS; по 7 targeted tests на обеих платформах. Создаётся только временная база, реальная Windows-служба не устанавливается, не запускается.
- Негативные проверки: незавершённый CORE state не создаёт журнал, после подписанного checkpoint удаление DB не может быть скрыто, повторное offline создание не разрешено, повреждение hash chain/schema блокирует дальнейшие append, restart сохраняет существующую историю.

## Нерешённое
- Привилегированная замена *валидной* старой SQLite и полный rollback тома не обнаруживаются только локальной hash-chain. Нужен независимый операторский высокий счётчик на внешнем физически отделённом сервере, защищённый mTLS и хранение неизменяемого состояния.
- Нужны физическая защищённая Windows SCM/DACL, реальный Windows reboot/rollback, Authenticode подписанного исполняемого файла и отдельное независимое уполномоченное экспертное одобрение.
- Обнаружен другой кандидат на будущую адресную проверку: `local_workspace.WorkspaceStore` создаёт `workspace.sqlite3` и таблицы при обычном `__init__`, хотя это черновое UI-хранилище, а не авторизованная очередь CORE. Потеря пользовательских черновиков может быть замаскирована пустой базой; приоритет после доказанных security P0 и целостности production.

**Статус:** `LOCAL_HOST_JOURNAL_LOST_DB=DENIED_IN_DRAFT`, `NO_EXTERNAL_ROLLBACK_ATTESTATION`, `DRAFT_UNMERGED`, `RELEASE_NOT_APPROVED`. Не объявлять это независимой приёмкой и не запускать HANDOFF/production.
