# НЕЙРОЗАВОД — 03.11.2026. Actual restricted Windows SCM сверяет живой CORE CLAIMED до файловой операции

**Уровень доказательства: isolated disposable CI / НЕ промышленная приёмка.** DRAFT [PR #90](https://github.com/DSLitvinov1/my_first_repo/pull/90), stacked на DRAFT [PR #88](https://github.com/DSLitvinov1/my_first_repo/pull/88), base exact `7340c824ca5ee5ce6d06814707e4801542025894`. Не устанавливалось и не запускалось на ПК владельца. Ветка main не менялась. Production/HANDOFF/SKILLS выключены.

## Подтверждённый исходный пробел

В существующем реальном CI-only Windows SCM защищённый LocalService с RESTRICTED per-service SID принимал подписанную владельцем файловую заявку по Named Pipe от отдельного низкопривилегированного Windows пользователя, но на самой стороне **получателя** не сверял актуальный CLAIMED/lease с реальной CORE SQLite. Успех worker-side readback НЕ гарантировал, что состояние не изменилось до выполнения.

## Изменение

1. Добавлен `one_pc_candidate/scm_recipient_core_claim_guard.py`: читает уже существующую CORE SQLite без пересоздания; проверяет единственный CLAIMED с попыткой №1, действующую аренду по локальному системному времени, отсутствие результата/квитанции, task_id/project_id/source_SHA, полный canonical spec SHA256, ожидаемый output SHA256, pin исполнителя из заранее защищённой operator-конфигурации. Входящий Named Pipe не может указать trust roots, путь SQLite или изменить pin.
2. Existing `trusted_host/windows_scm_sandbox_receiver.py` в изолированной SCM-среде обязательно создаёт этот получательский guard из установленной администратором конфигурации; другой процесс не может подменять поля запроса на привилегированное разрешение.
3. Existing `trusted_host/windows_named_pipe_pilot_receiver.py` вызывает guard после SID+Ed25519 проверки, **до** сохранения долговечной отметки UNKNOWN и повторно после отметки непосредственно перед одной файловой операцией CREATE_NEW. Crash после UNKNOWN до файла и повторный запуск остаются запретными. После создания файла защищённая служба подписывает test HOST receipt, который существующий CORE валидирует при финализации.
4. В тестовой инсталляции CORE взят из актуального PIN `f4c424a5544749668fd2eb5657207e7873a6039a`, его SQLite **явно подготовлена** оператором. Реальная служба получила только чтение CORE state под своим отдельным service SID, не доступ к owner signing key и не право записи в CORE.
5. Добавлены 10 точечных сценариев и фактические Windows LocalService + иной пользователь CI: правильное разрешение, поддельная подпись, **полностью корректная подпись на неверный payload**, просроченная CORE lease, запрет ACL, перезапуск после фатального сбоя, повторная попытка, signed HOST confirmation / SQLite restart.

## GitHub Actions — подтверждённый exact SHA

**TESTED CODE + CI SHA `a712b12313a9e221a5773dcc9ffaaab823d839c8`**. [Actions #41533586933](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41533586933) **SUCCESS**, все четыре задания:

- Ubuntu 24.04 — 10/10 unit guard PASS.
- Windows 2025 — 10/10 unit guard PASS.
- Настоящий временный Windows SCM LocalService, normal — SUCCESS. Реальный RESTRICTED per-service SID/NTFS ACL, иной пользователь и Ed25519 проверка, действительная подпись на неверный output отвергнута **без файловой операции**; истёкшая CORE lease отвергнута **до UNKNOWN/file**; ровно один правильный тестовый файл записан защищённым service SID; подписанная HOST receipt принята текущим CORE; повторное закрытие задачи после restart отвергнуто.
- Настоящий временный Windows SCM, crash-window — SUCCESS. После fsync UNKNOWN служба аварийно завершена до файла; при перезапуске нет повторной файловой операции.

Предыдущие промежуточные CI #41533134771 и #41533213828 — **FAIL**, поскольку первый вариант ошибочно проверял точный класс Path вместо `isinstance(Path)`, а также не находил модуль при импорте из source tree. Дефекты исправлены и те же тесты повторно завершились SUCCESS на exact SHA выше. CI #41533294301 SUCCESS на предыдущем SHA `b57d46cadc91e4351fd4f33eb7c984c076950aac` без последнего усиленного fully valid alternate payload test.

## Что именно НЕ доказано

- Проверка CORE внутри получателя — **две read-only SQLite операции, НЕ единая транзакция с внешним witness и filesystem**, поэтому между наблюдением и эффектом всё ещё возможна гонка; служба не обладает полноценным recipient-side CAS/fencing.
- Локальная SQLite, даже с ACL и SHA, не защищает от привилегированного восстановления целостного старого состояния. Нет физически независимого оператора VPS witness/highwater, реальных mTLS ключей и независимого монотонного якоря.
- HOST receipt в CI подписана кратковременным программным тестовым ключом, не настоящим аппаратно защищённым ключом. Нет раздельной удостоверенной эксплуатационной подписи OWNER+независимого REVIEWER, физической аттестации machine identity и обновляемого списка отзывов полномочий.
- Windows-сервис остаётся `NeurofactorySandboxReceiverCI` и принимает только строго фиксированный безвредный тестовый файл. Он НЕ `NeurofactoryCoreHost` production-пакета и не запускается установленным review-only Inno EXE. В настоящем приложении нельзя активировать его по итогам этих тестов.
- Нет Authenticode финального EXE, физических restart/backup/rollback проверок владельца и подписанного APPROVE от отдельного уполномоченного человека Issue #11.

## Решение

`REAL_RESTRICTED_WINDOWS_SCM_TEST_EFFECT=PASS`.
`RECIPIENT_CORE_CLAIM_SCOPE_READBACK=PASS_CI_ONLY`.
`INVALID_SIGNED_PAYLOAD_AND_EXPIRED_LEASE_DENY=PASS`.
`CRASH_UNKNOWN_NO_RETRY=PASS`.
`ATOMIC_RECIPIENT_SIDE_EXTERNAL_FENCING=NOT_YET_IMPLEMENTED`.
`INDEPENDENT_ACCEPTANCE=NO`.
`PRODUCTION_RELEASE=BLOCKED`.

**Никакого merge, установки пользователю, очереди в рабочую систему, выдачи постоянных ключей и платных API.**
