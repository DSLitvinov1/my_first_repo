# НЕЙРОЗАВОД — 02.11.2026. Отказ от незаметного восстановления потерянной CORE SQLite очереди

## Точная цепочка
- Основание: [расширенный внутренний аудит REVIEW №11](https://github.com/DSLitvinov1/my_first_repo/issues/11#issuecomment-6585832960), finding NF-REVIEW-10.
- База: [DRAFT PR #80](https://github.com/DSLitvinov1/my_first_repo/pull/80), exact base SHA `abe40808ec5c873b4cb94d8c7ab7b058e0e2f532`.
- Исправление CORE и тестов, точный tested code SHA `d366aea749e92487405a2c71a803585e9692a2c3`. Отдельная ветка `neurofactory-p0-core-no-silent-queue-recreate-20261102`; без merges и без production.
- GitHub Actions [run #41518575752](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41518575752) на том же exact SHA: **Windows 2025 = SUCCESS 58/58** и **Ubuntu 24.04 = SUCCESS 58/58**. Состоит из 8 тестов local CORE observer, 42 подписанных CORE→HOST witness integration и 8 подписанных owner-admission. Реальные disposable SQLite и тестовые Ed25519 подписи. Внешний witness network mock; реальных производственных файловых эффектов нет.
- Дополнительные адресные тесты интеграции CORE→HOST в пользовательской изолированной Ubuntu лаборатории до последней поправки к Windows handle: **71/71 PASS**; после неё официальная матрица на точном кодовом SHA выше **58/58 на обеих платформах**.

## Устранённый дефект
Прежний `OneTaskCore.__init__` автоматически создавал отсутствующий файл `queue.sqlite3` и таблицу `single_job` (при этом обнулялась история уже занятого единственного слота). В воспроизведении аудита после `CLAIMED` удаление базы и новый constructor давали `EMPTY` и повторный `QUEUED`. Это несовместимо с принципом NO REPLAY.

В [`one_task_core.py`](../development/core_owned/one_task_core.py):
1. Добавлена отдельная операторская функция `provision_empty_core_queue_offline(root)`: только первый запуск для заранее подготовленного пустого приватного CORE root; требует отсутствия `state` и `sandbox`. Создаёт один раз базу эксклюзивно с `O_EXCL`, `0600` на POSIX и фиксированной схемой; при повреждённом/прерванном первом provisioning НЕ сбрасывает состояние заново. НЕ вызывается автоматически обычным запуском Windows SCM.
2. Рабочий `OneTaskCore.__init__` читает только уже существующие `state/sandbox/queue.sqlite3`, сверяет полную точную схему и SQLite `quick_check`. Отсутствие/усечение/замена схемы означает отказ, а не реконструкцию пустой базы. `_connect` использует SQLite `mode=rw` на каждом доступе и ни при каких условиях не создаёт исчезнувшую базу.
3. Первоначальные **только тестовые** сценарии и CI-only Windows SCM подготовка явно вызывают offline provisioning; обычная service loop никогда не создаёт CORE очередь.
4. На первом Windows CI запуске [#41518470324](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41518470324) реальные негативные тесты удаления базы остановились на Windows file lock. Причина найдена: SQLite connection context manager в операторском initial provision не закрывал файловый дескриптор. Заменено на явное `contextlib.closing`; окончательный Windows+Linux прогон #41518575752 PASS, файловые дескрипторы закрываются.

## Негативные проверки
- После фактического claim удаление временного SQLite файла → повторный `OneTaskCore` и прежний экземпляр fail closed, файл не создаётся.
- После удаления всего `state` при сохранённом `sandbox` — отказ без восстановления.
- При уничтожении таблицы `single_job` внутри существующего файла — отказ без исправления или перезаписи.
- На неизменном заранее provisioned CORE state обычный restart сохраняет исходную `QUEUED` задачу.
- Повторное явное offline provisioning на уже занятом root отвергается.

## Внешние и физические границы, НЕ ЗАКРЫТЫЕ тестом
- Привилегированный оператор может откатить **весь** CORE root к старой валидной копии или удалить сам root полностью; локальный процесс без внешнего доверенного хранилища/монотонной эпохи не способен криптографически отличить новый root от восстановленного. Это всё ещё требует отдельного operator-custodied remote witness, защищённых ACL/SID и независимо хранимой highwater.
- В другом компоненте `protected_host_attempt_ledger.py` старый корректный SQLite snapshot после операторского rollback ещё допускает повторное локальное резервирование; удаление DB там уже заблокировано. Независимый внешний сервер обязан атомарно отказывать в повторе по nonce/operation + external epoch.
- Не установлен полноценный защищённый Windows SCM на ПК владельца, нет реальных operator-pinned keys, отдельного живого независимого VPS witness, подписанного Authenticode установщика и независимого человеческого reviewer verdict.
- Установщик и физический restart/recovery на exact SHA этого исправления пока отдельно не проходили испытание. Испытания GitHub CI ≠ физическая приёмка.

**Итог:** `CORE_MISSING_DB_REPLAY=FIXED_IN_DRAFT`; `CI_TARGETED_LINUX_WINDOWS=PASS`; `HOST_PRIVILEGED_ROLLBACK=BLOCKED_BY_EXTERNAL_WITNESS_ONLY_NOT_PROVEN`; `PRODUCTION_RELEASE=NOT_APPROVED`. Без merge/HANDOFF/production queues, без воздействия на пользовательский Windows и чужие проекты.
