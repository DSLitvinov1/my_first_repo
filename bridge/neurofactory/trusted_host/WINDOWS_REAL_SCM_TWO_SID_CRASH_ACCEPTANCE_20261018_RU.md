# НЕЙРОЗАВОД — проверенный Windows SCM: реальные два SID, запись, отказ и восстановление

Дата: 18 октября 2026 года. Исходный проект `DSLitvinov1/my_first_repo`. РЕЖИМ: **ограниченный учебный Windows-пилот; производственная очередь выключена.** Отдельная ветка `neurofactory-windows-two-sid-acl-recovery-20261018`. Источник CORE: неизменный SHA `beb08eff32923d8ca364aabfde0458f380acf8e7`, однотактная очередь `one_task_core.py` Git blob `ab1471813c6da29407c913b974a2209467a4b961`. 

## А. Две разные непривилегированные Windows-учётные записи — действительно испытано

Тест [Actions №39115568747](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39115568747), job `117640553341`, точный HEAD `2da6f339aa4d91261b1063d07ecdd92df00d1da5`, **SUCCESS**. Временный Microsoft Windows GitHub-hosted runner создал и затем удалил двух локальных НЕАДМИНИСТРАТИВНЫХ пользователей `nf_rc_...` (получатель) и `nf_wk_...` (исполнитель). Внутри ОС подтверждены **разные SID**. Исполнитель не имел права WRITE в защищённую папку получателя, не мог изменить receiver-owned журнал или подменить его; DACL разрешала запись только получателю, SYSTEM и Administrators. Утверждения в JSON без проверки фактического токена и Windows NTFS ACL не принимаются.

На точном pinned CORE синтетический Git task был помещён в настоящую однозадачную SQLite очередь, переведён в CLAIMED. Подписанная тестовым Ed25519 ключом владельца заявка была доставлена через настоящий Windows Named Pipe с явным SID-only DACL. Получатель проверил SID вызвавшего клиента путём Windows impersonation непосредственно после bounded pipe read, цифровую подпись и строго фиксированный целевой файл; создал один инертный `windows_pilot.txt` + ранее записанную `UNKNOWN_NO_AUTO_RETRY` квитанцию, fsync выполнен. Прямая запись CORE осталась запрещена.

Подтверждённые маркеры реального системного теста:
- `NF_TWO_REAL_DIFFERENT_NONADMIN_WINDOWS_SIDS=PASS`
- `NF_WORKER_PROTECTED_NTFS_DIRECT_WRITE=DENIED`
- `NF_TWO_SID_SIGNED_ONCE_AND_REPLAY_BLOCKED=PASS`
- `NF_TWO_SID_OWNER_SIGNATURE_FORGERY=DENIED`
- `NF_TWO_SID_FORCED_POST_FSYNC_CRASH_RECOVERY=PASS_TEST_ONLY`
- `NF_NEUROFACTORY_LIVE_QUEUE=OFF`

Во время аварийной проверки ОС принудительно завершила receiver-процесс ПОСЛЕ fsync тестового файла и ДО ответа клиенту. После запуска нового receiver-процесса повтор подписанного запроса был отклонён; файл и защищённая локальная UNKNOWN квитанция сохранились.

## Б. Настоящая зарегистрированная служба Windows SCM — действительно испытано

В отличии от раннего Python-каркаса реализован **реальный SCM `ServiceFramework`** в файле `windows_scm_one_shot_receiver.py`; оператор в полностью временной GitHub Windows-среде установил службу `NeurofactorySandboxReceiver` под отдельным `nf_rc_...` без административной роли. Ей специально выдали `SeServiceLogonRight` через Windows LSA (в одноразовом CI окружении), а не повысили до Administrators. Применили NTFS ACL для папки результата и **отдельную строго read-only для получателя** конфигурацию публичного owner ключа, запретив worker переписывать trust anchor. Реально использовались Windows `sc.exe` / SCM START, затем STOP, START, повторная доставка и отказ от второй записи; исходный файл остался прежним. Ни один реальный ключ пользователя не использован.

[Actions №39115608076](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39115608076), job `117640660576`, **SUCCESS**, точный HEAD `598f7e4ee24f62583738e1f8e2481b7bc81b246f`.
В журнале: `NF_DISPOSABLE_RECEIVER_ACCOUNT_LOGON_AS_SERVICE_GRANTED=PASS`, `NF_WINDOWS_REAL_SCM_SERVICE_REGISTERED_UNDER_SEPARATE_NONADMIN_SID=PASS`, `NF_WINDOWS_REAL_SCM_STOP_START_REPLAY_DENIED=PASS`, `NF_WINDOWS_PRODUCTION_QUEUE=OFF`. Зарегистрированные временные пользователи/служба удалены в cleanup, GitHub runner уничтожается. Первый SCM красный тест вскрыл отсутствие права SeServiceLogonRight (`StartService FAILED 1069`), исправлено через отдельно ограниченную CI-only LSA процедуру; окончательная успешность подтверждена именно run №39115608076.

## Проверенные исходники и строгие ограничения

Точный проверенный исполняемый SCM HEAD `598f7e4ee24f62583738e1f8e2481b7bc81b246f`:

- `windows_receiver_sid_acl_guard.py`: Git blob `c25d4726811ae6cf5f3f7cc2447e7b0f6d0cf7eb`; проверяет реальный токен и NTFS DACL protected output **и папки/файла публичного owner pin**.
- `windows_scm_one_shot_receiver.py`: Git blob `182aa968915ef1a281a279e02bc38696e2f31ae1`; настоящая `ServiceFramework`, принимает только один изолированный signed sandbox effect, не включает очередь и не содержит установщика для ПК пользователя.
- `windows_named_pipe_pilot_receiver.py`: Git blob `e0b6ba9b9c5194977c8181a588a9877846e98d57`; явный DACL Named Pipe, owner Ed25519 и O_EXCL+fsync.
- `test_windows_two_sid_signed_effect_ci.ps1`: Git blob `6d4b54ac02df09f803ba7ade16c7be6d44e89667`.
- `test_windows_real_scm_service_ci.ps1`: Git blob `a88ce9d0bc2347ebd54e2cd87f27b9f0bd835873`.
- `windows_ci_allow_service_logon.py`: Git blob `799e6748bd42b7f626c722233e54ae66bf093186`; разрешён исключительно на временном GitHub-hosted CI, никогда как обычный пользовательский установщик.

### Не подтверждено — не объявлять производственно завершённым

1. Пользовательский Windows-компьютер через резервный мост **не изменялся**, установка на нём не проводилась, аппаратная Windows перезагрузка не выполнялась. Ранее известны ограничения квоты удалённых команд.
2. Действующая схема одного ПК не обеспечивает независимую защиту от отката всего диска/БД привилегированным администратором. Локальный UNKNOWN marker даёт защиту только от обычного повторного выполнения/перезапуска при сохранённом NTFS диске. Для защищённой автономной промышленной записи требуется внешнее независимо администрируемое монотонное резервирование операций и независимые ключи.
3. Учебный owner Ed25519 приватный ключ был создан только в CI supervisor и не передавался двум непривилегированным пользователям; реальные полномочия GitHub владельца, TPM/CNG защищённые ключи и отдельно подписанная OWNER установка ещё НЕ подтверждены.
4. Получатель ограничен одним безвредным файлом в строго изолированной папке; не поддерживает рабочую очередь и запись реальных пользовательских проектов. Не является непрерывно работающим много-задачным production сервисом.
5. Независимый REVIEW человеком/другой уполномоченной личностью **не получен**. Самостоятельные тесты автора и общая GitHub identity не заменяют независимое одобрение.

До настоящего разрешения владельца, физического теста на целевой Windows машине и независимого REVIEW: `RELEASE=BLOCKED`, `HANDOFF=PAUSED_BY_USER`, `LIVE_QUEUE=OFF`. PR не объединять автоматически.
