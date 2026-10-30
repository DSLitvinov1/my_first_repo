# НЕЙРОЗАВОД — 30.10.2026. Настоящий подписанный запрос HOST → отдельный свидетель: интеграция проверки, без эффекта

Рабочая ветка `neurofactory-p0-signed-remote-service-bridge-20261030`, основание защищённая HOST/установочная DRAFT ветка PR №72, SHA `d73b7d628ee5f3ade7deca62a559fa6aaffcacb5`. Не изменены владельческие CORE/Qwen/PROVIDERS/HOST/REVIEW ветки; не объединён ни один PR.

## Реально выполнено

1. В `protected_host_remote_bridge.py` создан новый **одноразовый мост** между существующими `protected_host_task_authority.py` и `remote_highwater_client.py`, не новая подсистема. Он:
   - до какой-либо сети проверяет криптографические Ed25519 OWNER и отдельно назначенного REVIEWER над одним точным task/project/source/package/machine/worker SID/service SID/nonce/epoch;
   - сравнивает каждое поле с **отдельно предоставленным оператором** точным зафиксированным scope и тремя различными pinned public-key identities; не принимает ключи из текста Qwen, UI или сетевого сообщения;
   - сравнивает все поля witness reservation claim с уже проверенным OWNER+REVIEWER claim;
   - выполняет максимум **один** реальный клиентский запрос через существующий mTLS TLS1.3 с CA/hostname и точным pinned DER fingerprint сервера, не создавая новый транспорт; при любой неоднозначной ошибке **UNKNOWN, NO AUTO RETRY**;
   - проверяет полную Ed25519 подписанную квитанцию внешнего witness существующим `verify_one_host_operation` с bound epoch/nonce/source/package, не подменяя удалённую квитанцию локальной;
   - возвращает только `SIGNED_TASK_AND_REMOTE_ACK_VERIFIED_TEST_NO_EFFECT`, `production_task_effect_allowed=false`, `production_release_approved=false`, `actual_core_lease_attested=false`. Никакого кода записи файлов, автозапуска, установки службы, выдачи сертификатов или вызова модели внутри моста нет.
2. В `test_protected_host_remote_bridge.py` проверены десять адресных сценариев, импортирующих старые четырнадцать криптографических тестов OWNER/REVIEWER/WITNESS; это **10 новых + 14 прежних = 24 PASS**.
3. В уже существующий машинный *review-only* Inno Setup `windows_setup/NeurofactoryMachineReview.iss` добавлен новый bridge source. Существующий GitHub Actions staging явно копирует его в `review-host`, записывает SHA всех 75 файлов в общий manifest, сверяет после установки его контрольную сумму и удаляет пакет; тест CI подтверждает отсутствие установленной production SCM-службы и невыпуск на test runner.

## Проверенные точные коммиты и тесты

- [Адресный bridge Actions #41079904608](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41079904608), тестовый код SHA `c9b7842827fdb5af18088fb41345e592f8f2fe6e`: 24/24 PASS (10 новых и 14 импортированных; signed ACK внутри этого адресного теста моделируется, а настоящий TLS1.3 mTLS peer уже отдельно подтверждён старой лабораторной проверкой #40546275145). Не заявлять физическое независимое размещение узла из этого теста.
- [Итоговая Windows Inno компиляция/установка/проверка SHA/удаление #41080174700](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41080174700), точный исходный и workflow commit `e48e34e0e6836bb75e30857f1d4dd7bcd75044f7`, job `124146859608`: **SUCCESS** на временном Windows Github runner.
- Полученный review-only **UNSIGNED** инсталлятор SHA256 `1BFBA8A13130B31B930AAD59E7725E81990368D40CE7EF4CF920EAF0F3A795A7`. GitHub Actions artifact `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, ID `12987959795`, доступен из run, expires `2026-11-06T15:23:53Z`. 15 embedded immutable CORE/HOST/PROVIDERS/COORD components, 75 staged app+review files.
- Ранее [P0 HOST NTFS ACL source fix и targeted Windows run #41078097428](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41078097428) PASS; новая ветка наследует устранение arbitrary SID WRITE/DELETE_CHILD/unsafe-owner.
- Ранее реальная Qwen→CORE→restricted SCM signed fixed-effect→SQLite audit на **одном disposable CI Windows** [#40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090) PASS. Дорогостоящая модель сегодня повторно не запускалась.

## Не завершено (не путать с успешно проведённой сборкой)

- Это подготовленный bridge к производственному HOST, **НЕ подключённый постоянно установленный production service receiver**. Уже существующая `neurofactory_dormant_service.py` остаётся безопасно заблокированной. Машинный review-only установщик **не регистрирует** real production Windows SCM SERVICE, не открывает очередь и не делает project file effects.
- Передача `operator_expected`, публичных ключей и floor в bridge от реального Windows OS-protected operator trust store, а также проверка подлинного рабочего CORE lease/SID на момент неизбежного файлового эффекта и его crash-consistent transaction — ещё не реализованы и не подтверждены на физическом ПК.
- Независимый физически отделённый VPS witness с настоящими приватными ключами, mTLS за вне-rollback каналом и operator-controlled monotonic highwater **не развёрнут**. Исходники существующего отдельно защищённого VPS/witness находятся в PR #67 и PR #66; тесты там лабораторные, не внешний реальный VPS.
- Не предоставлены реальный подписанный Authenticode издательский сертификат и физическое удостоверение ключей OWNER/REVIEWER/WITNESS, нет отдельно назначенного independent REVIEW подписи на exact SRC+INSTALLER SHA. Нет полномасштабной холодной Windows OS reboot/upgrade/restore проверки на пользовательском ПК.
- Desktop Commander на момент работы показывал один Windows ПК `WIN-LIDC05TBOQD` online, но `remote_calls_left_pct=0`; ни файлов, ни служб, ни реестра, ни модели пользователя не изменял. Ни один сторонний VPS/проект клиента не использовался и не оплачивался.
- SAFE state: `DRAFT`, `UNMERGED`, `RELEASE_BLOCKED`, `HANDOFF_PAUSED_BY_USER`, `PRODUCTION_QUEUE_OFF`, `NO_PAID_API`, `NO_SKILLS_ACTIVATION`.

## Независимый REVIEW и следующие действия по минимальному критическому пути

1. Отдельно назначенный REVIEW проверяет exact repo SHA, опубликованный **неподписанный** exe SHA, source provenance, NTFS owner/ACL и подписи, запрашивает защищённые operator-installed public pins без передачи приватных ключей в репозиторий.
2. Владелец подтверждает отдельный VPS witness и учётную запись оператора, реальные сертификаты; уполномоченный администратор устанавливает witness в защищённой OS session и предоставляет заверенный read-only remote highwater evidence. До этого bridge выполняет только лабораторные запросы.
3. Отдельный оператор связывает bridge с настоящей restricted SCM receiver и живой CORE lease в одной устойчивой к сбоям операции, исключая обход legacy test fixture и UNKNOWN retry. Независимый ревизор проверяет новые точные SHAs и физический fail-closed replay/reboot.
4. Только после одобренного подписанного окончательного installer EXE и отдельного разрешения владельца возможно установка на реальный Windows ПК и локальный пилот. Если нужен безопасный ранний запуск UI, есть отдельный review-only/per-user пилот без production автоматизации, не считать его полноценно работающим НЕЙРОЗАВОДОМ.
