# НЕЙРОЗАВОД — подключение внешнего контроля отката к Windows SCM, установка проверочного пакета на компьютер владельца

Дата: 05.11.2026 (Москва/Абхазия); текущее состояние подтверждено выполненными операциями, а не планом. [DRAFT PR #96](https://github.com/DSLitvinov1/my_first_repo/pull/96) (стек от #95→#94→#93→#92→#91→#90), никаких слияний, публикаций, оплаченных сервисов, запуска SKILLS/HANDOFF или production очереди.

## Внесённые изменения

- Изменён существующий `windows_named_pipe_pilot_receiver.py`: добавлены аргументы `recipient_signed_witness_guard` и `require_signed_external_witness`. В обязательном режиме отсутствие callback или CORE guard → отказ до создания именованного канала. После проверки реального worker SID и подписи OWNER, сверки CORE CLAIMED и синхронной фиксации `UNKNOWN_NO_AUTO_RETRY` в файл в самой службе выполняется проверка внешней квитанции **до** создания разрешённого файла. Затем вновь сверяется CORE. Неуспешный ответ, неверная подписанная квитанция, истёкший lease или потеря ACK не дают файла и не приводят к автоматическому повтору.
- Изменена существующая `windows_scm_sandbox_receiver.py`: ОС-служба поддерживает отдельно включаемый администратором строго обязательный режим `neurofactory.windows.ci_service.remote_required.v1`; если в режиме отсутствует защищённая политика, то SCM прекращает запуск. Никакого понижения до старого режима только CORE. Реальная служба считывает actual service SID через Windows API, а не из сообщения worker.
- Добавлен `scm_witness_service_policy.py`. Выделенная защищённая политика с exact signer keys, actual worker/service SID, hash операции, epoch, owner/reviewer signed claim, mTLS pinned remote identity и двумя существующими журналами конструирует `OneShotHostWitnessBridge` и `OneShotScmRecipientFence` **внутри службы**. Подлинный закреплённый OWNER публичный ключ должен совпасть с ключом пилотной подписи Windows; иначе отказ, даже если подписи по отдельности валидны. NTFS reparse ссылки в корне/политике запрещены. Этот код ни при каких условиях не выдаёт production authorization, HSM/physical custody нельзя аттестовать по одному JSON.
- Для проверки существующий тест реальной `LocalService` SCM дополнен негативным сценарием `remote-required-missing` и проверено отсутствие запуска и файлового эффекта при отсутствии подписанного независимого свидетельства. Старый положительный CI-only тест с реальным restricted SID и отдельным Windows пользователем сохранён.

## Выполненные проверки

1. **Exact Python/Windows CI source SHA `bba8c5de2e4caaf7c6de714f2651b042fb0e35e9`**, [GitHub Actions #41920387831 SUCCESS](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41920387831): 8 проверок отсутствующей/повреждённой политики и обязательных callback, 34 unit/integration теста signed OWNER+REVIEWER+CORE witness fence (с настоящими Ed25519 и SQLite, сетевой ACK в этом наборе подменён криптографически корректной фикстурой), actual SCM remote-policy-missing fail-closed, real Windows SCM regression valid owner fixed file, foreign SID denied, expired CORE lease denied, crash/restart no duplicate. Это не полноценная live mTLS witness через реальный SCM на двух машинах.
2. **Exact installer source SHA `049caa91429ee81145f96f22f57612001448ece7`**, [GitHub Actions #41920321041 SUCCESS](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41920321041): инертная review-only Windows Inno-сборка. SHA256 EXE `794D0BE71BB6A6DC404D95E00D359F34CBA2098445EDD8725A5B77E55BD38826`, артефакт `13366627346`. Проверены инсталляция на временной Windows, 15 закреплённых CORE/HOST/PROVIDERS/COORD source components, ACL/preflight deny, установленный Python importer и полное удаление. В составе лежат три новых SCM/witness исходных файла; сама защищённая служба установщиком не регистрируется.
3. **На реальном Windows `WIN-LIDC05TBOQD` (Windows 10, ~5726 MB RAM)**: через Desktop Commander с административным токеном загружен свежий пакет из private GH, точно проверен EXE SHA256, использован только отдельный каталог `C:\ChatGPTProjects\NeurofactoryReview-20261105-verified`. Реальная установка завершена с exit 0. По установленному `release-manifest.json` заново вычислены и совпали SHA256 **84** файлов, source SHA соответствует `049caa91429ee81145f96f22f57612001448ece7`; установлены SCM/pipe/policy исходники без системного сервиса. Исходные старые манифесты сохранены в загрузочных папках для отката. `Get-CimInstance Win32_Service` подтверждает 0 Neurofactory-сервисов после установки. Прямой Windows/резервный мост уже ранее принимал реальные UTF-8 данные Qwen с Linux и подтверждал SHA, [квитанция](https://github.com/DSLitvinov1/lesson3.1/blob/chatgpt-control/bridge/results/neurofactory-20261103-cloud-qwen-owner-windows-readonly-utf8hex.json).
4. **Code Signing (только чтение)**: `Get-AuthenticodeSignature` обоих EXE возвращает `NotSigned`; в `Cert:\CurrentUser\My` и `Cert:\LocalMachine\My` не обнаружено ни одного действительного сертификата CodeSigning с private key. НЕ создавать самоподписанный ключ в качестве якобы действительного publisher signing.
5. **Облачный Linux** `litd12123.clodocd.com`: доступен, модель Qwen2.5 Coder 1.5B на нём реально запускалась, но `neurofactory-witness` inactive/not-found; `/etc/neurofactory/witness/production.json` и `/var/lib/neurofactory-witness/remote-ledger.sqlite3` отсутствуют; `cloudagent` без `sudo -n`. Это физически отдельная машина, но **НЕ** установленный отдельным доверенным оператором antirollback anchor.
6. Независимый HUMAN [REVIEW Issue #11](https://github.com/DSLitvinov1/my_first_repo/issues/11) открыт. CI результаты размещены для ревизора, но ChatGPT не может самостоятельно выдать независимую подпись или подтверждённое полномочие стороннего лица.

## Строгий статус после выполненной работы

- `ACTUAL_SCM_CODE_REQUIRES_OPERATOR_SIGNED_WITNESS=IMPLEMENTED`
- `WINDOWS_REAL_SCM_MISSING_WITNESS_DENIAL=CI_PASS`
- `SCM_ONE_USE_SIGNED_SCOPE_CORE_TEST=CI_PASS_34`
- `PHYSICAL_OWNER_PC_INERT_REVIEW_INSTALL=PASS_84_FILES`
- `OWNER_PC_PRODUCTION_SERVICE=NOT_INSTALLED`
- `TWO_PHYSICAL_NODES_SIGNED_MTLS_SCM=NOT_TESTED`
- `INDEPENDENT_REMOTE_ROLLBACK_ANCHOR=NOT_PROVISIONED`
- `REAL_AUTHENTICODE_PUBLISHER=NOT_AVAILABLE_NOT_SIGNED`
- `INDEPENDENT_REVIEWER_FINAL_APPROVAL=NOT_RECEIVED`
- `PRODUCTION_RELEASE=BLOCKED`

Причина: отсутствие реальной независимой цепочки операторских ключей, производственного Windows CodeSigning и независимой приёмки. Даже подписанная TLS-квитанция не является общей ACID-транзакцией CORE SQLite + remote anchor + NTFS; возможен UNKNOWN, который требует ручного разбирательства без повторного исполнения. Нельзя публиковать/запускать производственный CORE/HOST с тестовыми private keys, самоподписанными сертификатами либо без независимого допуска.

## Продолжение без пересоздания

Проверить живую вершину PR #96, точный tested code SHA `bba8c5de2e4caaf7c6de714f2651b042fb0e35e9` и packaged SHA `049caa91429ee81145f96f22f57612001448ece7`. Подтвердить у доверенного независимого оператора полномочия на отдельную Linux service + монотонный защищённый highwater и приватные TLS/Ed25519 ключи, получить действительный publisher CodeSigning certificate и независимого ревизора с правом подписать verdict. После раздельных реальных двухмашинных с проверкой remote ACK, crash/reboot/rollback / Windows SID и signature positive/negative тестов провести operator-authorized production release на уже доступный Windows через резервный мост. До выполнения воротов не регистрировать производственную Windows-службу.
