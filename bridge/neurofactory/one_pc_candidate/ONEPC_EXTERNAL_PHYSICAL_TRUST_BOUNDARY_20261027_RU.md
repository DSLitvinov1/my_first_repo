# НЕЙРОЗАВОД — 27.10.2026: Windows release boundary и внешний highwater

Репозиторий: DSLitvinov1/my_first_repo. PR ветка `neurofactory-onepc-physical-trust-boundary-20261027`, исходная проверенная база PR #65, без новых изменений старых CORE, Qwen, подписанного CI HOST, очереди, UI, SKILLS.

**Главный итог:** подготовлена библиотека клиент↔внешний независимый свидетель, на Linux-одном CI реально выполнено TLS 1.3 mutual-auth + durable SQLite epoch reservation + Ed25519 подписанный ответ; обновлённый Windows review-установщик действительно включает и проверяет файлы защиты выпуска. Физического независимого сервера, реальных ключей и подписанного производственного ПО **НЕ СУЩЕСТВУЕТ В РАМКАХ ЭТИХ ИСПЫТАНИЙ**.

## Подтверждённые испытания

- [run #40545128019](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40545128019), PASS, исполняемый SHA `d106cb31b634ae6a45d38516bec3d907786722f3`. Десять адресных проверок клиентского кода: Ed25519, nonce/operation/machine/source, старые состояния, нет автоматически повтора при сетевой ошибке, запрет localhost и symlink источника ключа. Лабораторный сетевой обмен заменён mock, **не production**.
- [run #40545786571](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40545786571), PASS, SHA `94936d91c0cdc7ae2c0036d40870a17413f02d06`. Реальный SQLite WAL-disabled transaction + synchronous FULL фиксирует CAS highwater **до** подписания подтверждения, дубликат операции, неверная машина/пакет, несогласованный epoch блокируются. Отдельная физическая машина не использована.
- [run #40546275145](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40546275145), PASS, SHA `333f24c89229f26bf0e1ad43553167fe298b2fa5`. Настоящий TLS 1.3 клиент+сервер с отдельными временными CA/server/client сертификатами и отдельным Ed25519 подписантом, реальная SQLite запись и проверка MAC/signature, **внутри одного временного Linux CI, где только тестовая проверка remote IP локально обойдена**.
- [run #40546935844](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40546935844), PASS, SHA `536793c7991b5baf693add4e4d864dcc5448fd25`. Повтор реального localhost TLS3 симулятора и передача в GitHub Actions zip-архива только исходников remote witness/manifest без секретов: `Neurofactory-External-Witness-REVIEW-SOURCES-NO-KEYS`, срок хранения до 03.11.2026.
- [run #40546834469](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40546834469), PASS, SHA `56b497d65a58b9f787ad9d50cac38a48e168e2ae`. Машинный Windows Inno review installer с 15 уже pinned SOURCE компонентами, 73 stage-файлами приложения (плюс 5 отдельно перечисленных HOST обзорных файлов): добавлены `remote_highwater_client.py`, `independent_witness_receipt.py`, `combined_release_review_gate.py`, `secure_release_preflight.py`, `windows_package_preflight.py`. EXE реально собран, Windows install/uninstall, SHA каждого файла после install PASS. **UNSIGNED EXE** SHA-256: `c6fe086967ebd9e44b22d61d55ad3bb087161a1b8d6b7216bff65ed386420392`. Архив `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, срок хранения 03.11.2026.

### Непрерывная Qwen → CORE → restricted SCM HOST → подпись → local audit

Предыдущая успешная настоящая end-to-end hosted Windows проверка не повторялась: [№40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090), отдельный source SHA `e1e09cda0d6ec82870a1a437dcd25ecf1363371b`, один безопасный фиксированный эффект по синтетически owner-approved подписи, а не произвольная запись текста Qwen. Windows SCM после kill вернулся с новым PID, CORE checkpoint и local SQLite hash-chain audit сохранились.

## Жёсткие ограничения

1. **Постоянная активная производственная Windows CORE-HOST-служба ещё не установлена.** В установленном Inno-пакете лежат программные компоненты и guard-код, но службу с правом выполнять рабочие задания он НЕ активирует. На Windows пользователя никаких действий не было. Встроенный Python нуждается в утверждённых и проверенных криптографических runtime-зависимостях; размещение исходников не равно доказанной работоспособности полной production-инсталляции.
2. **Тестовый remote highwater backend ещё не отдельный сервер.** Приложение `external_highwater_mtls_server.py` на данный момент реализует *один TLS сеанс, инициируемый оператором*, не содержит автономного деплоймента, systemd unit, hardware-signer, журналов удалённого мониторинга, независимого escrow или внешнего WORM. Ключи в тестах временные. Доказательство живого удалённого HTTPS/TLS клиента существует только внутри одной тестовой Linux машины.
3. **Реальные публичные/секретные полномочия owner/host/reviewer/witness, независимый издательский код-сайн сертификат и внешний защищённый аппаратный monotonic floor** не настроены. CI подпись и локальная SQLite-среда не могут юридически/криптографически заменить владельца, ревизора или хранилище на отдельном физическом узле.
4. **Независимый reviewer ISSUE #11 не вынес APPROVED на окончательный бинарный SHA.** Открытие draft PR и комментарий его автора к Issue не является независимым решением.
5. **Настоящий remote доступ потребует отдельного уполномоченного Linux service account + machine/domain + mTLS CA/cert/private + контролируемого доступа из Windows.** Для подключённой Render-инфраструктуры список ресурсов требует *явно выбранного пользователем рабочего пространства*. Автосоздание серверов/платных ресурсов, изменение других проектов и экстракция чужих ключей НЕ производились.

Путь к описанию безопасного развертывания и требований отдельного узла: `bridge/neurofactory/one_pc_candidate/WITNESS_REMOTE_NODE_DEPLOYMENT_BLOCKERS_20261027_RU.md`.

## Следующая фактическая производственная граница

- Завершить подписанный по реальным issuer keys installer/updater, stage crypto/Windows SCM runtime с точными wheel хэшами и atomic ACL;
- реализовать в установленном сервисе проверку независимо закреплённых operator owner/reviewer/witness полномочий + fresh remote witness ACK *до* единственного явно owner-approved исполнения;
- отдельно протестировать дисковые snapshot rollback и потерю ACK ПОСЛЕ внешнего durable reservation;
- назначить независимого ревизора, подписать результат и провести реальный reboot/restore/upgrade на Windows ПК владельца.

До этого: **DRAFT / NO MAIN MERGE / NO PROD INSTALL / NO LIVE TASK EFFECTS / NO SKILLS.**
