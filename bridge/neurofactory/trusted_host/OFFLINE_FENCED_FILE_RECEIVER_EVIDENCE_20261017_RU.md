# TRUSTED HOST: отдельный TEST-only конечный получатель файлового эффекта

Дата: 17 октября 2026. Статус **ПРОВЕРЕНО НА GITHUB-HOSTED LINUX В ОДНОРАЗОВОЙ СРЕДЕ; НЕ ПРОИЗВОДСТВЕННАЯ АВТОРИЗАЦИЯ**.

## Новый исполняемый код
`bridge/neurofactory/trusted_host/offline_fenced_file_receiver.py`, exact source Git blob `96739ec56183aca55b4102c4d0bb5cc6f3dabc9c`.
Точный тест `test_offline_fenced_file_receiver.py` Git blob `577c88638044042dc162a72aeb5edb79554bd7ee`.
Ветка владельца `neurofactory-trusted-host-owned-20261015`, самостоятельный workflow `.github/workflows/neurofactory-trusted-host-owned-offline-receiver.yml`.

Фактический test-only алгоритм: проверка приватного disposable каталога и явного environment-gate, реальный HOST `nf_test` PostgreSQL16 CAS и `nf_effect_intent`; проверка живого состояния аренды, worker/epoch/fence SHA, scope владельца/репозитория/источника/файла/политики/операции из тестовой БД; проверка настоящей Ed25519 signature с переданным тестовым ключом и текущим локальным временем. До файла коммитится один `nf_receiver_effect_journal` со статусом UNKNOWN, ключами задачи/idempotency и контрольной суммой. Затем единственный новый регулярный файл в ПРИВАТНОЙ тестовой директории создаётся через Linux dirfd/O_NOFOLLOW/O_EXCL и fsync. После записи квитанция становится `COMPLETED_TEST`; если запись или подтверждение прерваны, остаётся UNKNOWN и автоматическое повторение запрещено. Повторная доставка запрещена даже после успешной записи.

Результат успеха `ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY`, флаги реального разрешения владельца, защищённой подписи/отдельной OS identity, независимого получателя, живого продакшн допуска, авто retries/публикации — **FALSE**. Тестовое значение `fixture_authorized=true` и временный Ed25519 private key НЕ являются реальным подтверждением права владельца.

## Фактический прогон
Исходники HOST и тесты на точном коммите `0c33d8181e102e2ca3f47559ae6abeb2f4b72757`. GitHub-hosted Ubuntu24.04, ephemeral Postgres16 `nf_test`, [Actions №39025550761](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39025550761), job 117375710353 — **15/15 PASS**, проверены непосредственные Linux файлы на диске, SHA256, отметка выполненной операции, невозможность второго эффекта, forged signature, signed scope другого worker/target/project/source, expired signed permit, expired PG lease, HOST UNKNOWN, HOST disconnect, altered bytes, symlink-цель, существующий файл и crash AFTER fsync BEFORE receipt. Последний оставляет запись UNKNOWN и один существующий файл; повтор отклонён. Журнальные маркеры `NF_SIGNED_FENCED_FIXTURE=ONE_PHYSICAL_FILE_ONCE`, `NF_LOST_RECEIPT=UNKNOWN_STOP_NO_SECOND_FILE`.

Первый [Actions №39025499816](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39025499816) **FAILED**: сценарий Host unavailable закрыл class-shared PG connection и испортил независимость следующих тестов; исправлено в тестовом setUp выделением отдельного PG connection для каждого теста, БЕЗ изменения исполняемого HOST recipient. Второй прогон 15/15 успешен. Указаны точные реальные доказательства; исходники на тестовом SHA совпадают с физическими blob при создании этого отчёта.

## Непреодолённые производственные требования

- Нет настоящего отдельно уполномоченного владельца проекта, ACL/подписанта и защищённой private-key custody вне доступа администратора рабочей БД, исполнителя, модели и ChatGPT.
- Предоставляемый открытый ключ и scope fixture НЕ имеют независимо закреплённого корня доверия; администратор nf_test может переписать право и журнал. Нет независимого от БД монотонного antirollback highwater.
- Нет реального authenticated HTTPS сервера и постоянной защищённой OS identity у конечного получателя; root/parent могут быть изменены тем же OS UID. Коммит PostgreSQL и fsync файлов не атомарны (поэтому UNKNOWN/manual reconciliation), signed permit alone не препятствует replay.
- Проверка срока арены сделана в момент DB транзакции до fsync, но не привязана к внешнему постоянно защищённому receiver fence в одной неснимаемой границе. Нет мультихостовой выдачи доверенного права и не испытаны два настоящих устройства.
- CORE интегрирован только через новый тестовый маршрут на своей ветке; legacy прямой production write не включался. Нет реального Qwen или публикации.
- Нет решения отдельного уполномоченного независимого ревизора/оператора о production release.

**REJECT LIVE.** PR остаётся DRAFT, никаких секретов/настроек пользовательской машины/моделей/платных API/merge/HANDOFF. Следующий этап: отдельно уполномоченный оператор доверенного сервера, OS отдельный подписант и корень доверия, независимый durable antirollback, аутентифицированный многоклиентский CAS и receiver-side fence/idempotency на реальной защищённой машине; затем отдельный REVIEW exact SHA и two-physical-host drill.
