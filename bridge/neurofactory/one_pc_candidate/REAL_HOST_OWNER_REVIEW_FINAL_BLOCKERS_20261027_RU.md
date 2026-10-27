# НЕЙРОЗАВОД — HOST, полномочия и независимая приёмка
Дата: 27 октября 2026 года.

## Главная граница

Цель пользователя: доделать постоянный HOST, реальные полномочия, получить независимую приёмку. Этой целью НЕЛЬЗЯ честно считать достигнутой, пока нет доступа к реальной Windows владельца, настоящих раздельных ключей, подписи издателя и независимого человека-ревизора с реальным заверенным решением. **НИКАКОГО независимого APPROVED в этом выпуске нет.**

Проверенные до нового этапа работающие составляющие:
- Одна настоящая цепочка **genuine Qwen → CORE → отдельный Windows restricted LocalService SCM HOST → подписанный receipt → SQLite checkpoint + локальный hash-chain audit → автоматический restart без повторного эффекта** в единой hosted Windows GitHub Actions: [run 40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090), точный source SHA `e1e09cda0d6ec82870a1a437dcd25ecf1363371b`. Модель загружалась только во временный тестовый раннер, эффект один безопасный fixture-файл, подпись производилась временными тестовыми ключами. Не на физическом компьютере владельца.
- Полный per-user Windows локальный установщик с UI, SQLite, pinned 15 CORE/HOST/PROVIDERS/COORDINATOR исходниками и независимо сверенным хэшем всех установленных файлов, тесты с отказом подменённого JS и unpinned sidecar, backup/restore и uninstall PASS: [run 40556641679](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40556641679), точный tested SHA `d177cd28dbbb0089079fd33082aa791b733fa165`. Эта программа **не включает** активный HOST и не выдаёт ключевых полномочий.
- Внешний независимый witness client/server и monotonic SQLite реальный TLS1.3 в одном disposable GitHub Linux CI PASS [run 40551539129](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40551539129). Физический VPS не развёрнут; эту часть без отдельного сервера нельзя заявлять как независимое antirollback-доказательство.

## Новый результат текущего этапа: физический доверенный HOST аудит

Добавлена чисто читающая `windows_setup/physical_host_production_preflight.ps1`, включена в общий Windows-обзорный пакет. Эта программа НЕ имеет режима enroll/install/start/approve, не выдаёт LIVE HOST authority, не копирует/генерирует никаких приватных ключей. В качестве аргументов принимает отдельно полученные доверенные SHA256 настоящего HOST-кода и Python runtime, **три разные** доверенные SHA256 реальных Ed25519 публичных ключей (owner, reviewer, witness) и доверенный thumbprint Authenticode издателя runtime.

На РЕАЛЬНОМ Windows проверяет доступные ОС-свидетельства: запущенную автоматическую SCM-службу `NeurofactoryCoreHost` под `NT AUTHORITY\LocalService`; действующий restricted service SID и фактическую учётную запись PID через CIM; фиксированный беззаглушечный путь к защищённому исполняемому Python и предполагаемому HOST; полные SHA256; Valid Windows Authenticode и внешний publisher thumbprint; раздельные закреплённые файлы owner/reviewer/witness public root внутри `C:\ProgramData\NeurofactoryProtectedHost\trust`; отсутствие широких и доступных службе прав записи на код, конфигурацию и публичные ключи; отсутствие изменяемых junction/reparse на директориях доверия. Если всего этого нет — **ошибка и отказ**, никакого автоматического исправления или ослабления прав.

Даже если эти признаки будут подтверждены на реальном ПК, результат **намеренно** `LOCAL_SERVICE_AND_PUBLIC_PINS_OBSERVED_NO_PRODUCTION_AUTHORITY`: полномочия конкретного задания подписывает сам владелец, независимость private-key custody, live witness, настоящее человеческое решение reviewer и remote nonrollback floor не доказаны этим скриптом. Отсутствующие внешние условия не могут быть заменены CI PASS.

### Проверенные результаты

**PASS [GitHub Actions run #40563421554](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40563421554)**, exact tested source SHA `543f630ccb74987facddde8ac6fa60bde9465eb0`.

На Windows-2025 GitHub-hosted реально собран unsigned Inno с 73 файлами application stage, 6 отдельными read-only HOST review файлами, установлен в Windows, сверена целостность всего manifest, read-only физический HOST аудит отказал облачной тестовой машине в праве выдавать реальные физические разрешения, сервис не зарегистрирован, продукт удалён. Новая диагностика исправляет расстановку функций PowerShell и дополнительно проверяет ACL на отсутствие права записи у общего LocalService и самого HOST SID.

SHA256 машинного обзорного EXE: `6c41dea9e96f9b764e126d1b20d35a208c00e93e53242f68a5a5179ec59d97d8`. Артефакт: `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, хранится до 03.11.2026 (срок GitHub). **Unsigned, no production HOST auto-installer**.

## Что НЕЛЬЗЯ считать завершённым — точные 5 блокировок

1. **Физический Windows Owner-PC не подключён.** В доступном Remote Desktop Commander исчерпаны обращения (`remote_calls_left_pct=0`); GitHub API для self-hosted runner status через текущие доступные инструменты недоступен. На PC владельца ничего не устанавливалось.
2. **Нет законченного production HOST runtime**: существующий реально работавший Windows LocalService защищённый listener — ИЗОЛИРОВАННЫЙ CI fixture со статически ограниченным тестовым файлом и тестовыми ключами. Обзорный install включает только его источники и dormant service, а настоящее `C:\ProgramData\NeurofactoryProtectedHost\host\protected_scm_host.py` ещё не утверждено, не зарегистрировано и не стартовало в защищённой Windows.
3. **Реальные ключи и owner rights не выданы.** Нужна интерактивная отдельная owner enrollment с полномочиями на ПК владельца и отдельно управляемые private HOST/reviewer/witness keys; нельзя генерировать/присваивать ключи от имени постороннего человека в GitHub CI. Reviewer, owner и witness должны действительно принадлежать разным субъектам и иметь отдельные требования ОС.
4. **Нет настоящего publisher-signed Authenticode окончательного Windows EXE.** Эпhemeral CI signing не заменяет реальное удостоверенное издательское подписание или owner-approved installer. Не загружать неподписанное review EXE как производственное.
5. **Независимая приёмка Issue #11 не произошла.** Результат GitHub Issues: Issue открыт; все 130 комментариев написаны одним `DSLitvinov1`, нет ни одного независимого ревизора или отдельно подписанного человека-решения. Не создавать GitHub self-approval от владельца, не назначать вымышленного ревизора; ревизору нужно независимо проверить exact SHA source, построенный бинарник, путь signer, Windows ACL, настоящий Qwen/CORE/HOST physical reboot, recovery no replay, physical remote antirollback.

## Рекомендация ревизору и владельцу

- Использовать текущий PR лишь как **DRAFT evidence**, не объединять его в main. Для независимого человека доступен [Issue #11](https://github.com/DSLitvinov1/my_first_repo/issues/11), для технической базы [run 40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090) + [run 40556641679](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40556641679) + [run 40563421554](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40563421554).
- На реальном Windows ограниченная read-only проверка может быть запущена после provisioned keys/системной службы — она **не** устанавливает и не активирует HOST. Для отдельной собственной цифровой подписи используются утверждённые издателем и владельцем ключи (НЕ тестовые).
- Не переводить production flags, SCM или очередь в active mode до положительного человеческого независимого verdict, действительных физических ОС-доказательств и полноценного remote witness antirollback. Для предварительного LOCAL DRAFT UI допускается независимый ограниченный unsigned review-only запуск в изолированной Windows без ключей/эффектов по явному выбору владельца.

**Результат этапа: ГОТОВ ФАКТИЧЕСКИ НОВЫЙ ПРОВЕРЯЕМЫЙ read-only HOST trust-boundary и Windows установочная сборка; production HOST/real keys/independent human verdict = BLOCKED / NOT DONE.**
