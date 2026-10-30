# НЕЙРОЗАВОД — 30.10.2026: факт выполнения P0 и карта шестипунктового завершения

Репозиторий: `DSLitvinov1/my_first_repo`. Продолжение существующей интеграционной Windows ветки, не новый проект. Основа: DRAFT PR #71, SHA `14a0edb64c59b601fecb626fc76aed6f6823084f`. Рабочая ветка: `neurofactory-p0-host-trust-acl-fix-20261030`, новый DRAFT PR #72. Ни один PR не объединён; нет выпуска в production или пользовательской установки.

## Последняя реальная лабораторная база — не запускать повторно дорогую модель

- 27.10.2026: [GitHub Actions #40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090) SUCCESS — реальная локальная Qwen/Ollama -> подписанный CI-owner CORE -> защищённый restricted-SID Windows SCM HOST -> signed result -> durable SQLite audit + process restart. Тест на disposable GitHub Windows, а НЕ на настоящем ПК владельца. Не повторяем без нового дефекта.
- PR #71: [Windows installer #40567564660](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40567564660) SUCCESS; реальная пользовательская/машинная установка только review-only с запретом службы и промышленной записи. OWNER/REVIEW/HOST/WITNESS полноценные производственные ключи и независимое подтверждение отсутствуют.
- PR #67: исходники independently operated VPS witness, systemd + mTLS готовы лабораторно, но сервер на независимом VPS фактически не развёрнут и нет реальных operator/service/TLS signing keys.
- PR #69: [реальный Windows per-user local draft installer #40556641679](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40556641679) SUCCESS с резервным копированием/восстановлением и обновлением локальной SQLite базы в изолированной лаборатории. Самый безопасный доступный владельцу пилот — без SCM/автозапуска задач, но он не производственная система.

## Конкретный устранённый дефект P0

В `windows_setup/physical_host_production_preflight.ps1` реальная проверка доверенного каталога Windows раньше блокировала запись только избранным известным SID (Everyone, Users, LocalService, service SID), **но пропускала произвольный другой SID с WRITE, DELETE_CHILD или правом смены ACL**. А также не проверяла OWNER защищённых файлов/каталогов.

Исправление допускает права записи в OS-protected trust roots, machine runtime, source и их parent-dir **исключительно SYSTEM и BUILTIN\\Administrators**, отказывает произвольным NTFS SID/поддельному владельцу/inherited ACL и DELETE_CHILD. Допускает службе только чтение. Никаких секретов, подстановок фиктивных подписей или отключения fail-closed protection не внесено.

**Одна адресная Windows-проверка PASS:** [Actions #41078097428](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41078097428), точный код+тесты commit `28421542e79a8c563fa07a26f453d2c9dc3f3c88`. Подтверждены пять сценариев: легитимный system/admin WRITE+service READ, произвольный SID WRITE отказ, DELETE_CHILD отказ, ненадёжный OWNER отказ, наследуемая ACL отказ. Ключи и права на реальной пользовательской Windows не исследовались.

**Проверенная пересборка существующего Windows Inno Installer:** [Actions #41078230530](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41078230530), job `124140075556`, exact tested source SHA `f510143b48de98a493214ecbbbac8047e3c002e5`, SUCCESS. Содержит 15 pinned application components и 74 staged files. Фактическая compilation, temporary machine-wide install, each staged app/review-host SHA verification, refusal to register production SCM, PowerShell preflight fail-closed on hosted CI, uninstall PASS.

Полученный **неподписанный, не производственный** Inno EXE SHA256:
`4B6F1430205407F8AB82CD3A781D1770D4F5EE6137858F327725CB016F0E6F2F`.
GitHub Action artifact `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, ID `12988172672`, ссылка на [Actions #41078230530](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41078230530), срок хранения по GitHub `2026-11-06T15:11:26Z`. SHA256 zip архива `ff8dd3c3359af397bc323b31bf95fef1b3b597b2d4139b922fc6604100b51073`. Не выдавать EXE за подписанный Authenticode, не запускать его с административными правами на пользовательском ПК без отдельного разрешения владельца/ревизора.

## Список 1–6 — только фактически подтверждённые состояния

1. **CORE–Qwen–HOST + инсталлятор:** одноразовая полная hosted Windows CI на настоящей Qwen выполнена; встроенный в установщик production receiver ещё не подтверждён и ACTIVE SCM не зарегистрирован. Реальный install candidate — REVIEW ONLY.
2. **Полномочия и ключи:** криптография/OS ACL и signed-scope preflight протестированы, P0 ACL дефект исправлен; real owner/signer/reviewer public ROOTS, private key custody, service identity/operator rights на ПК владельца не получены и не подтверждены.
3. **Независимый antirollback witness:** программный VPS/mTLS кандидат готов, реального независимого сервера/устойчивого реального highwater не проверено. Не переиспользовать unrelated VPS сервиса клиента без разрешения.
4. **Restart/updates/restore:** Windows SCM process restart+SQLite backup/restore на hosted CI частично проверены; полноценный реальный physical Windows cold reboot, обновление подписанного пакета и отказное восстановление на ПК владельца не испытаны.
5. **Независимый REVIEW:** не существует подписанного утверждения финального EXE и всех exact source SHA от отдельно назначенного человека; авторские тесты/комментарии не APPROVE.
6. **Installation на PC владельца:** удалённо доступен один `WIN-LIDC05TBOQD`, Desktop Commander оставшаяся квота `0%`, реальная installation не выполнялась. Ни попыток обхода квоты, ни изменения пользовательской Windows.

## Кратчайший безопасный путь к результату

- Не разрабатывать очередную Qwen/SCM демоверсию; устранён один найденный HOST blocker, запакован свежий проверенный review EXE.
- Требуются операторски назначенный независимый REVIEW и реальные provider certificates/public root pins; оператор и владелец не должны отправлять секреты или private keys в GitHub/чат.
- Для автономного защищённого режима нужен отдельный owner-authorized VPS/physically independent highwater. Указывать текущий hostname/администратора и не трогать другие проекты.
- Для безопасного локального начального использования можно отдельно санкционировать per-user local draft installer (без active HOST и автоматического выполнения). Для production машины обязательны подписанный выпуск, реальный действующий HOST service, внешняя проверка на физическом оборудовании и независимый approval.
- Не мержить draft PRs, не включать real CORE task effects, HANDOFF, модели за деньги или SKILLS. Все флаги выпуска остаются FALSE.

Конечное доказательство этого этапа — два GitHub-hosted run плюс сохранённый Git SHA и artifact ID. Никаких фоновых обещаний автоматической последующей установки.
