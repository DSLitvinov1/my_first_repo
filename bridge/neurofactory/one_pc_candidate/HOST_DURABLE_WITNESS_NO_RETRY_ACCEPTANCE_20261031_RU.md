# НЕЙРОЗАВОД — журнал HOST перед внешним свидетелем, 31.10.2026

Основа: [PR №73](https://github.com/DSLitvinov1/my_first_repo/pull/73), SHA `2832c2237b9b13c649e238428da6f5f3766f94f7`. Продолжается существующая интеграция без объединения веток.

## Реализовано

Устранён дефект: старый мост HOST помнил отправленную заявку только в памяти `self._spent` и после аварийного завершения новый экземпляр мог ещё раз обратиться к свидетелю.

Добавлен `protected_host_attempt_ledger.py`: до первого сетевого TLS-запроса в заранее подготовленной оператором папке сохраняется SQLite запись `UNKNOWN_NO_AUTO_RETRY`. Полная синхронизация SQLite `synchronous=FULL`, `BEGIN IMMEDIATE/COMMIT`, уникальность task/operation/nonce/source+epoch, SHA256 exact scope. Повтор после нового процесса, повреждение журнала, неопределённость транзакции и отсутствие защищённого каталога — отказ. Ключи и данные Qwen не сохраняются.

`protected_host_remote_bridge.py` теперь требует отдельный операторский каталог журнала. Он по-прежнему проверяет OWNER/REVIEWER Ed25519 и точный scope до сети, после чего делает максимум одну попытку подписанного mTLS резервирования. **Никаких производственных файловых эффектов не разрешает.** Код не подтверждает ACL/Service SID каталога, настоящие private key custody и защиту внешнего сервера от отката всей ОС.

## Фактические проверки

- [Windows Actions №41198454122](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41198454122): SHA `03d6a6da2b546beb3f93fc00ffb7708d8fe88886`, **29/29 PASS**; 15 тестов моста (5 новых на SQLite и повтор после нового экземпляра), 14 прежних криптографических. РЕАЛЬНОГО reboot ОС не было. Предыдущий красный run №41198363185 — проблема не закрытых тестовых SQLite соединений, исправлена.
- [Windows installer Actions №41198573783](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41198573783): точный код SHA `04ade652d602db34234fe3232e020aebd0365b9a`, **SUCCESS**. 15 закреплённых компонентов, 76 файлов, Inno compile/install/hash verification/uninstall, без запуска производственной SCM.
- Неподписанный review-only EXE SHA256 `FE075A04F10122DB9A40A9BE711849627DDCF68D1BC18DEAE6531920DCF81314`. GitHub artifact ID `13041009366` из этого run, срок до 07.11.2026. **Не производственный релиз.**

## Блокеры

Нет фактически развёрнутого независимого сервера witness и настоящих operator-provisioned keys, не завершена постоянно защищённая production SCM с настоящей CORE lease и operator-protected ACL, нет Authenticode publisher-signature, OS cold reboot/restore на пользовательском ПК, подписанного вердикта отдельного независимого REVIEW. Desktop Commander видит один Windows `WIN-LIDC05TBOQD`, но квота команд 0%; ПК не изменялся.

**DRAFT / NO MERGE / PRODUCTION QUEUE OFF / HANDOFF PAUSED / NO LIVE EFFECTS**.
