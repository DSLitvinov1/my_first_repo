# CORE — совместимый клиент для HOST четырёхподписанного учебного исполнения

Дата: 18.10.2026. Направление CORE, Issue #9. Оригинальная ветка CORE `neurofactory-core-queue-owned-20261013` и исходный SHA `beb08eff32923d8ca364aabfde0458f380acf8e7` не изменялись. Рабочая ветка этого кандидата: `neurofactory-core-four-party-sandbox-adapter-20261018`.

## Проверенный результат

CORE-owned адаптер `four_party_sandbox_client.py` реализует одноразовую передачу предложения к отдельному защищаемому HOST test handler. Он:
- сверяет `task_id`, `worker_id`, token hash, состояние CLAIMED и `lease_until` с собственным существующим CORE `_row` через его read connection;
- сверяет исходный SHA40, digest исходного файла, проект и target c реальной существующей схемой `OneTaskCore task.v1`;
- ограничивает proposal до OFFLINE_TEST, сверяет digest полезного содержимого, размер до 64КиБ и значения подписанного `expected_effect`;
- проверяет полный набор envelope ролей owner/operator/host/witness и их одинаковую привязку к scope, но НЕ делает ложного утверждения о криптографическом удостоверении без независимого HOST;
- не пишет локальный файл, не открывает внешний порт, не запускает задачи и модели; передаёт bytes только во внешний тестовый callback, при неопределённом ответе возвращает UNKNOWN и запрещает повтор у того же объекта;
- требует два точных флага тестирования, иначе отказывает. Любой положительный тестовый ответ возвращает `live_execution_allowed=false`, `automatic_retry_allowed=false` и `independent_review_approved=false`.

Точные исходники: `bridge/neurofactory/development/core_owned/four_party_sandbox_client.py`, blob `5fea9af13ea8bd45463f06d9cbfc832218450728`; тесты `test_four_party_sandbox_client.py`.

Доказательство: [GitHub Actions #39109729320](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39109729320), job 117623071842, точный checked out HEAD `441e6c9790ba9c3a776904ac530915871a598ad1` — **12/12 PASS**. Содержат текущую локальную аренду и token, подмены, forged envelope, истёкшее состояние, ложное квитирование, callback timeout/replay и несовпадение содержимого.

## Межветочный сквозной запуск

В отдельно принадлежащем HOST кандидате `neurofactory-host-core-e2e-sandbox-20261018` загружен ТОЛЬКО данный отдельный исходный CORE blob из pinned `441e6c9790ba9c3a776904ac530915871a598ad1` с обязательным сравнением фактического Git object hash на другом checkout. Никакие исходники CORE не изменены из HOST.

[GitHub Actions #39109952023](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39109952023), job 117623731422, точный HOST тестовый SHA `fa073719a08f581a283bdc05b39d4bf552dffa0a`: **35/35 PASS = 8 новых сквозных + 27 импортированных чужих unit/crypto/PostgreSQL проверок**. Тест на одном disposable GitHub Ubuntu runner и PostgreSQL16, с подлинными временными Ed25519 test keys и реальным временным файловым эффектом HOST; локальная CORE `_row` сымитирована структурой `OneTaskCore task.v1`, это ещё НЕ полный запуск реальной CORE SQLite очереди.

## Неодобренные и отсутствующие условия

Отдельный физический доверенный witness с независимо защищённым стойким монотонным состоянием, подтверждённые аппаратные ключи владельца и оператора, защищённый OS receiver, live TLS/Named Pipe интеграция, фактическое восстановление ОС, два физически разных компьютера, настоящая CORE SQLite claim→HOST цепочка, уполномоченное независимое REVIEW отсутствуют.

Поэтому исходники остаются только DRAFT, несовместимы с производственным использованием, для безопасного полного маршрута нужен отдельный операторский ввод и LIVE аппаратная/сервисная приёмка. Никаких merges, HANDOFF, производственной очереди, файлов пользователя и платных API.

## Дополнение: закреплён настоящий OneTaskCore SQLite/Git E2E

Предыдущая пометка «в E2E только имитация CORE _row» относится к раннему прогону. Теперь отдельный HOST runner закрепляет именно настоящий `OneTaskCore` source blob `ab1471813c6da29407c913b974a2209467a4b961` вместе с адаптером `5fea9af13ea8bd45463f06d9cbfc832218450728` из **неизменного** CORE исходного commit `441e6c9790ba9c3a776904ac530915871a598ad1`. В /tmp Git+SQLite создано и захвачено настоящее учебное задание через методы `enqueue`, `claim`, `snapshot`; оно доведено до реального тестового HOST файла, завершающей PostgreSQL квитанции и отдельно проверено на истекание локальной аренды.

Новая подтверждённая проверка: [Actions 39110461958](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39110461958), exact host tested SHA `254eee5445ccb05cb40704714a25edf5d2c81a34`, **37/37 PASS (10 новых сквозных, 27 импортированных регрессий)**. CLI log `CORE_ADAPTER_AND_ONETASKCORE_EXACT_SOURCE_PINS_VERIFIED=PASS`.

Это НЕ продакшен: approval callback только fixture, witness double в том же runner, нет внешнего аппаратного highwater, полномочий ключей, раздельных физических ПК, настоящего OS reboot, независимого подписанного REVIEW. Старые сквозные 35/35 тоже сохраняются, не смешивать их со свежим 37/37.
