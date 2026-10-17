# TRUSTED HOST: криптографически связанное разрешение на действие — узкий кандидат
Дата: 2026-10-17. Источник: ветка TRUSTED HOST / Issue #14 / DRAFT PR #15. Состояние: **CRYPTO VERIFIER TESTED, NO EXECUTION AUTHORITY, NO PROD**.

## Новый исполняемый модуль
`bridge/neurofactory/trusted_host/signed_effect_permit.py` (проверяемый Git blob `2f6cb04295536edd7d834f39d364af4786b22d23`) проверяет Ed25519 над строго канонизированным подписанным объектом, все обязательные поля, exact внешне заданные ожидания, UTC UNIX время начала/истечения и максимальное 300-секундное окно. Контракт включает issuer и key ID, owner, репозиторий, project/task/worker, исходный Git SHA40, хеш исходного файла/снимка задачи/политики/предлагаемого результата, target, lease_epoch, hash fencing token, idempotency key и operation_id.

Отсутствие или несоответствие любого поля, чужой публичный ключ, изменённый подписанный payload, поздняя/будущая квитанция, двойной bool/число, Windows device alias, относительный обход пути — запрещены. Успех возвращает **только** `CRYPTO_SCOPE_MATCHES_NO_EXECUTION_AUTHORITY`, и все флаги владельца/внешнего доверенного корня/актуальности аренды/idempotency/исполнения/публикации/автоповтора остаются FALSE.

**Ни private key, ни настоящие operator certificates в GitHub не добавлялись.** В тестах используется только ephemeral Ed25519PrivateKey, создаваемый во время каждого unittest в изолированном Github-hosted runner. Даже подлинная подпись от временного ключа не является разрешением владельца. Если атакующий контролирует и ключ, и ожидаемые поля, форматная и криптографическая проверка может пройти, но реального допуска к записи по прежнему нет.

## Реально проведённые тесты

GitHub-hosted Ubuntu24.04 Actions [run #38985744277](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38985744277), job `117256680734`, exact tested commit `2f5197b408b43d4aad375df3f190c54a47c8c1b7`: `Ran 17 tests`, `OK`, зелёный job. Пин исходного модуля `2f6cb04295536edd7d834f39d364af4786b22d23`; тест `test_signed_effect_permit.py` Git blob `29e54efef422255211481d907805506229b54d1f`. Проверены неверная подпись, чужой ключ, изменение любого scope, неверный владелец/repository/project/source/target/epoch/op/idempotency, expiry, поддельные 'execution_allowed' поля, traversal/Windows device, bool as epoch, окно срока, повреждённое Base64. Все положительные криптографические квитанции **НЕ** разрешают real file effects.

## Что пока отсутствует и должно быть реализовано только уполномоченными владельцами

1. Отдельный защищённый signer/issuer OS principal с private key вне CORE, PostgreSQL DB owner, модели, Actions и ChatGPT. Публичный ключ и owner/source/policy expectation должны быть независимым защищённым provisioned-root, нельзя брать их из того же API сообщения.
2. Аутентифицированный HTTPS API защищённого HOST, реальная проверка подлинного владельца и его проекта, запрет самостоятельной подмены разрешений и независимое от администратора БД монотонное хранилище head/sequence.
3. Актуальная центральная аренда и защита idempotency/replay именно у конечного OS-protected получателя эффекта в момент файла/коммита; этот модуль не делает запросов HOST, не защищает время, не фиксирует потреблённый operation_id и не пишет файлы.
4. CORE должен импортировать контракт только после создания доверенного защищённого receiver, пока legacy `apply_offline_test` остаётся отключён. Использовать этот read-only результат как разрешение на `apply_fixture_offline_test` или реальную запись строго запрещено.
5. Независимый REVIEW на exact SHA новой реализации и потом отдельный подписанный допуск производственного развёртывания, физические 2 авторизованных компьютера, crash-recovery и UNKNOWN STOP. GitHub Actions на одном runner — не эти доказательства.

Релиз остаётся **BLOCKED**. HANDOFF PAUSED. Никаких реальных ключей, runtime services, real model, user files, merge или платных API.
