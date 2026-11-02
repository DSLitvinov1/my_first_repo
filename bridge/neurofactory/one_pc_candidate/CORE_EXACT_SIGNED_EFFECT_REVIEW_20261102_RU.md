# НЕЙРОЗАВОД — 02.11.2026. Повторная проверка: точная подписанная операция CORE → HOST

**Режим:** DRAFT / READ-ONLY preflight / без производственных эффектов и без независимого одобрения.

## Исправленный недостаток NF-REVIEW-AI №2

Исходный audit verdict: [Issue #11, comment 6584560287](https://github.com/DSLitvinov1/my_first_repo/issues/11#issuecomment-6584560287), [PR #78](https://github.com/DSLitvinov1/my_first_repo/pull/78) исходный HEAD `8994d27212d5c08231977f2f23334de8a8e3a4a3`.

В предыдущей интеграции `protected_host_core_witness_binding.py` уже сравнивал `task_id`, `project_id`, `source_sha40` и состояние аренды `CLAIMED`, но эти три идентификатора не охватывают `target`, `objective`, `model`, `source_sha256`, `approval_commit`, `reserved_units`. Подписанный `operation_sha256` можно было оставить прежним при другом содержимом CORE spec. Это позволяло локальному предварительному этапу принять несовпадающий scope; **разрешение производственного исполнения и тогда не выдавалось**.

## Реальное изменение в отдельной ветке

Рабочая ветка `neurofactory-p0-exact-core-signed-effect-20261102`, только поверх PR #78, без слияния с main.

1. Существующий `core_readonly_observer.py` после проверки `spec_sha256 == SHA256(canonical JSON UTF-8 полного spec)` теперь возвращает `core_spec_sha256` в ограниченной проекции CORE. Не выдаёт сырой spec, токен worker, receipt, private keys.
2. В `protected_host_core_witness_binding.py` добавлен детерминированный разделённый доменом digest `SHA256("NF_CORE_FULL_SPEC_AND_PAYLOAD_OPERATION_V1\\0" || bytes.fromhex(core_spec_sha256) || bytes.fromhex(payload_sha256))`. Он является **обязательным значением подписанного OWNER/REVIEWER `claim.operation_sha256`** и таким же значением в отдельно закреплённом `operator_expected.operation_sha256` и remote witness claim.
3. Любое отличие полного CORE spec или `claim.payload_sha256` от signed operation теперь отклоняется **до вызова remote witness и до записи локального резервирования**. Сохранились старые проверки task_id/project_id/source_sha40, отсутствие результата, действующая lease, правильное время ОС (PR #78), повторная проверка CORE после remote ACK, сохранение `NO_RETRY`.
4. Существующий `protected_host_task_authority` уже проверяет реальные отдельные Ed25519 роли OWNER/REVIEWER, отдельно операторский pinned operation/payload SHA, а подписанный ответ witness привязан к operation. В этой ветке алгоритм подписей не менялся, чтобы не расширять поверхность риска.
5. Не вводились новые пути исполнения: лишь предварительная проверка, все полномочия на запись, открытие очереди, слияние PR и производственный выпуск — `false`. Локальная SQLite без защищённого OS token и независимого remote highwater **не эквивалентна промышленному CORE lease fencing**.

## Адресные доказательства

- Точный исходный коммит исправления и негативных тестов `6c03fe7049728c9166353dd3e77eed996c47caf8`. На облачной Ubuntu `litd12123.clodocd.com` в отдельном изолированном каталоге выполнилось **34/34 PASS**, продолжительность около 2 секунд. Это действительная временная `OneTaskCore` SQLite, настоящие ephemeral Ed25519 ключи, но mock-сетевой ответ witness — не реально развёрнутый VPS.
- [Windows GitHub Actions run #41500753305](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41500753305), код+workflow exact SHA `c759814b54426618cb506abe6116d5b0878d17ac`, завершён **SUCCESS**, **34/34 PASS**, ~8.656 секунд на временной Windows. Отдельная Windows venv, без компиляции полного установщика и без обращения к Windows-компьютеру владельца.
- Ключевые новые отрицательные случаи:
  - другой `target` и `objective` с тем же task/project/source/старой подписью ⇒ отказ до сети;
  - после claim локальный SQLite `spec` и его **контрольная сумма** обе изменены на другую корректную пару (objective/model/source_sha256/approval_commit) ⇒ отказ до сети, даже когда сам CORE observer видит консистентную базу;
  - другой подписанный `payload_sha256` при прежнем `operation_sha256` ⇒ отказ до сети;
  - неверный/неформатный operation hash ⇒ отказ;
  - прежний законный claim с вычисленным FULL spec + payload hash ⇒ криптографический verify-only PASS, все производственные полномочия `false`.
- Регрессия исходной проверки `source_sha40` обнаружена при первом полном адресном прогоне и **исправлена** в исходном SHA выше. До успешного полного прогона было 1 ожидаемое отклонение теста; окончательный 34/34 PASS на точном исправленном коде.

## Не являются доказанной промышленной приёмкой

1. ОС-время, nonce и CORE lease в этом коде не заверены отдельным физическим доверенным устройством; race между локальным чтением и внешним ACK не даёт разрешения реального эффекта.
2. Никто не проверял реальную выдачу файла на рабочем защищённом Windows SCM с отдельным SID/DACL, выключением питания, rollback и permanent highwater. Пользовательская Windows не изменялась.
3. Производственный независимый Linux witness с конфигурацией, mTLS и root-owned ключами до сих пор не подтверждён; сетевой вызов в новых тестах моделируется.
4. Нет подписанного Authenticode конечного установщика и отдельного подлинного уполномоченного независимого reviewer verdict на точные source+binary hash.

**Итог:** исправление конкретной проблемы binding подтверждено адресными Linux и Windows испытаниями. Готово к внешнему кодаудиту exact SHA; **independent APPROVE / production ready — НЕТ**. Все PR DRAFT/UNMERGED, queue/HANDOFF OFF, ключи и чужие проекты не затронуты.
