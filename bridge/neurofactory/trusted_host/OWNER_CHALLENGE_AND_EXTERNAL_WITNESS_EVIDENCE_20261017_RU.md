# №16 — независимая привязка GitHub-владельца к ключу и внебазовый контроль полного локального отката
Дата: 17 октября 2026. Область: `TRUSTED HOST` Issue №14 / DRAFT PR №15. **Всё ниже подготовлено и проверено исключительно в ephemeral GitHub-hosted Linux; это НЕ внедрение постоянного доверенного сервера.**

## Реальная проверка прав на GitHub

В текущей сессии через авторизованный GitHub API подтвердилось: подключённая учётная запись `DSLitvinov1`, numeric GitHub user ID `151650108`, имеет permission `admin` к `DSLitvinov1/my_first_repo` (репозиторий с numeric ID `723328237`) и к `DSLitvinov1/lesson3.1`. Это реальная проверка прав сеанса **на момент запроса**. НЕ является доказательством того, что пользователь уже контролирует какой-либо долговременный Ed25519-ключ, или что отдельный оператор подтвердил его право запускать production.

## Двухсторонняя процедура криптографической привязки владельца

Новый исходник `bridge/neurofactory/trusted_host/offline_github_owner_key_enrollment.py`, blob `e69e5c611cfce6b13c15f984ab79e0c8e5371f6f`. В отличие от самоподтверждённой JSON-анкеты, механизм одновременно требует:
1. Защищённо закреплённый **вне рабочей базы** operator-public key. Отдельный оператор должен непосредственно проверить официальным API точный GitHub stable user ID, stable repository ID, право администратора, срок, рабочий проект и границы разрешений и подписать snapshot своим закрытым ключом.
2. Владелец, под отдельным подтверждённым каналом, подписывает своим собственным ключом свежий challenge, который однозначно связан с fingerprint owner-key, nonce, stable GitHub IDs, fingerprint операторского snapshot, project scope и коротким TTL. Одного логина или скриншота для этого недостаточно.
3. Проверка отклоняет поддельный snapshot, замену operator key, замену owner key, другой numeric repository ID, истечение времени и признак использованного nonce.

Модуль **не может самостоятельно удостоверить реального оператора**; поле snapshot `source` — утверждение лишь тогда, когда snapshot действительно подписан предварительно удостоверенным независимым оператором. Выдаёт `pending_owner_enrollment` с `production_authorization=false`, `actual_independent_operator_enrolled=false` и `persistent_nonce_recorded=false`. Для настоящего использования оператор отдельно сохраняет nonce highwater и владелец keys/out-of-band pin в защищённый signer-only store; модель/CORE/DB не имеют доступа. **Настоящие личные закрытые ключи или токены в репозиторий не передавались.**

Точный GitHub-hosted Ubuntu эксперимент: [Actions №39068798565](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39068798565), job `117501908200`, exact tested HOST SHA `d69552bdc3e3b81889f4280378fc6ad9d92b6066`, **7/7 owner challenge-tests PASS**, все приватные ключи сугубо временные.

## Независимый по системным правам журнал одноразовых внешних эффектов

Исходник `bridge/neurofactory/trusted_host/offline_external_effect_witness.py`, blob `1dbdffcfa78a4b0c5ab8a196d7d8deadadc7d4ab`. У него отдельная системная учётная запись и private Ed25519 key, закрытый журнал с метками `task` и `target` fsync до подтверждения операции, исключающие повтор даже после удаления **всех** локальных checkpoint-файлов получателя и SQL effect receipt. Проверяет системного Linux peer UID, подписывает ACK, а CORE/HOST принимает только pinned public key witness из принадлежащей получателю закрытой настройки. Если ACK не получен после durable fsync, исход становится `UNKNOWN`: новый необратимый эффект запрещён; нельзя просто повторить сетевой запрос. У исполнителя/DB actor нет доступа к witness-only store.

[Тот же CI №39068798565](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39068798565), **7/7 новых внешних witness-тестов PASS**, плюс 7 выше = **14/14 PASS**. Проверены: повтор после имитации восстановления старой LOCAL state получателя и PostgreSQL, новый operation ID для того же пути, потеря ACK, поддельные OS UID, неправильный публичный ключ, попытка чтения хранилища пользователем DB, недоступность witness.

## Настоящая интеграция в конечный файловый получатель

Новая конфигурация защищённого HOST `neurofactory.os_separated_recipient.external_witness_fixture.v2` разрешает эффект только после ИХ ВСЕХ шагов: (1) защищённый подписант проверяет owner Ed25519 grant на точный проект/repo/source/task/worker/lease/operation и свой signer highwater; (2) конечный получатель `nf_effect` аутентифицируется у независимо заданного witness по Linux SO_PEERCRED и pinned Ed25519 public key; (3) witness фиксирует и fsync необратимый target/task высоководный маркер; (4) получатель затем фиксирует свой защищённый журнал `UNKNOWN`, сверяет PostgreSQL lease/fence и выполняет только одну sandbox O_EXCL/fsync файловую запись. Возврат старого локального DB+recipient checkpoint НЕ возвращает подтверждённый witness marker назад.

Исходники: `offline_os_separated_effect_receiver.py` blob `7ec17e812686e59dc18aee580b8d3289fab43b69`, `offline_operator_gated_receiver.py` blob `5128337a8b626f4822a6f7878e58762b8cf65fe6`. Они добавляют v2, оставляя предыдущий v1 **только** для исторических изолированных тестов: ни один из них не предоставляет live permission.

[GitHub Actions №39069156061](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39069156061), job `117502952085`, exact tested HOST SHA `3332b6f95368b1c288c476eb5792c4e397b3df50`, **3/3 НОВЫХ V2 сквозных испытания PASS**. Временно работают 4 независимых Linux UID: `nf_signer`, `nf_db_actor`, `nf_effect`, `nf_witness`, но ВСЕ НА ОДНОМ GitHub-hosted runner. Реальные контрольные сценарии: первый файл создаётся только при подтверждении witness; затем PostgreSQL DB effect receipt, локальные recipient ledger markers и сам временный файл стерты оператором теста, а удалённый **по отношению к этим ролям** witness store не затронут: новая доставка блокируется. Потеря ACK после регистрации у witness блокирует файл и все повторы; неправильный pinned witness pubkey блокирует файл, хотя witness уже зарегистрировал намерение. **Не было реальной перезагрузки машины, сетевого внешнего сервера, физически двух разных компьютеров или production KMS.**

## Непреодолённые условия перед LIVE

1. Фактически выполнить proof-of-possession **на реальном отдельно управляемом владельцем ключе**, с независимым оператором, который по официальному GitHub API подтверждает live access и защищённо закрепляет numeric ID/repository/scope + revoke/expiry. До этого даже правильная тестовая подпись не даёт production rights.
2. Разместить witness на **отдельной авторизованной физической машине** с независимым от HOST/root архивом/монотонным хранилищем. Нынешний witness в одном runner не выдержит rollback снапшота ВСЕГО этого компьютера, включая witness. Unix SO_PEERCRED не работает как аутентифицированный межмашинный транспорт; на реальных двух хостах нужен подтверждённый mTLS/device identity, независимый pin root и ACL.
3. Настоящий безопасный reboot/backup restore и power-cut должен проверять внешнюю witness-счётную запись и файловый highwater после обрыва питания и восстановления **обеих** авторизованных машин; при неопределённости — **DENY/ручная сверка**. Не удалять устойчивый marker простым restore DB. Отдельный оператор подтверждает точные коды и хеши.
4. Получить отдельное независимое подписанное заключение `REVIEW #11` на точных версиях и отдельное разрешение реального владельца на production. Готовый runbook двух машин: `bridge/neurofactory/coordination/TWO_PHYSICAL_NODES_ACCEPTANCE_RUNBOOK_20261017_RU.md`; операторский runbook `OWNER_REPO_SIGNER_RECOVERY_OPERATOR_RUNBOOK_20261017_RU.md`. Сейчас подключён лишь один Windows ПК, поэтому выполнять физическую процедуру НЕ разрешено и НЕ возможно с доказательством двух хостов.

**Статус: REJECT LIVE.** Нет настоящих ключей в Github, платных API, публикации, слияния веток, рабочей очереди или HANDOFF. Код даёт проверенный изолированный путь, но не самостоятельный производственный выпуск.
