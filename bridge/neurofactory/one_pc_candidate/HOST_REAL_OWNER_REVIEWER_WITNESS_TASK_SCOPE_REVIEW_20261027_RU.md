# НЕЙРОЗАВОД — HOST: подлинные проверяемые подписи для одной операции и передача независимому ревизору

Контрольная дата 27.10.2026. Новая ветка `neurofactory-host-real-owner-task-permits-20261027` на базе DRAFT PR #70. **Отсутствует независимое APPROVE**, пока не совершена физическая проверка Windows и реальные подписи владельца/ревизора/свидетеля. Слово «реальные» ниже относится к работе криптографического алгоритма Ed25519, а не к наличию привилегий владельца в тестовой среде.

## Что реализовано

- Модуль `protected_host_task_authority.py`: авторизация строго **одной** заданной узкой безопасной операции через проверку независимо закреплённых публичных Ed25519 ключей владельца и ревизора, подписи на одном и том же точном теле задачи, отдельного подписанного подтверждения highwater-свидетеля. Ограничены schema, репозиторий, имя операции, task/project, hash source SHA40, digest пакета и payload, идентичность машины, digest доказательств review, **точные разные Windows worker/service SID**, nonce, reserved monotonic epoch и срок жизни максимум 300 секунд. Запрещены произвольные shell команды, чужой payload и неподписанные переходы.
- Вход `operator_expected` должен приходить из отдельного защищённого OS-администратором контура, а минимум внешнего epoch — из независимого живого highwater, НЕ из JSON ответа, модели, репозитория или локального откатываемого SQLite.
- Возвращаемый статус **всегда** `SIGNED_OWNER_REVIEWER_REMOTE_RESERVATION_MATCH_NO_EFFECT` с `production_task_effect_allowed=false`. Он **не позволяет** ни запустить произвольный HOST effect, ни запустить Windows службу, ни выписать себе APPROVED: не хватает независимого реального согласия/хранения приватных ключей, live remote witness и физического OS token/SID/lease attestation.
- Новый путь пакета Windows Review Inno включает этот модуль как ещё один исходник в каталоге `review-host`; программа не вызывает его автоматически, не регистрирует службу и не скачивает Qwen.

## Фактически PASS на точных исполняемых коммитах

1. [Actions #40567388031](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40567388031), source SHA `c27ac6d7bd8739a8f3d12ecf346635666c649b22`. 14 целевых unittest Linux, верификация настоящих подписей трёх *временных изолированных* разных Ed25519 signer и отдельной подписи внешней квитанции; специально поддельные owner/reviewer/witness подписи, искажение задачи, worker SID, service SID, machine, task, nonce, epoch, scope, expiry и shell-команда отвергнуты.
2. [Actions #40567564660](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40567564660), source SHA `5201818a7e48257f0523f49d6c2f7be7a3075f37`. Полноценный Windows hosted unsigned-review machine-wide Inno EXE действительно собран/установлен, digest новых модулей проверен по manifest, проверено отсутствие регистрации и эффектов HOST, uninstall PASS. SHA256 **НЕПОДПИСАННОГО** EXE `d38ff6ab87ec7c381ff6a318aad6603ab61465e29021874780056dc96db96d9a`.
3. [Actions #40567890914](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40567890914), source SHA `7ba1146ea40174dc9258ec27e84c4bc3c2bee49c`. Те же 14 реальных Ed25519 tests на Windows-2025 hosted PASS, отдельная `physical_host_production_preflight.ps1` отвергает попытку выдать GitHub CI раннер за физическую Windows пользователя; нет самовольной регистрации `NeurofactoryCoreHost`.

## Независимому ревизору — конкретные негативные воспроизведения

(1) Подписать чужим owner ключом без замены PIN — REFUSE; (2) заменить reviewer подпись — REFUSE; (3) заменить witness signer или пришить квитанцию от другой operation / SID / machine / package — REFUSE; (4) подделать public keys из входящего запроса — REFUSE на доверенной границе; (5) ослабить scope до shell — REFUSE; (6) просрочить claim/epoch — REFUSE; (7) смоделировать потерю ответа с обязательным **UNKNOWN, не автоповтором**; (8) доказать, что Windows HOST действительно существует под **restricted per-service SID**, но не имеет права записи в trust/source install; (9) реальный физический reboot, смена SID/ACL, откат Windows snapshot; (10) проверить отсутствие возможности отозванному owner/reviewer signer подписать новое задание; (11) предъявить Authenticode реального release-пакета и независимое подтверждение custody keys/hardware/highwater.

## Что не готово и кому принадлежит

- На данном этапе это проверенный криптографический **примитив авторизации**, не подключённый ещё к production Windows receiver/effect и реальным доверенным OS secret-store и команде CORE. Пакет `Neurofactory-Machine-Review-UNSIGNED.exe` только для ревизора, сам не устанавливает активную исполняющую HOST-службу.
- Нет независимо закреплённых публичных ROOT-ключей и реальных приватных owner/reviewer/host/witness signing keys на компьютере владельца, нет удалённого физически независимого witness, нет подтверждения доступа к Windows пользователя через резервный Runner, нет настоящего publisher Authenticode, нет подписанного human review issue #11.
- Не разрешать merge, production service auto-start с заданиями, SKILLS или скачивание модели на ПК без отдельного согласия и фактического отрицательного/положительного OS-аудита.

**Текущий честный итог: HOST отдельный узкий per-task Ed25519 review/witness GATE и Windows review installer — PASS disposable CI; полноценно запущенный production HOST и независимая человеческая приёмка — НЕ ВЫПОЛНЕНЫ.**
