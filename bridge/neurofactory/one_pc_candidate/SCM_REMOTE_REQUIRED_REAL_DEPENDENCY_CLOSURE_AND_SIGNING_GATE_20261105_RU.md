# НЕЙРОЗАВОД — закрытие зависимостей Windows-службы и ворота независимого релиза, 05.11.2026

Продолжение [DRAFT #97](https://github.com/DSLitvinov1/my_first_repo/pull/97) и [#96](https://github.com/DSLitvinov1/my_first_repo/pull/96). Рабочие проекты/очереди не включались; новых оплаченных операций, переданных приватных ключей, реального code-signing или производственной SCM установки не выполнялось.

## Новый исправленный дефект: неполная комплектация сервиса

В реальном disposable Windows SCM `windows_scm_sandbox_receiver.py` в обязательном `remote_required` режиме импортирует `scm_witness_service_policy`, затем `OneShotScmRecipientFence` и связанные crypto/TLS, защищённые SQLite и CORE-модули. Старый Windows CI installer `test_windows_scm_two_user_recovery.py` копировал в `receiver_bin` **только** `scm_recipient_core_claim_guard.py` и `core_readonly_observer.py`. Следовательно, тест `remote-required-missing` мог ложно проходить: SCM останавливается из-за отсутствующего Python-модуля, а не отсутствующего защищённого внешнего witness. Это опасный ложноположительный тест безопасности.

**Исправлено:** копируется полный набор из **10** зависимостей service receiver в отдельный protected runtime каталог, с проверкой файлов и **фактическим импортом** `scm_witness_service_policy`, `OneShotScmRecipientFence`, `OneShotHostWitnessBridge` из этой папки через отдельный Python subprocess ПЕРЕД тестом startup. Негативный SCM-тест без sealed witness и регрессия под restricted LocalService и отдельным worker SID затем действительно проходят через доступный работающий код. Исходный CORE/WORKER policy не менялся.

**Exact executable+CI commit SHA `20365d5f81b82271fe00f1bd16bfbe24149f436c`**, [GitHub Actions #42037075327 SUCCESS](https://github.com/DSLitvinov1/my_first_repo/actions/runs/42037075327):
- 8/8 Windows отрицательных тестов обязательной witness policy,
- 34/34 Windows signed owner/reviewer + real CORE SQLite и one-use durable fence policy,
- `NF_ACTUAL_SCM_EXTERNAL_WITNESS_FULL_IMPORT_CLOSURE=PASS_CI_ONLY`,
- `NF_REAL_WINDOWS_SCM_MISSING_SIGNED_REMOTE_POLICY=DENIED_NO_FILE`,
- `NF_REAL_WINDOWS_SCM_CANNOT_FALLBACK_TO_CORE_ONLY=PASS_CI_ONLY`,
- `NF_WINDOWS_PER_SERVICE_RESTRICTED_TOKEN_AND_ACL=PASS_TEST_ONLY`,
- `NF_WINDOWS_REAL_SCM_DIFFERENT_ACCOUNT_ONE_FILE=PASS_TEST_ONLY`,
- `NF_WINDOWS_DUPLICATE_REJECTED=PASS_TEST_ONLY`,
- `NF_WINDOWS_SCM_CRASH_RESTART_NO_REPLAY=PASS_TEST_ONLY`.

## Физический Windows-компьютер

`WIN-LIDC05TBOQD` (Desktop Commander доступен). В существующем **только обзорном** установленном пакете `C:\ChatGPTProjects\NeurofactoryReview-20261105-verified` (source SHA `30082140b8acfe3adb79f1a7f4f71714b20431eb`) присутствуют все 12 модулей настоящего SCM/witness пути, но стандартный Inno runtime Python embeddable **не включает pywin32**, поскольку обзорная поставка не устанавливает ОС-службу. Для точного разграничения в отдельное тестовое изолированное виртуальное окружение `C:\ChatGPTProjects\Neurofactory-PhysicalWitnessLab-20261105\venv` установлен `pywin32==311` (никаких global Python changes или live service). Проведён Python 3.14 real-Windows импорт всех **12/12** модулей `review-host` по точному установленному пути с проверкой происхождения: `NF_PHYSICAL_WINDOWS_ALL_SCM_SIGNED_WITNESS_RUNTIME_MODULES_IMPORT=PASS`; `NF_PRODUCTION_SCM_SERVICE_COUNT=0`. Эта операция **не подтверждает** запуск постоянной службы, сертификат издателя, live witness в её процессе или независимый выпуск.

Подтверждён сохранённый Linux journal `epoch=3`, `reservations=3`, `PRAGMA integrity_check=ok`, приватный файл `0600`. Лабораторный SSH tunnel отключён, временный port-forward ключ отозван, экспериментальный сервер не слушает публичных портов. [Реальный двухузловой отчёт](https://github.com/DSLitvinov1/my_first_repo/blob/neurofactory-p0-real-two-node-witness-clock-fix-20261105/bridge/neurofactory/one_pc_candidate/PHYSICAL_TWO_HOST_SIGNED_WITNESS_AND_RELEASE_GATES_20261105_RU.md) и [подписанный highwater checkpoint](https://github.com/DSLitvinov1/my_first_repo/blob/neurofactory-p0-real-two-node-witness-clock-fix-20261105/bridge/neurofactory/one_pc_candidate/PHYSICAL_TWO_HOST_LAB_LEDGER_CHECKPOINT_EPOCH3_20261105.json).

## Реальная цифровая подпись (НЕ выполнена)

Windows EXE обзорного установщика `5B30794C95799E8E7CCD2DBA3C7BE3880D21A8617A9AA486024FE48E240E4884` получил `Authenticode=NotSigned`. Ранее проверены хранилища Windows CurrentUser/My и LocalMachine/My: **0 доступных действительных сертификатов Code Signing с private key**. Самоподписанный сертификат нельзя выдавать за доверенный. Покупку/идентификацию/выдачу CA нельзя выполнить по одному доступу к ПК/репозиторию: проверка юридической личности и оплата у CA требуют реального заявителя. У Microsoft доступность Artifact Signing для частных лиц ограничена США/Канадой. Для физического лица вне этих территорий доступны CA-managed OV/Standard signing варианты, например официальный [Certum Standard Code Signing](https://www.certum.eu/en/code-signing-certificates/) (проверка личности и разрешённой юрисдикции — у CA). Официальные [требования Certum по документам](https://support.certum.eu/en/code-signing-required-documents/) включают удостоверение личности и подтверждение адреса для физлица. Не отправлять личные документы в репозиторий или в чат.

## Независимая приёмка (НЕ выполнена)

[GitHub Issue #11](https://github.com/DSLitvinov1/my_first_repo/issues/11) по-прежнему OPEN, положительной human review записи с доказанной независимостью и правами на точный candidate SHA нет. В PR #97 reviewer не назначен/отзывов нет. Автоматические тесты и собственная ревизия **не** являются положительным заключением независимого внешнего человека. Ревизор должен отдельной личностью проверить exact source and review bundle SHA, требование полноты SCM runtime, все подписи/ACL, прежние UNKNOWN операции, реальную Linux→Windows signed ACK из постоянно запущенной Windows SCM, допустимость sys-clock skew, сертификат издателя и два физических хоста. Затем выдать подписанный APPROVE/REJECT/INCONCLUSIVE и воспроизводимый независимый лог.

## Незакрытые release blockers

`TWO_PHYSICAL_NODES_REAL_TLS_SIGNED_ACK=PASS_LAB_ONLY`, `REMOTE_HIGHWATER_PERSISTENT_EPOCH3=PASS_LAB_ONLY`, `RESTRICTED_WINDOWS_SCM_DEPENDENCY_CLOSURE_AND_MISSING_WITNESS_DENIAL=PASS_HOSTED_CI`, `OWNER_PC_INERT_REVIEW_RUNTIME_IMPORT=PASS`.
`OWNER_PC_PRODUCTION_SCM=NOT_INSTALLED`, `INDEPENDENT_OPERATOR_HARDWARE_WORM_ANCHOR=ABSENT`, `PUBLISHER_TRUSTED_SIGNING_CERT=ABSENT`, `HUMAN_INDEPENDENT_REVIEW=NOT_APPROVED`, `PRODUCTION_RELEASE=BLOCKED`.

Без отдельного доверенного владельца/оператора witness private signing key & non-rollback anchor (владелец текущего Linux может удалить/откатить свой SQLite), реального сертификата CA, подписанного владельцем/ревизором production release и положительного независимого решения нельзя включать автозапуск/произвольные файлы или объявлять Windows приложение промышленно завершённым. В новой интеграции никакие частные ключи, TLS секреты или рабочие пользовательские данные не публиковались.
