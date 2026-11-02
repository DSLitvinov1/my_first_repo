# НЕЙРОЗАВОД — 03.11.2026. Совместный review-only Windows-кандидат CORE + SCM

**Статус: DRAFT, только лабораторная проверка.** Изменены только review pipeline и закрепление immutable CORE; производственный запуск/установка владельцу запрещены до отдельного допуска. Это не независимая приёмка.

## Происхождение и точный проверенный код

- DRAFT [PR #88](https://github.com/DSLitvinov1/my_first_repo/pull/88): `neurofactory-p1-combined-core-scm-review-20261103`.
- Источник новой ветки: DRAFT [#87](https://github.com/DSLitvinov1/my_first_repo/pull/87), SHA `2fdb275ac4a1650fe0d91893158d4ef231737f4e`, сохраняет исправление `Assert-NfActualScmServiceDacl` от недоверенного `$env:SystemRoot`.
- Из параллельного DRAFT [#86](https://github.com/DSLitvinov1/my_first_repo/pull/86) перенесены точный pin проверенного CORE SHA `f4c424a5544749668fd2eb5657207e7873a6039a` и тест его включения в Windows review-only installer. Старый CORE SHA `1c4ccd7d64e87e284a3796b3432f13910a48679c` в новом кандидате не используется.
- **Exact tested code+CI SHA:** `34cd302475e2bed699944487c71f1a375d04f0dd`. Дополнительный коммит этого отчёта только документационный; его не выдавать за отдельно испытанный SHA.
- GitHub compare от #87 к указанному tested SHA: 3 изменённых пути — `stage_runtime_sources.py` и два workflow. Ни модель, ни очередь, ни доверенный host, ни main не изменялись этим PR.

## Реальные общие Windows CI проверки на одном SHA

1. [Windows actual SCM wrapper negative #41528309074](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41528309074) — **SUCCESS**, job 125561650167, 2 PASS_ALLOW + 9 PASS_DENY. Временный cmd-fixture и CIM stub, без изменения настоящей службы; подтверждены ограничения для подменённого SystemRoot и отказные случаи.
2. [Windows installed review bundle #41528308979](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41528308979) — **SUCCESS**, job 125561650245, 15 pinned source components, 78 staged files; exact CORE SHA и SHA256 сверены, Inno компилятор собрал EXE, машинная временная установка, сверка installed SHA256 и удаление PASS; реальная SCM-служба не зарегистрирована и не запущена. Physical host preflight доступен только для fail-closed проверки, не для impersonation CI.
3. Артефакт: `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, GitHub artifact ID `13181211124`, истекает 09.11.2026 21:27:42 UTC. **Unsigned review EXE SHA256:** `0F5BBF0F0B2143052A1E8B8AB4FD95217DAF3D91296304BB24689535DD987FCD`. Не предназначен для установки с администраторскими правами на ПК владельца.

## Непреодолённые ворота выпуска

- Нет физически установленного и подтверждённого restricted Windows SCM + получателя с атомарной транзакционной CORE lease/fencing и полномочиями; испытание crash/reboot/restore на устройстве владельца отсутствует.
- Нет действительно независимого внешнего свидетеля с отдельным оператором, защищёнными настоящими mTLS/Ed25519 ключами и устойчивой к привилегированному откату монотонной точкой; локальная SQLite/временный CI свидетель этого не заменяет.
- Нет подписанного Authenticode production binary с реальным издательским сертификатом и сверенным SHA, нет отдельного human APPROVE от уполномоченного независимого ревизора Issue #11.
- Qwen исследовательский цикл не предоставляет полномочия на изменение проекта; production queue и HANDOFF остаются отключёнными. SKILLS остаются выключены. Никаких платных API, merge или пользователя Windows PC действия не выполнялись.

**Итог:** `COMMON_SHA_WINDOWS_CI=PASS`; `REVIEW_INSTALLER=UNSIGNED_INERT`; `LIVE_RELEASE=BLOCKED`; `INDEPENDENT_REVIEW=NOT_OBTAINED`.
