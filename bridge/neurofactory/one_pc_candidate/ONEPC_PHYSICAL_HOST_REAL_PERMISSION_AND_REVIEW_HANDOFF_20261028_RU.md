# НЕЙРОЗАВОД: HOST / реальные полномочия / независимая приёмка — пакет передачи
Дата оформления: 28.10.2026. Ветка: `neurofactory-host-owner-review-physical-preflight-20261027`, основание: DRAFT PR №69 и предыдущие испытания.

## Исправленная программная проблема

Предыдущие редакции Windows доверенного HOST использовали два конфликтующих корня публичных ключей: защищённые учётные корни под `%ProgramData%\Neurofactory\trust\four-party-public-pins.json` и выдуманные отдельные файлы под `%ProgramData%\NeurofactoryProtectedHost\trust`. Нельзя создавать второе самозаявленное хранилище ключей для обхода первого.

В `windows_setup/physical_host_production_preflight.ps1` установлена единая обязательная схема доверия:
- защищённый каталог `%ProgramData%\Neurofactory\trust` с единым four-party manifest для operator/owner/host/witness; проверяется отдельно переданный SHA256 всего манифеста, точный GitHub repository и owner numeric ID, тринадцать фиксированных полей, сроки, четыре public-key base64 длиной по 32 байта и **внешние отдельные SHA256 для каждого ключа**;
- пятый публичный ключ независимого reviewer в `independent-reviewer-public.bin` по отдельно закреплённому SHA256. Весь набор из пяти независимых fingerprints обязан быть различным;
- каталог, файлы и бинарные компоненты OS HOST обязаны принадлежать SYSTEM/Administrators, иметь выключенное наследование DACL, ни **один посторонний SID** не может изменять файл или DACL. Даже NTFS owner проверяется, поскольку он способен заменить права без явного Write ACE. LocalService и restricted per-service SID могут только читать защищённые roots;
- реальная установленная Windows SCM служба `NeurofactoryCoreHost` должна быть AUTO/RUNNING, работать как `NT AUTHORITY\LocalService`, иметь restricted Service SID и фактический LocalService process token; точный service binPath обязан совпадать с независимо заданными SHA256 исходника `protected_scm_host.py` и Python runtime;
- реальный runtime должен пройти Windows Authenticode `Valid` по независимо закреплённому отпечатку сертификата издателя;
- никакие значения из модели, UI, входящего IPC сообщения или файла, который сам себя подписал, **не становятся** доверенными владельцем/reviewer/witness ключами.

Программа ничего не меняет на Windows; при малейшей ошибке завершает проверку отказом. Даже если вся локальная процедура когда-либо вернёт наблюдение без ошибок, **эффекты задач и production release остаются запрещёнными**, пока независимая организация не проверит настоящие владельческие полномочия, подпись релиза и внешний highwater.

## Точно испытано

**PASS [Windows Actions №40585055844](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40585055844)**, исполняемый SHA `c77412b198aa92aa8a3bc944f1643afffb9fba7f`:
- реальный Windows-2025 hosted machine-wide Inno review EXE собран, установлен, сверены SHA исходников, 73 файлов staging, HOST-side исходники и установочные манифесты, затем полностью удалён;
- PowerShell preflight AST теперь действительно разбирается Windows PowerShell 7 без синтаксических ошибок;
- попытка получить physical production release на одноразовом GitHub runner возвращает FAIL_CLOSED;
- попытка смешать owner и host public-key fingerprints также отклонена; remote/OS keys на гостевом CI не назначены;
- не было автоматической регистрации SCM, установки привилегированных ключей, записи пользовательских файлов, установки Ollama или загрузки моделей.

Не подписанный Authenticode обзорный EXE `Neurofactory-Machine-Review-UNSIGNED.exe` SHA256:
`e3fd8f1cc704b43dfa86396c03656e3d53fd63f86e971f08b1e859b6018e5ffb`.
Артефакт `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, TTL согласно GitHub 7 суток.

Уже подтверждённая отдельная реальная CI цепочка Qwen→CORE→protected SCM→signed receipt→local SQLite journal, включая восстановление службы после аварийного завершения: [Actions №40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090), SHA `e1e09cda0d6ec82870a1a437dcd25ecf1363371b`. **Она испытана на одной disposable Windows, а не как окончательная пользовательская служба.**

## НЕ закрыто: строго различать настоящую AUTHORITY от исходников

1. Исполнительный файл `protected_scm_host.py`, на который ссылается проверка **пока не установлен и не зарегистрирован** как производственная служба на ПК владельца. Реальная CI служба принадлежит test-only receiver и не должна превращаться в production простой сменой названия.
2. Настоящие независимые Ed25519 private signing keys owner, host, operator, reviewer, witness не выданы отдельно уполномоченными сторонами, публичные roots и программа не закреплены физическим оператором на ПК владельца. Тестовые CI ключи недействительны.
3. Publisher Authenticode production installation EXE ещё не подписан настоящим издательским сертификатом, независимо закреплённой цепочки сертификатов нет.
4. Отдельный живой witness/неоткатываемый storage пока не развёрнут, реальный low-level Windows HOST не связан с его fresh signed highwater receipt. Для предварительного пользовательского UI он не нужен; для антиоткатного production execution — блокировка сохраняется.
5. Независимый reviewer не назначен и не подписал APPPROVE для точного Git SHA и бинарного SHA. Аудитором не может быть лицо, которое само создало PR, и авторские комментарии в Issue №11 не считаются независимым вердиктом.
6. Нет доступа к физическому владельческому ПК для полномочного администрирования, перезагрузки и проверки recovery/ACL с настоящими сертификатами.

## Объём независимой проверки

Ревизор должен: сверить Git исходник, бинарь, настоящую доверенную publisher цепочку, пять независимых root-key PIN, владельческое разрешение на конкретное действие, SCM SID + token + DACL, отсутствие изменяемого кода с правом HOST, сравнить signed remote epoch с защищённым **независимым** highwater, проверить rollback старого Windows snapshot, reboot, потерю ACK после внешнего durable commit, дублирование task/operation/nonce, отозванный ключ, неподписанный/повреждённый компонент и повторную проверку состояния после падения. Обязателен отдельный подписанный decision `APPROVE` или `REJECT` на точный source+installer SHA и конкретную машину.

**Итог:** программный OS read-only preflight готов и испытан на гостевой Windows; производственный HOST, реальные полномочия, независимая физическая приёмка и установка на ПК владельца не завершены. Никаких формулировок «PRODUCTION PASS» до их фактического выполнения.
