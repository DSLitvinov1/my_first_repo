# НЕЙРОЗАВОД — Windows HOST: защита объекта службы SCM, 02.11.2026

**Только DRAFT / read-only preflight / без установки и без разрешения на выполнение.** Продолжение PR #79 (исходный HEAD `c761a382c262c19f381f6774762f762ece16eb69`). Не меняет исходники CORE, Qwen, ключи, внешнего свидетеля и production.

## Почему этот контроль необходим

Ранее `windows_setup/physical_host_production_preflight.ps1` проверял реальный процесс Windows, ограниченный Service SID, командную строку SCM, SHA-256 runtime/source, Authenticode runtime, NTFS ACL файлов и трёх публичных корней. Но **DACL самого объекта Windows-службы** не проверялся. NTFS-запрет на замену файла не защищает от права `SERVICE_CHANGE_CONFIG`: пользователь, которому выдано такое право в SCM, может заменить `ImagePath` службы уже после однократного просмотра. Также опасны START/STOP, WRITE_DAC, WRITE_OWNER, DELETE и generic service rights.

## Изменения

1. Добавлен `Assert-NfScmServiceDacl`: строгая разборка Windows SDDL средствами `RawSecurityDescriptor`; требует владельца SCM-объекта SYSTEM или BUILTIN Administrators, существующего DACL, отказывает неизвестным ACE, проверяет каждый разрешающий ACE. Только SYSTEM/Administrators могут иметь права конфигурации, запуска/остановки, удаления, смены DACL/владельца и generic-control. Прочим разрешены только безопасные запросы состояния.
2. `Assert-NfActualScmServiceDacl` читает DACL через реальный `sc.exe sdshow NeurofactoryCoreHost`, но не полагается на его текст как на доказательство владельца. На временной Windows 2025 подтверждено: `sc sdshow EventLog` возвращает DACL **без OWNER**, поэтому владелец запрашивается независимо через read-only Windows CIM `Win32_Service.GetSecurityDescriptor`; при ошибке, не SYSTEM/Administrators или несовпадении данных — отказ.
3. Новый барьер вызывается **до** отчёта о локальном доверии из уже существующего физического Windows HOST preflight. Он не включает службу, не меняет права и не обходит запреты запуска/релиза.
4. Отдельный `test_scm_service_object_dacl_ci.ps1` извлекает именно функцию из текущего рабочего скрипта через PowerShell AST, без вызова preflight на реальном объекте. Синтетические SDDL проверяют положительные случаи и негативные SERVICE_CHANGE_CONFIG/START/STOP/PAUSE/USER_CONTROL/DELETE/WRITE_DAC/WRITE_OWNER/GENERIC_ALL/EXECUTE/WRITE/MAXIMUM_ALLOWED, чужого владельца, доменного пользователя, отсутствие DACL, отсутствие owner, невалидный SDDL.

## Адресные доказательства

- Windows GitHub Actions [run #41506001431](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41506001431) — **SUCCESS**, исходный код+workflow exact SHA `3dc6e4676248f7a4c3026f4335a3a801d01fe0ae`, **19/19 сценариев PASS** (2 разрешающих, 17 отказов). Проверен `git diff --exit-code`.
- На том же одноразовом Windows 2025 раннере реальная read-only проверка системной службы `EventLog`: `NF_REAL_SC_SDSHOW_OWNER_PRESENT=False`; `NF_REAL_SCM_CIM_OWNER_QUERY=PASS_READ_ONLY`. Это проверяет реальную доступность двух источников ОС, **не** подтверждает, что NeurofactoryCoreHost установлен на компьютере владельца.
- Первая промежуточная CI попытка #41505623353 завершилась FAIL из-за некорректной проверки `$LASTEXITCODE` после PowerShell-скрипта (19? на тот момент 17 синтетических случаев уже прошли). Исправлен исключительно тестовый workflow; финальный #41506001431 PASS.
- Временный Windows runner не менял службу, DACL, ключи или установку; весь код read-only. Полная тяжёлая матрица не повторялась.

## Что ещё НЕ подтверждено

Реальный физический Windows HOST с доверенной DACL и отдельными SID, настоящий независимо управляемый Linux mTLS witness и durable highwater, защищённые root-owned ключи, реальный Windows CORE lease fencing, подпись конечного установщика Authenticode и независимое человеческое одобрение на точный бинарный SHA. Результат **не означает**, что Windows SCM DACL владельца уже безопасна; она будет проверена только на конкретной машине в физической приёмке.

**Статус:** локальный read-only защитный барьер реализован и прошёл адресные Windows тесты. RELEASE BLOCKED / PR DRAFT / NO MERGE / QUEUE OFF / HANDOFF OFF.
