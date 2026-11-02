# НЕЙРОЗАВОД — 02.11.2026. Windows HOST — read-only проверка реестра конфигурации службы

## Основание
Внутренний NF-REVIEW-13, [Issue #11](https://github.com/DSLitvinov1/my_first_repo/issues/11#issuecomment-6586703444): PR #80 уже проверяет реальный SCM service-object DACL и права NTFS, но не owner/DACL реального Registry раздела конфигурации. Отдельный Windows Registry ключ может дать неадминистратору право изменять ImagePath и сервисные настройки. Это ещё один путь конфигурации, не подменяемый SCM-object DACL.

## Ветка и изменение
На exact базе [PR #81](https://github.com/DSLitvinov1/my_first_repo/pull/81) `8bf1e52862248a598e5a29d5c6cc06d4d598d3fa` создана отдельная ветка `neurofactory-p1-windows-service-registry-acl-20261102`. В уже существующем скрипте `windows_setup/physical_host_production_preflight.ps1` добавлено:
- `Assert-NfServiceRegistrySddl`: read-only fail-closed проверка структурного Windows Registry SDDL; owner строго SYSTEM/BUILTIN Administrators. Неизвестные ACE, отсутствие owner/DACL, неограниченные ключи и любые разрешения на KEY_SET_VALUE/CREATE_SUB_KEY/CREATE_LINK, DELETE, WRITE_DAC/OWNER, SYSTEM_SECURITY, MAXIMUM_ALLOWED и GENERIC_* для иных SID блокируются.
- `Assert-NfActualServiceRegistryAcl`: реальное чтение Windows RegistrySecurity через `Get-Acl` с отдельной проверкой **двух** узлов `HKLM\SYSTEM\CurrentControlSet\Services` и `HKLM\SYSTEM\CurrentControlSet\Services\NeurofactoryCoreHost`. Неизвестный путь, отсутствие ключа, ошибка owner/DACL или небезопасные права — отказ. Вызывается рядом с `Assert-NfActualScmServiceDacl`, до любого вывода о локальном доверии.
- Никакого изменения реестра/прав, установки SCM, ключей или выдачи производственного допуска. Действующий physical preflight по-прежнему возвращает только результат наблюдения с `production_release_authorized=false`.

## Результат адресных испытаний
[Windows GitHub Actions #41519552818](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41519552818), exact code+CI SHA `4cc0258b86a36ab9c62f9966ee32845eea2c67a3`: **SUCCESS** на временной Windows 2025. Два допуска безопасных SDDL; четырнадцать строгих отрицательных проверок; отдельно синтетически вызван **actual wrapper**, проверены обе Registry пути и его отказ при опасной ACE; реальная read-only проверка Get-Acl системного EventLog service key убедилась, что OS Registry API даёт owner+DACL. Код не менял реальные OS/Service Registry значения. Git diff — clean.
Проверяемые результаты: `NF_REGISTRY_SERVICE_AND_PARENT_ACL_WRAPPER=PASS_TEST_ONLY`, `NF_ACTUAL_WINDOWS_REGISTRY_READONLY_API=PASS`. Предыдущий audit NF-REVIEW-14 по реальному SCM-object wrapper **не закрывается** этой новой проверкой; для него нужен отдельный negative integration test.

## Что ещё остаётся
- Нет реально установленной и защищённой службы NeurofactoryCoreHost на Windows владельца; неизвестно, какой физический ACL будет у конкретного ключа. Тестовая RegistrySecurity системной EventLog — проверка API, не приёмка службы владельца.
- Нет реальных ключей OWNER/REVIEWER/WITNESS с физическим раздельным хранением, не развернут независимый живой Linux VPS witness/highwater, не подписан Authenticode окончательный производственный установщик, не проведён Windows reboot/rollback end-to-end, нет независимого подписанного APPROVE человека.
- Привилегированное изменение OS/Registry после разовой проверки (TOCTOU) требует защищённой установленной Windows службы, операторских ACL/ключей и повторной проверки непосредственно перед эффектом. Этот скрипт не выдаёт право исполнять CORE.
- Старый валидный snapshot HOST ledger всё ещё может локально обойти попытку запрета повтора без настоящего независимого внешнего highwater; это документированный P0.
**Решение:** `WINDOWS_REGISTRY_SECURITY_PRECHECK=TESTED_READONLY`; `PRODUCTION=BLOCKED`; все PR DRAFT, очередь/HANDOFF выключены.
