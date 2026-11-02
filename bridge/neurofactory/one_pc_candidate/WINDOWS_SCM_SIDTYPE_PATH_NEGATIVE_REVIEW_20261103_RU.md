# NF-REVIEW-15 — Windows SCM SID type: PATH spoof, targeted DRAFT proof

Дата: 03.11.2026 (МСК). Режим: только GitHub DRAFT / Windows CI fixture, **не production**.

## Исходная точка

- [Объединённый DRAFT #88](https://github.com/DSLitvinov1/my_first_repo/pull/88), точный базовый HEAD `7340c824ca5ee5ce6d06814707e4801542025894`.
- [REVIEW #11](https://github.com/DSLitvinov1/my_first_repo/issues/11): независимого подписанного решения человека нет. Результат автора не является APPROVE.
- Исправлены только read-only проверки Windows `physical_host_production_preflight.ps1` и адресный CI. Состояние #86/#87 в main не менялось.

## Дефект и изменение

Ранее `sc.exe qsidtype` искался через PATH, а произвольная строка с `RESTRICTED` засчитывалась как действительная проверка. Злоумышленник мог подменить `sc.exe` в окружении вызывающего процесса и исказить отчёт физической проверки.

Теперь `Assert-NfActualRestrictedServiceSidType` получает Windows-каталог от ОС, вызывает абсолютный `System32\\sc.exe`, требует успешный native exit и ровно одно поле `SERVICE_SID_TYPE: RESTRICTED`, отклоняет дубли и посторонние значения. Полный физический preflight по-прежнему не даёт production authority.

## Воспроизводимое подтверждение

**Точный код и CI SHA:** `9d0517a54368b26a76ce8be40e39318533a33aa8`.

[GitHub Actions Windows 2025 run #41533436010](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41533436010): **SUCCESS** на этом SHA, job `125579195026`. Проверка фактической функции через извлечённый PowerShell AST с изолированным native .cmd и подменёнными `PATH` / `SystemRoot`:

- Новые сценарии: 2 разрешённых (строго доверенный OS path, однозначный вывод), 7 запрещённых (NONE, ложная подстрока, дублирующее поле, неверный суффикс, ненулевой native exit, неверное имя службы; перечень содержит 6 меток, так как последнее — отдельный прямой отказ).
- Прежняя actual SCM wrapper integration: 2 allow / 9 deny, также PASS на этом SHA.
- `git diff --exit-code` после тестов: PASS.

Промежуточные run #41533230006 и #41533307851 были **FAILURE**. Первый до устранения ошибочной сериализации исходника, второй из-за оставшегося в тестовом PowerShell сеансе ненулевого native exit code после намеренно отрицательного сценария. Исходник восстановлен из точного #88 base, diff ограничен, тестовый exit code сбрасывается только после успешных проверок. Финальный run выше SUCCESS; промежуточные провалы не скрываются.

## Не доказано

Не запускалась настоящая установленная SCM-служба владельца, не проверялся реальный ограниченный Windows service token, не выполнялись физический reboot/rollback, внешняя независимая защита VPS highwater, Authenticode-подпись, операторские ключи или независимая человеческая приёмка. Qwen на устройстве владельца не запускалась. Никаких очередей, HANDOFF, установок и production-операций не было.

**Граница выпуска:** DRAFT, NO MERGE, NO PRODUCTION, NO OWNER WINDOWS INSTALL, NO INDEPENDENT APPROVE.
