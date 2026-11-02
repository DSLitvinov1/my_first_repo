# НЕЙРОЗАВОД — 02.11.2026. Windows review-only installer теперь включает актуальный CORE

**Дата:** 02.11.2026. **Статус:** проверено на одноразовой Windows 2025 в GitHub Actions; НЕ производственный релиз и НЕ независимая человеческая приёмка.

## Доказанный дефект
Существовавший [workflow установки review-only](https://github.com/DSLitvinov1/my_first_repo/blob/neurofactory-p0-core-lease-signed-witness-bind-20261102/.github/workflows/neurofactory-host-four-party-review-installer-ci.yml) и `stage_runtime_sources.py` запрашивали CORE из старого pinned commit `1c4ccd7d64e87e284a3796b3432f13910a48679c`. Поэтому новые исправления CORE-очереди в PR #81 и далее **не входили в устанавливаемый машинный пакет**, хотя исходники уже успешно проходили tests. Это прежняя NF-REVIEW-12.

## Изменения
- В существующем `stage_runtime_sources.py` закреплён верифицированный immutable CORE Git commit `f4c424a5544749668fd2eb5657207e7873a6039a` на базе [DRAFT PR #85](https://github.com/DSLitvinov1/my_first_repo/pull/85). Стадирование всё ещё использует Git blob SHA + SHA256 и 15 компонентов, но содержит новый `one_task_core.py` с `provision_empty_core_queue_offline` и отказом при пропаже очереди.
- В существующем Windows review-only installer workflow checkout CORE обновлён до того же точного SHA; добавлен обязательный manifest check (`source_commit`, staged file SHA256, наличие новых отказов), без bypass и без изменения трёх остальных исторически pinned источников HOST/PROVIDERS/COORDINATOR.
- Актуальные `local_workspace.py`, `physical_host_production_preflight.ps1`, подписанный `CORE↔HOST` scope/witness verify-only, защищённый HOST ledger/journal берутся из текущего source branch, как прежде. Все executable effects по-прежнему выключены.

## Реальная проверка на Windows GitHub Actions
[Run #41524425854](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41524425854), exact code+workflow SHA `3fb5fa0d67c849f9c556e0f0801cfe79055a248c`, **SUCCESS**.
- 15 pinned исходных компонентов.
- 78 файлов в staged package, SHA256 manifest.
- Точная версия CORE сверена и входит в review installer.
- Сборка Inno Windows EXE, временная машинная установка, проверка всех staged/installed SHA256 и отсутствие изменения/автоматического старта Windows SCM, корректное удаление — PASS.
- **UNSIGNED REVIEW-ONLY EXE SHA256:** `7288ACC60BEB90892F7ECC94BD1B99F6FEBF93215EC8FDFFB4872F61296632B7`.
- GitHub artifact `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION`, ID `13179456327`, автоматическое истечение **09.11.2026 21:01:52 UTC**. Устанавливать unsigned review-only с администраторскими правами на компьютер владельца ради проверки НЕ следует.
- Доказаны только CI-hosted install/uninstall и файл-целостность. Это не подтверждает защиту настоящего установленного Windows Host, запуск локальной Qwen, согласование owner/reviewer и выполнение задачи в производственной службе.

## Что осталось
1. Защищённая реальная Windows SCM с отдельным SID/DACL и защищённой конфигурацией/реестром, настоящий recipient-side atomic lease/fencing, пользовательская приёмка и отказ при power loss/reboot.
2. Независимо управляемый внешний Linux witness с root-owned trust, отдельными TLS/Ed25519 ключами, mTLS и внешне закреплённым монотонным состоянием, проверки полного rollback. Лабораторная имитация не равно реальному независимому узлу.
3. Законная подпись окончательного установщика Authenticode (не этим тестовым EXE), отдельное подтверждение подписанных точных source+binary SHA реальным независимым уполномоченным ревизором.
4. Последующие PR остаются DRAFT и **не объединены**. Никаких производственных очередей или HANDOFF, ПК владельца не менялся.

**Итог:** `CURRENT_CORE_IN_REVIEW_INSTALLER=VERIFIED`, `WINDOWS_CI_PACKAGE_INSTALL_UNINSTALL=PASS`, `SIGNED_PRODUCTION_BINARY=NO`, `INDEPENDENT_ACCEPTANCE=NOT_OBTAINED`.
