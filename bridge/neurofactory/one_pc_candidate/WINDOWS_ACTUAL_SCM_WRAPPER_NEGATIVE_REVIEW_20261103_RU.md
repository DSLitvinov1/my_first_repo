# НЕЙРОЗАВОД — 03.11.2026. Actual Windows SCM wrapper: NF-REVIEW-14

**Исходная точка:** [DRAFT #85](https://github.com/DSLitvinov1/my_first_repo/pull/85), точный родитель `f4c424a5544749668fd2eb5657207e7873a6039a`. В это же время появился параллельный DRAFT #86 по стадированию CORE; изменения этой ветки изолированы и не объединены.

**Новый DRAFT:** [PR #87](https://github.com/DSLitvinov1/my_first_repo/pull/87), ветка `neurofactory-p1-scm-wrapper-env-root-negative-20261103`.

## Уязвимость и исправление
В реальном `Assert-NfActualScmServiceDacl` путь к `sc.exe` ранее составлялся из переменной окружения процесса `$env:SystemRoot`. Этот источник управляется вызывающим процессом. Подмена могла заставить проверку читать фальшивый безопасный service-object DACL от чужого исполняемого файла при настоящем безопасном CIM owner. Это проблема доверия к источнику проверки, а не свидетельство взлома установленной службы.

Теперь путь строится через `[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)` (Windows special folder от ОС), с отказом при недоступности каталога. Остальная проверка реального wrapper, CIM owner, SDDL и прав не отключена. Изменение находится в исходнике `windows_setup/physical_host_production_preflight.ps1`.

## Адресная Windows-проверка
- **Точный SHA проверенного кода и workflow:** `8b21fca4bc7e447aa07feda06578fbd3a2ee58c3`.
- [GitHub Actions Windows 2025 #41524980069](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41524980069): **SUCCESS**. Логи job `125550268601`: 2 положительных сценария, 9 отрицательных, `NF_ACTUAL_SCM_WRAPPER_NEGATIVE_INTEGRATION=PASS_TEST_ONLY`, git diff clean.
- Тест запускает именно извлечённую из production source функцию `Assert-NfActualScmServiceDacl` и `Assert-NfScmServiceDacl`. Для получения SDDL использован только одноразовый нативный `.cmd` в временном каталоге; CIM owner возвращает изолированный stub. Тест отдельно подменяет `SystemRoot` и доказывает, что production wrapper получает путь ОС, а не переменную окружения.
- Отрицательные случаи: owner из CIM и SDDL не совпадают, недоверенный owner, CIM отказ и ошибка, sc nonzero, два SDDL, нет SDDL, недоверенный CHANGE_CONFIG, чужое имя службы. **Реальный `NeurofactoryCoreHost` не установлен и не запускался.**

## Границы
Это авторское тестирование на GitHub-hosted Windows с подставленными входными данными, **не** физическая проверка Windows владельца, **не** независимый ревизор, **не** production approval. Подмена окружения и проверка отказов доказаны только в указанных сценариях. Нужны реальные Windows SCM ACL/SID, transactional recipient-side CORE lease/fencing, актуальный pinned CORE в signed installer, физически независимый witness/highwater и защита от привилегированного valid-state rollback, ключи раздельных операторов и Authenticode. Не было установки, слияния, запуска очереди/HANDOFF, выдачи настоящих ключей или расходования средств.

**Решение:** `NF_REVIEW_14_ACTUAL_WRAPPER_NEGATIVE=AUTHOR_TESTED`; `PROCESS_SYSTEMROOT_TRUST_BYPASS=FIXED_IN_DRAFT`; `INDEPENDENT_HUMAN_REVIEW=NOT_OBTAINED`; `PRODUCTION_RELEASE=BLOCKED`.
