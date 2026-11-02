# НЕЙРОЗАВОД — 02.11.2026. Облачная лаборатория и устранение P0 silent ledger recreation

**Основа:** существующий [DRAFT PR #74](https://github.com/DSLitvinov1/my_first_repo/pull/74), точный исходный SHA `7afef5bc19aff3b330e7dcedc35cb29232f1a911`. Новая изолированная ветка `neurofactory-p0-no-silent-ledger-recreate-20261102`. Никакого изменения main, пользовательского Windows и других проектов.

## Проверенное реальное облачное окружение

Устройство `litd12123.clodocd.com` зарегистрировано в Remote Desktop Commander как отдельный Linux узел; Ubuntu Linux, x86_64, Python 3.12.3, Git и Python cryptography доступны. RAM около 11 GiB, свободно около 107 GiB. Отдельная копия *точно существовавшего* PR #74 размещена в `/home/cloudagent/neurofactory-lab/source`, собственная папка изолирована от существующих cloud-browser, migrations и других приложений. `git ls-remote` сверил GitHub SHA исходника. Доступны одновременно 2 удалённых устройства (Windows и Linux); это доказывает только регистрацию устройств, **НЕ назначение независимых владельцев ключей**.

В облаке базовые **29/29 тестов** signed HOST bridge прошли до изменений. После исправления cloud Linux испытания: **32/32** прежних/новых криптографических и журналирующих теста и **4/4 отдельные OS-process** испытания успешно. Никакой настоящей Qwen и Windows OS reboot в облаке не запускались.

Отдельно прочитаны факты о VPS-witness: `/etc/neurofactory/witness` отсутствует, `/var/lib/neurofactory-witness` отсутствует, защищённого конфигурационного файла и персистентной witness SQLite базы нет, `systemctl is-active neurofactory-witness` = inactive. Пользователь `cloudagent` uid=1000, а не административный root. НЕТ действующего внешнего доверенного witness. Чужие службы, сетевые правила, миграции не менялись.

## Подтверждённая ошибка и исправление

**Риск:** предыдущая функция `_connect` при отсутствующем journal db **молча создавала пустую SQLite и таблицу**, тем самым возвращая локальную систему к чистому состоянию и неявно позволяя повторить прежнее внешнее резервирование после удаления/отката локального файла. Отдельный внешний witness должен независимо запрещать такой replay, но HOST обязан сам fail-closed.

**Изменено:**
- Run-time HOST теперь **не создаёт и не восстанавливает** отсутствующую, удалённую, усечённую или повреждённую SQLite journal DB. SQLite открывается только как уже существующая база в режиме `mode=rw`. Несуществующая папка и симлинк запрещены.
- Отдельная offline функция `provision_empty_attempt_ledger_offline` допускает создание пустой базы один раз только в заранее созданном оператором каталоге; не вызывается службой/мостом и никогда не перезаписывает существующую. Настоящие права владельца и DACL должен установить и проверить независимый Windows оператор; сам Python-код не доказывает эти права.
- При использовании проверяется точная заранее определённая DDL-схема, отсутствие посторонних таблиц/триггеров, `PRAGMA quick_check` и журнал `DELETE`. Любая порча или непредвиденное изменение означает отказ до вызова mTLS.
- Добавлен адресный тест, моделирующий **настоящий аварийный `os._exit` отдельного дочернего процесса после SQLite COMMIT** и отказ следующего OS-процесса повторить; ещё тестируются 4 конкурентных OS-процесса, deleted DB и повтор external epoch.

## Точные испытания GitHub Windows

- [Windows 32 + 4 PASS №41471842112](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41471842112), код и тесты commit `2df145b1396d87bde3d434b32cb25bb5503056d3`; отдельный настоящий дочерний процесс Windows и racing-simulation, не физический reboot ОС. Не повторялась дорогостоящая модель Qwen.
- [Windows Inno release-candidate №41471892222](https://github.com/DSLitvinov1/my_first_repo/actions/runs/41471892222), точный код/CI commit `2cbb57a4c482ddeff6fc7fe4286a56c1e35307d0`, status SUCCESS, 15 pinned CORE/HOST/PROVIDERS/COORD files, 76 install-staged files. Успешные compile, installed manifest SHA verification, deliberate refusal to register production SCM, uninstall. 
- Review-only **UNSIGNED** установщик SHA256 `5D1F3E2AC2B7F9E95B9328883450316AEE8A5C950197C6AAF43F6E498C16EB58`. GitHub Actions artifact `Neurofactory-Machine-Combined-Review-UNSIGNED-NOT-PRODUCTION` ID `13155272421`, expires `2026-11-09T15:29:11Z`. Пакет НЕ подписан Authenticode и НЕ одобрен независимым ревизором.

## Остаётся принципиально незавершённым

1. Подключение настоящего постоянно работающего Windows SCM HOST к защищённой оператором SQLite и CORE живому lease так, чтобы проверка OWNER/REVIEWER/witness и запись эффекта были последовательными без обходного тестового контура. **Текущий установщик для REVIEW, не production.**
2. Реальный независимый VPS witness с root-owned config, TLS/Ed25519 защищёнными ключами отдельного оператора, частным VPN-каналом и highwater, защищённым от отката Windows. Текущий облачный Linux узел **не удовлетворяет этим условиям** и не должен считаться доверенным только потому, что он физически отличается от Windows.
3. Реальные owner/reviewer/operator key custody, Windows SCM SID/DACL, подписанный Authenticode installer, безопасное обновление/backup/restore и физический Windows OS reboot/rollback приемка.
4. Формальный signed independent REVIEW на точные исходные SHA+hash EXE, отдельный допуск владельца до установки.

**Статус: DRAFT / NO MERGE / NO REAL HOST EFFECTS / PRODUCTION QUEUE OFF / HANDOFF PAUSED.** Эта работа не означает согласия на оплату VPS, реальную авторизацию подписи или публикацию.
