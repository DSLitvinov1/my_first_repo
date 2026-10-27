# НЕЙРОЗАВОД — отдельный VPS для независимого свидетеля: результат 27 октября 2026

**Текущий статус**: владельцем разрешено выбрать отдельный платный VPS. Цель — отдельная от Windows ОС и диска непрерывная защищённая служба внешнего журнала, а не перенос Qwen. Никакого платежа, регистрации аккаунта или создания VPS из этого чата не выполнено: у инструментов отсутствует подключённый провайдер VPS/учётная запись Timeweb. Это существенный *реальный* блокер; не заменять его утверждением «сервер запущен».

## Выбор сервера для заказа

Рекомендованный конкретный вариант: Timeweb Cloud Cloud-40, 2 vCPU 3.3 ГГц, 2 ГБ ОЗУ, 40 ГБ NVMe, около **900 ₽/мес** по официальной странице `https://timeweb.cloud/services/cloud-servers` (помесячный тариф, без неизвестных дополнительных платных опций). Выбирается только НОВАЯ VM Ubuntu 24.04 LTS, x86_64, отдельный сервисный UNIX UID, отдельная VPN и подписной контур; существующие Render/KRYTEX/Ashamta/ChoiceFlow/CRM и другие VM не использовать. Перед оформлением заказать только конфигурацию в установленном лимите и перепроверить стоимость IP/бэкапов/VPN/хранения. Физическую независимость узла нельзя установить тестом на локальной Github VM.

## Разработано и испытано в новой ветке

Исходная безопасная база PR #66 (remote highwater client, реальная mTLS TLS1.3 и одноразовая server-часть). Новая отдельная ветка `neurofactory-independent-vps-witness-operator-20261027` добавляет:
- `external_highwater_daemon.py` — непрерывная обработка последовательных mTLS подключений; исключительно IPv4 из RFC1918 для production; root-owned config `/etc/neurofactory/witness/production.json`, отдельные защищённые server certificate, client CA, Ed25519 private signer, TLS private key, постоянная SQLite БД и точная проверка Ed25519 **публичного SHA PIN** и своего TLS server DER сертификата перед запуском; запуск non-root; ненастроенная VM немедленно отказывает.
- `vps_witness_systemd/neurofactory-witness.service` — постоянная системная служба с dedicated user/group, защищённым `/opt/` исходником, `ProtectSystem=strict`, отсутствием Linux capabilities, сетевым доступом только к частным IP диапазонам, автоматическим возвратом процесса при сбое, read-only audit before startup; **не установлена** ни на один пользовательский Linux сервер.
- `vps_witness_systemd/verify_witness_source_archive.py` — read-only проверка отдельно независимо заданного SHA256 архива, строгого набора файлов, внутреннего SHA256 каждого файла, отсутствия неизвестных ZIP путей/симлинков/секретов; ни один файл не распаковывает и прав не выдаёт.
- `vps_witness_systemd/OPERATOR_VPS_INSTALLATION_RU.md`, заведомо **НЕРАБОТАЮЩАЯ до ввода реальных pins** `production.json.example`, закреплённая версия криптографической зависимости.

## Точные подтверждения

**PASS** [Actions №40551539129](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40551539129) на source SHA `6ee8ef443f4c9663ff14dbb5fb9eb959154ecacd`.
- 4 проверки защищённого VPS-сервиса: реальная последовательность трёх TCP/TLS1.3+клиентских-сертификатов, два независимых epoch, запрет повторной операции, корректная остановка, отказ wildcard/public/localhost production IP, static systemd ACL/UX.
- 6 проверок операторского source-архива: SHA отдельно сверяется по входному значению, отказ подделки файла/изменения манифеста на RELEASE/незнакомых файлов/отсутствующего архива.
- CI подтвердил отказ **реального запуска** сервиса без OS-installed protected config: `NF independent witness NOT READY: protected operator pins absent`.
- Собран ZIP артефакт GitHub Actions `Neurofactory-VPS-Witness-OPERATOR-STAGING-NO-KEYS`, 11 контрольных source-файлов, SHA256 архива `f907d5d4514cde15ed706738c619ec998501391b4b5d0c06ce63b80f47e72f8d`; GitHub retention до **03.11.2026**. Архив НЕ production-approved, в нём нет реальных приватных ключей и цифровой подписи издателя.
- Более ранний действительный Qwen → CORE → restricted SCM HOST → local signed journal, unattended crash recovery **на одной hosted Windows** подтверждён [№40542374090](https://github.com/DSLitvinov1/my_first_repo/actions/runs/40542374090). Это отдельно от VPS proof.

## Что именно ещё необходимо сделать на РЕАЛЬНОМ VPS

1. Владелец создаёт НОВЫЙ VPS Timeweb Cloud; предоставляет оператору реквизиты инстанса и доступ без передачи приватных SSH ключей в чат. Сервер должен иметь публичный IP **только для администрирования по разрешённому адресу**, witness API — только на частном VPN IP. Если провайдер требует оплаты, фактический платёж производится владельцем в защищённом кабинете; разработчик не получал платёжные реквизиты.
2. Отдельный доверенный администратор сверяет source/ZIP digest через независимый канал и **после подписанного ревью** устанавливает системного пользователя, root-owned pins и immutable source, необходимые wheel dependencies по независимым SHA256, создаёт persistent-DB, TLS1.3 cert/key, отдельный Ed25519 signer, VPN, firewall и отозванные signer политики.
3. Независимый reviewer подтверждает точный исходный SHA и signer-полномочия Issue #11, отсутствие утечки приватных ключей и цепочки удаления/обновления.
4. После отдельной подписи publisher Authenticode точного окончательного Windows EXE подключить production Windows клиент и защищённый HOST к реальному witness: проверить потерю ACK после commit, rollback Windows, reboot VPS, компрометацию signer, переключение lease epoch и невозможность дубля.
5. Критично: защищённое хранение только на VPS, хотя физически отделено от Windows, **можно откатить вместе с VPS**. Для сильного внешнего antirollback необходимы WORM/append-only storage/внешний независимый floor и отдельные полномочия storage-owner. Такие механизмы пока не развернуты и не проверены.

До полного внешнего решения — DRAFT, NO MAIN MERGE, NO AUTO CORE/HOST TASKS, NO SKILLS, NO OWNER-PC INSTALL.

Официальный тариф необходимо проверять по фактическому счёту пользователя; информация о цене не является договором или бронированием.
