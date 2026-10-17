НЕЙРОЗАВОД: защищённый получатель операций — проверенные границы 17.10.2026

СТАТУС: ТОЛЬКО ИЗОЛИРОВАННЫЙ КАНДИДАТ. RELEASE BLOCKED. HANDOFF PAUSED_BY_USER. НЕ СЧИТАТЬ производственной приёмкой или испытанием двух физических компьютеров.

1. Точные исходники
- HOST основная owned ветка на момент замера: 0c33d8181e102e2ca3f47559ae6abeb2f4b72757, исходный offline_fenced_file_receiver.py Git blob 96739ec56183aca55b4102c4d0bb5cc6f3dabc9c.
- Исправление TOCTOU в отдельной ветке neurofactory-host-receiver-lock-audit-20261017: exact SHA 6bb33d4cdaa26abee6b6f9961b9f1ff5e546ba4e, новый receiver blob 11c4588f660ffbe66c24c2a200eff082fdab3369. Никакого merge нет.
- CORE в момент pinned E2E: 05ab48bf5b04818df2b632906886610587cad642, файл offline_receiver_client.py blob fffe9c513f3acc6e5d11e7baa26917648d6f9a4f. CORE старый локально авторизованный путь остаётся disabled.
- COORD pinned base E2E 5b7f8c48dc2f998f342ab9918f8828a815c4e73b; повторный pinned E2E после исправления в ветке neurofactory-coord-pinned-locked-receiver-20261017, tested commit b5c26799ca313c9224b857d1837a590d13c533ff.
- REVIEW source SHA d0f5e338c859016664924424405866ba8d445607.

2. Реальные изолированные тесты (точные CI записи)
- НОВЫЙ CORE signed-scope тестовый мост: CORE d38bc974578960ee4a7c57edb411d049acc909a1 + HOST 66dfbc6957c04cd9f8d19ba52ec783fa1dec129d, https://github.com/DSLitvinov1/my_first_repo/actions/runs/39025646182, job 117375981312, 17/17 PASS, ephemeral Ed25519 keys, PostgreSQL16. Это лишь signed-scope test fixture.
- Исходный endpoint HOST+CORE cross-component: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39025938343 job 117376803706, 8/8 PASS, actual one inert temporary file, five HOST negative cases, duplicate deny, forged signer, UNKNOWN recovery; one hosted runner.
- Отдельный REVIEW adversarial предварительный: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39026114292 job 117377312342, 12/12 PASS, подтверждён TOCTOU: revocation from SAME privileged PostgreSQL connection after first DB check before file writing still produces file (synthetic injection). RELEASE REJECT.
- HOST исправление двухфазного протокола: durable UNKNOWN intent first, then NEW live lease check under PostgreSQL FOR UPDATE lock held through O_EXCL file creation/fsync and completed receipt, crash rolls back receipt to precommitted UNKNOWN, no retry. Hosted Ubuntu/PostgreSQL16 https://github.com/DSLitvinov1/my_first_repo/actions/runs/39026318143 job 117377892906, first prior 15/15, then targeted 33/33 PASS. Explicit different connection's attempted revoke timed out while row locked; existing file O_EXCL/no overwrite remains.
- NEW E2E на точном исправленном HOST: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39026412065 job 117378161308, 8/8 PASS, one output file, five negatives and duplicate denial, SHA readback.
- REVIEW повторная hostile проверка PATCHED: https://github.com/DSLitvinov1/my_first_repo/actions/runs/39026524104 job 117378473853, 13/13 PASS. Отдельная PostgreSQL connection блокируется во время file/fsync; SAME PRIVILEGED connection способна инжектировать состояние в своей же транзакции — подлинная независимая OS граница отсутствует. REVIEW-NARROW: PASS для row-lock mitigation, REJECT LIVE.

3. Незакрытые блокеры
- Нет независимого authorised issuer/signing operator с отдельной OS identity и защищённым хранилищем private key ВНЕ CORE, PostgreSQL, модели, runner и GitHub Actions.
- Нет доверенного owner/repository/project authorization registry, внешне защищённого monotonic antirollback/head, pinned public key под другой доверенной identity.
- Нет реального аутентифицированного защищённого сетевого сервера и receiver under independently privileged OS identity. Возможен same-UID/admin/fork/root compromise; тестовые environment flags и ephemeral key НЕ security boundary.
- HOST fixture держит PostgreSQL row lock во время effect, но DB owner/admin, перенос dirfd, root, rollback key sequence и реальный distributed fault model не аттестованы.
- Неизвестен отдельно уполномоченный человек REVIEW и оператор двух действительных физических компьютеров. REVIEW code under shared GitHub identity не является внешней независимой приемкой.
- Ни реальные модели, ни live queue, ни публикация, ни оплачиваемые API, ни HANDOFF не запускались.

4. Строгий выпуск
REJECT LIVE. Не объединять отдельную ветку исправления с HOST и COORD без одобрения. Владельцу HOST Issue 14 — интегрировать изменение в свою branch после собственной проверки и обеспечить независимый protected operator trust root. CORE Issue 9 — только защищённый receiver выполняет effect и получает protected owner permit; не использовать тестовый response как разрешение. REVIEW Issue 11 — отдельный реальный security actor рассматривает pinned SHA и evidence, затем истинный 2-physical-host authorization. После одобрения провести настоящую одной учебной операции с отрицательными аварийными и повторными доставками.
