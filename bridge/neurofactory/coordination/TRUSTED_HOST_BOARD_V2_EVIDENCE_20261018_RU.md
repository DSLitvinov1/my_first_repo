# НЕЙРОЗАВОД — проверка исправления координационной панели TRUSTED HOST

Дата: 18.10.2026. Владелец: COORDINATOR, Issue #3, DRAFT PR #12. Изменение в пределах исключительно coordination/ и собственного CI workflow.

## Подтверждённый дефект

Действующий v1 статус-проектор содержал девять направлений и вовсе не содержал критический TRUSTED_HOST. Это не изменяло защищённое исполнение, но скрывало ключевую ветку при отображении статуса разработки. Ветку HOST нельзя считать прошедшей приёмку.

## Реализация

Добавлена опциональная v2 десяти направлений с TRUSTED_HOST. Старые девять направлений, схема v1, порядок и путь по умолчанию сохранены. Новая версия включается только явно. Для наблюдений HOST принимаются только связанный репозиторий и задачи/черновики #14, PR #15/#17/#18. Пустые сведения = unknown; любые сведения = not_verified. Возврат всегда запрещает live execution, retry и publish, независимо от phase.

Изменённые файлы:
- `bridge/neurofactory/coordination/mvp_status_projection.py` — Git blob `5c982826d3c57782396ec6385358ab3e1870428f`.
- `bridge/neurofactory/coordination/test_mvp_status_projection.py` — Git blob `0569ebbd60b5c479a9186355ed2b1a627806d4fa`.
- `.github/workflows/neurofactory-coordination-host-board-v2-linux.yml` — отдельный GitHub-hosted Linux тестовый workflow, только checkout+read-only Python; никаких ПК пользователя, секретов, модели, очереди или сетевой публикации.

Коммиты: source `a7836c11852792c838a8b4a42847e0ac13238689`, tests `95919d4173871e90da12f974ecfa2b4914277bb1`, workflow `d171375dc5f5c4e99605360cd727c013d0482618`.

## Испытания

Локальный изолированный Linux Python 3.13.5: точные файлы из GitHub свёрнуты обратно в Git blob ID, оба SHA полностью совпали с серверными; компиляция source выполнена; `python -B -m unittest discover ...`: **15/15 PASS, 0 FAIL**. В том числе 10 прежних и 5 новых случаев: v1 обратная совместимость, HOST UNKNOWN по умолчанию, блокировка ложного разрешения, отказ поддельной привязке HOST URL, повтору/переполнению и новый CLI-флаг.

Самостоятельная проверка автора, НЕ независимый REVIEW. Новый GitHub-hosted CI workflow создан на ветке; результат cloud run на момент записи НЕ ПОДТВЕРЖДЁН (GitHub connector не вернул push-only workflow run). Ранее ожидающий Windows self-hosted read-only run #39074665194 по последней проверке по-прежнему queued, НЕ считать его успешным.

## Производственные ограничения и следующий шаг

Это исправление только отображения статусов и не является реальной UI интеграцией. UI owner (#10) должен отдельно согласовать read-only v2 контракт. CORE owner (#9) и HOST owner (#14) должны довести подлинную финальную атомарную границу записи и защищённый off-host witness; никакие координаторские статусы не могут заменить криптографическую авторизацию.

PR #18 current observed `4221aaea1d549dd872fe189b551879b873bc4e47`: учебный SQL+четырёхрольный preflight 27/27 PASS на GitHub hosted, **но не финальная атомарная запись** и не производственная установка.

Нет второго отдельно авторизованного физического узла, реальных операционных owner/operator ключей, фактического OS reboot+старой DB restore и отдельного signed independent REVIEW. Производственный статус BLOCKED/REJECT LIVE; HANDOFF PAUSED_BY_USER; queue OFF; no paid API, merges or deployments.

## Дополнение: подтверждённые GitHub-hosted испытания 18.10.2026

Предыдущий статус «GitHub hosted run не подтверждён» относится только к более раннему моменту записи; теперь GitHub Actions и job logs проверены непосредственно через доступный GitHub.

1. v2 source v1-compatible, original 15/15 Linux: [run 39076449199](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39076449199), job 117524486658, exact tested commit `d171375dc5f5c4e99605360cd727c013d0482618`: 15/15 PASS.
2. Добавлен отдельный pinned `mvp_status_snapshot_v2_20261018.json` с 8 предоставленными наблюдениями и 10 конечными lane. TRUSTED_HOST `02972424eefabcd61d21100611e3eace4c6c3d5e` explicitly blocked; отсутствующий REVIEW = unknown; всё `not_verified`, разрешения false. Это недоверенные метаданные для отображения, НЕ криптографическое одобрение и не live GitHub refresh.
3. Добавлена адресная проверка физически неразвёрнутого HOST blocked и safety flags в `test_mvp_status_projection.py`. [run 39077391742](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39077391742), job 117527271156, tested exact commit `470a3c98760a14facfbd59a7ce9debc349b6c35a`, **16/16 PASS**. Подтверждено дополнительно [run 39077374587](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39077374587) 16/16 PASS на предыдущем snapshot-test SHA `8bc8e7d29c2d793163771c30f0dc0600329f3b46`.
4. Отдельный fail-closed десятипунктовый реестр release-readiness обновлён текущими проверенными исходными SHA: CORE `beb08eff32923d8ca364aabfde0458f380acf8e7`, HOST `02972424eefabcd61d21100611e3eace4c6c3d5e`, production-scope PR18 `4221aaea1d549dd872fe189b551879b873bc4e47`, PROVIDERS `827b654d9f7c6a10a9b90a9c97802e63116711b9`. [run 39077152808](https://github.com/DSLitvinov1/my_first_repo/actions/runs/39077152808), job 117526565181, exact SHA `e0a1891d0b3c534b6d1e2ae198b35938f8364cad`, **14/14 PASS**. При всех десяти пунктах статус остаётся BLOCKED и независимых подтверждённых разрешений 0.
5. Connected Desktop Commander account shows exactly one online Windows `WIN-LIDC05TBOQD`, month remaining remote-call quota `0%`; команды на ПК не запускались. Windows self-hosted CI не считать подтверждением второго физического устройства.

Приоритет CORE↔HOST неизменен: существующий `db_bound_four_party_preflight.py` blob `644fa6ddbeb8fe73ee61d8a29acf6620a24804be` удерживает SQL FOR SHARE только в пределах своего вызова и возвращает `receiver_effect_lock_still_held=false`, `production_effect_authorized=false`; тестовый HOST V4 `offline_operator_gated_receiver.py` blob `f040a69e63a405d9a75a87d621c0f9e3f2c5ee9c` явно разрешает только FIXTURE_ONLY и сохраняет старый тестовый путь. Этого нельзя передавать реальному исполнителю как production write permit. Точный контракт должен реализовываться в чужих HOST/CORE owned paths назначенными владельцами.

RELEASE REJECT/BLOCKED; HANDOFF PAUSED_BY_USER; нет независимого подписанного REVIEW, вторых физических машин, реальных длительных ключей, реального OS reboot/recovery. Никаких merges, модели в очереди, платных API или изменений пользовательского ПК.
