# НЕЙРОЗАВОД — закрытие локального CORE bypass и пределы технической приёмки
Дата: 2026-10-17 (Europe/Moscow); COORDINATOR owner, release = BLOCKED.

## Исходники / точные коммиты
- CORE branch `neurofactory-core-queue-owned-20261013`, current exact candidate commit `9313d508a1f5d9288f18046abf5130b46bedc194`. Mandatory-legacy-entrypoint denial introduced `88fb8d80efbc69966cd2ed98de85ed3cf37a2b38`, later own test workflow fixture environment corrected without changing executable source. Real `one_task_core.py` Git blob `ab1471813c6da29407c913b974a2209467a4b961`.
- HOST branch `neurofactory-trusted-host-owned-20261015`, exact `5c0132d1c53d3d569dd66967915203069e2a25e8`. Its `OfflineEffectReservation` still **TEST-ONLY** and returns `execution_allowed=false` even when intent reserved. No deployed protected issuer/API or destination fencing.
- REVIEW branch `neurofactory-review-owned-20261013`, exact `dfed53bbe9587e2644ccfc2799a0583508e88b66`; reviewer-owned negative test harness and own ephemeral Ubuntu CI only. The GitHub identity/owner is shared; NO independently delegated real-world security reviewer/RELEASE_APPROVE authority.

## Изменение CORE и доказательство
Старая `OneTaskCore.apply_offline_test(...)` теперь ALWAYS throws `CoreSafetyError(LEGACY_WRITE_DISABLED)` regardless of positive untrusted enqueue callback, local valid SQLite token or test environment variable; по этому старому пути запись файлов более не выполняется.

Прежняя детерминированная операция перемещена в `apply_fixture_offline_test` только для **изолированных** тестов: requires `NF_CORE_OFFLINE_FIXTURE=1` + temporary scratch repo and temp workspace. `FencedOfflineTestBridge` uses this explicit fixture-only API AFTER HOST `reserve_once` in ephemeral `nf_test` PostgreSQL. Local fixture switch can be set by the same OS principal: it is NOT proof of remote owner, signer or production authorization. The raw internal `_write_one_pinned` remains callable by the trusted same-UID principal; OS-level separation and host rights are therefore still crucial.

### Actually executed GitHub Actions
1. [CORE Linux/Windows #38982994520](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38982994520), exact executable code commit `88fb8d80efbc69966cd2ed98de85ed3cf37a2b38` (same executable blob as final HEAD), Linux **29/29** and Windows disabled-writer/path targeted checks successful. Includes new `test_legacy_direct_writer_is_disabled_even_after_positive_test_enqueue`.
2. [CORE different ephemeral UID #38982994564](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38982994564), exact `88fb8d80...`, success. This is a single GitHub-hosted machine with two Linux principals, NOT an authorized multi-PC trial.
3. [CORE + HOST #38983065738](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38983065738), current exact CORE commit `9313d508a1f5d9288f18046abf5130b46bedc194` + pinned HOST `5c0132d1c53d3d569dd66967915203069e2a25e8`, job `117248149814`, hosted Ubuntu / disposable PostgreSQL16 `nf_test`, **7/7 PASS**, verified log `NF_CORE_HOST_SYNTHETIC_ONE_FILE_CHECKPOINT=PASS_TEST_ONLY`, `NF_REAL_AUTHENTICATED_RECIPIENT_FENCING=NOT_DEPLOYED`. Five central HOST blocked/UNKNOWN/lease expiry/loser-or-stale worker/duplicate negatives cause NO sandbox file; one inert synthetic one-file checkpoint, plus explicit direct legacy route denial.
4. [REVIEW-owned independent *source harness* #38983203314](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38983203314), exact reviewer commit `dfed53bbe9587e2644ccfc2799a0583508e88b66` against exact CORE `9313d508...`, job `117248590133`, 6/6 PASS (old entry denies valid/forged token, including fixture environment, fixture endpoint absent switch/unsafe path denied, bridge denies when fixture gate off). This is independent test SOURCE, not independent human or trusted deployer signature.
5. First CORE+HOST run [#38982994521](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38982994521) FAILED one positive test due missing `NF_CORE_OFFLINE_FIXTURE` CI opt-in after source safety change. Own workflow update corrected and full 7/7 PASS on `9313d...`. Preserve failure history; no production file touched.

## Boundary of claims
- **CLOSED ON EXACT CORE SHA:** legacy `apply_offline_test` can no longer write based solely on local trusted callback and claim token.
- **NOT CLOSED / BLOCKED:** actual protected per-effect signed authorization at a separately privileged filesystem receiver (not just test host `reserve_once`), authenticated source/owner/repository permissions, durable external independent antirollback/key custody, receiver-side replay/idempotency atomic file commit, real multiple workers under separately trusted OS principals, and two actual separately authorized physical computers.
- No truly independent separately authorized release verdict/identity. REVIEW branch CI success must be recorded `APPROVE_NARROW_NEGATIVE_SOURCE` only, global `REJECT_LIVE` unchanged.
- Older COORD 5 negative gaps on CORE pre-change HEAD are historical baselines; do NOT claim they apply to final exact code unchanged.
- HANDOFF PAUSED_BY_USER; no models/Qwen, paid API, real users' code, auto-merge, publisher, or live queue ran.

## Next mandated sequence
1. Separate authorized HOST operator deploys real signed issuer/root protected OUTSIDE CORE/DB principal, signed project/repository source/policy, client auth and durable antirollback; produce exact HOST code SHA and real verification evidence.
2. CORE sole owner implements an actual protected per-effect recipient that consumes host identity/current lease/fence+idempotency inside atomic effect boundary, without synthetic env permissions. Keep legacy disabled.
3. Independent separately authorized REVIEW adversarial verdict on exact executable CORE/HOST SHAs, including real stopped writes for 5 negatives, crash after effect before receipt, path relocation, rollbacks/replays.
4. Only after written user authorization and independent acceptance, run one harmless task on two **different physical authorized computers**, with exact pre/post output proof; preserve release blockers until all gates green.
