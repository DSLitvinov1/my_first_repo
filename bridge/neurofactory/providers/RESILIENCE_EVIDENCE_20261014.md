# PROVIDERS evidence checkpoint — 2026-10-14

**Scope:** offline/local Qwen only, no billable API, no live task queue, no merge.
**Base:** PROVIDERS PR #5, commit `8d4723a95808df1d66d7a49152c441960da6b1a5`.
**New branch:** `neurofactory-providers-resilience-20261014`, draft review required.

## Verified locally (own tests, NOT independent)

- Environment: isolated Linux container, Python 3.13.5.
- Full module discovery: `python -m unittest discover -p 'test_*.py' -v` → **71/71 PASS** (21 pre-existing offline router, 29 local Qwen/mock fallback, 21 new durable journal tests), runtime 3.871s.
- `python -m compileall -q *.py` → PASS.
- New durability test specifically exercises same-task duplicate reservation after process restart, unknown network outcome, concurrent threads and **3 spawned independent processes**, changed limits, tampered and duplicate-key JSON, symbolic link, pending partial write, lock after crash, second fallback replay and no effects before task-ID validation.
- All tests use a local loopback HTTP stub or mocks; there were NO real Claude/DeepSeek/Alibaba/Ollama model inference requests.
- Source readback verified by Git blob SHA:
  - `offline_router.py`: `4d2df763743152237c737f8dbfe5ec520af6907e` (unchanged)
  - `test_offline_router.py`: `d833cab2470dd66aeed4ca62704d16e78819e6d8` (unchanged)
  - `local_qwen.py`: `7c9526cf9cada019f9b641bb02d950c69c0b459b`
  - `fallback_controller.py`: `150ee008df1596db1697f37d9aff95e9bade081e`
  - `durable_budget.py`: `e7cbdc706ab1637ed0194c046bc10ec55d456552`
  - `test_durable_budget.py`: `4040690ba6ab36c7a9d3518795840e23f244cf75`
  - `test_local_qwen.py`: `1792db6f744c7f06e539665273baba5f3b82e41a` (unchanged)

## Isolation and recovery contract

The process explicitly opts into a trusted *pre-existing* local budget directory, requires stable task IDs, reserves before localhost inference, persists the task hash/counters using exclusive mkdir lock, temp write, file fsync, atomic replace, readback and POSIX directory fsync. Duplicate task IDs are never replayed; under uncertain disk or transport outcomes do not retry, do not remove a stuck lock automatically, and demand manual operator investigation. No queue records or external publishers are touched.

This is a conservative single-machine journal for local-only inference, NOT a distributed ledger or guaranteed exactly-once delivery across networked hosts. Persistent counters represent **attempts and character-reservation units**, not measured tokens or billing. Stable task IDs must come from the future owner; no caller can bypass identity in durable mode.

## Windows and independent audit: NOT YET VERIFIED

Windows device `WIN-LIDC05TBOQD` was reported online by Remote Desktop Commander, but account quota `remote_calls_left_pct: 0` makes remote inspection impossible. **No claim about installed Ollama, Qwen models, or actual Windows execution**. No models downloaded. Dedicated workflow `.github/workflows/neurofactory-providers-isolated-regression.yml` was added for isolated GitHub-hosted Linux and Windows tests (read-only, no secrets, no self-hosted runners). A successfully completed hosted run is NOT confirmed at this checkpoint. It never queries user's Windows Ollama.

Power-loss durability of Windows directory entries, recovery on network filesystems, cross-machine concurrency and independent security sign-off remain unproven. A Windows test success alone would not prove power-cut safety.

## Release decision

**BLOCKED.** Independent reviewer must re-evaluate exact final commit, run unit/integration and adversarial cases on Windows/Linux and sign off network boundary and storage invariants. Coordinator must approve before future integration/merge/production. HANDOFF remains paused, CORE/REVIEW/OPS/SKILLS untouched; Q090 not replayed.
