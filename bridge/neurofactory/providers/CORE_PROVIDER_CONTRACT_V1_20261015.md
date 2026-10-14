# PROVIDERS ↔ CORE — proposed request/result contract v1 (2026-10-15)

**Status: CANDIDATE, not integrated or approved.** Owner: PROVIDERS #5. Coordination reference: `bridge/neurofactory/coordination/MVP_READ_ONLY_INTERFACE_CONTRACT_20261015_RU.md` in the COORDINATOR branch. This contract is a proposal for coordinator (#3) and CORE (#9) agreement, **not** authority to alter their code.

## Input from a trusted CORE caller

JSON object, exact mandatory fields, all other keys rejected:
- `schema`: literal `neurofactory.providers.request.v1`
- `task_id`: stable, unique, never re-used within a provider ledger; safe identifier (max 64 chars)
- `project_id`: approved sandbox project identifier (max 64 chars)
- `input_sha256`: 64 lowercase hex bytes digest of trusted task/input snapshot, provided by CORE
- `target_path`: approved relative path under `src/`, `docs/`, or exact coordinator sandbox `bridge/neurofactory/development/core_owned/`, extensions `.py`, `.md`, `.txt`, `.json`, no hidden/traversal/absolute components
- `instruction`: plain text instruction max 4000 characters; no shell commands, downloads, secrets or API keys

Crucial: `project_id`, `target_path`, `input_sha256` come from CORE's own allowlist and trusted claim, not an arbitrary model or UI message. This provider validates syntax and exact model reply path but **cannot authenticate CORE**. Do not call the adapter directly with unapproved requests.

## Result returned to CORE (not REVIEW)

- `schema`: literal `neurofactory.providers.result.v1`.
- `status`: `BLOCKED` (diagnostics/resources/replay), `INVALID_MODEL_OUTPUT`, or `PROPOSED_UNVERIFIED`.
- `task_id`, `project_id`, `input_sha256`, `provider=ollama-loopback`, exact `model` (allowlisted and read back from local generation), `offline_mock=false`.
- `error_code`: explicit reason or null; `attempt_consumed` distinguishes preflight from tentative inference attempt.
- `prompt_sha256`, `response_sha256` (hash of exact textual response), with no plain prompt or raw model output in diagnostic log.
- `resources` includes observed available physical RAM, model size from Ollama installed tags, and conservative required RAM; absence of evidence returns `BLOCKED`.
- `proposed_files`: **zero or one** untrusted file suggestion; `relative_path`, full `content` for protected in-process handoff, `content_sha256`, `applied=false`, `verified_by_core=false`.
- `api_cost_usd=0`, `review_approved=false`, `published=false`. These are policy statements about no external APIs or publishing, not independent billing provenance.

**Provider never mutates project files.** CORE owns approved branch, filesystem writer, deterministic tests, leases, receipts, replay/cancel decision, and readback after writing. The provider must never issue review verdicts or side-effect publishing permissions. Keep all raw proposed content in a trusted approved in-process channel; CLI safe smoke redacts content and prints only hashes.

## Trust, crash and resource boundaries

1. Read-only preflight: installed model must match exact allowlist `qwen2.5-coder:1.5b`, `qwen3:0.6b`, `qwen3:4b`, or `qwen2.5-coder:7b`; Ollama tags URL pinned to IPv4 localhost; disable proxies and redirects; no downloads. Use `GlobalMemoryStatusEx` on Windows and `sysconf` on Linux; fail closed on low/unknown RAM.
2. Provider adapter stays disabled by default; explicit enabling only after successful preflight. Max 60s HTTP timeout, limited input/output, one request per approved task; no unbounded retry, paid API, cloud fallback or automatic model install.
3. Own trusted persistent ledger records stable task id and reservation before Ollama inference. Crash, duplicate task id, uncertain HTTP result or corrupt ledger ⇒ STOP/blocked. Ledger is single-machine, not distributed. Windows power-cut fsync durability is NOT independently confirmed.
4. Model output is untrusted JSON suggestion validated against CORE's one-file target. No model evaluation is mistaken for independent review, verified patch, or successful CORE E2E.
5. A GitHub Actions hosted/Windows job reporting success with a **mocked loopback service** does not prove actual Qwen inference. Real inference requires a Windows/self-hosted evidence run with actual installed Ollama model and raw model reply digest, plus independent attestation.
6. Diagnostic `--diagnose` never invokes generation. `--safe-smoke` creates only its own provider attempt ledger in runner user's home and issues one harmless toy-file request *if* installed model and RAM preflight both pass. A stuck/duplicate reservation blocks future replays.

## Acceptance requests

**CORE (#9)**: confirm input_sha digest definition and idempotent task-ID ownership, sanctioned one-file-path allowlist, trusted in-process handoff, and rules for creating actual isolated file/commit outside PROVIDERS. No integration until independent approval.

**COORDINATOR (#3)**: confirm v1 naming, field types, source-of-truth, approval/review gates and budget allocation. No release or merge implied.

**REVIEW**: independent provenance and negative security check to come from a separate authorized reviewer, not the provider author. This provider's own tests can never approve itself.

## Coordinator MVP compatibility adapter (added 15 October)

Read-only compatibility source: `bridge/neurofactory/coordination/mvp_task_exchange.py` at the coordinator's own candidate branch. **No coordinator source has been modified.**

New PROVIDERS-owned `coordinator_adapter.py` accepts one strict JSON envelope with `schema=neurofactory.providers.coordinator_pair.v1`, exact nested `proposal` fields defined by COORDINATOR (task_id, project_id, target, objective, source_sha, source_sha256, model, reserved_units) and exact nested `prepared_request` fields (task_id, source_sha, model, budget_units, local_only, purpose).

- Correlates immutable task ID, full input Git SHA, input SHA256, exact approved model, one bounded resource reservation, and the coordinator-approved `CORE_SANDBOX_PROPOSAL` purpose.
- Accepts coordinator `NF-DEV-05-Qxxx` task IDs and **only** paths in `bridge/neurofactory/development/core_owned/` for this special route. The alternate standalone `src/` and `docs/` paths are not admitted by the coordinator bridge.
- Rejects any key duplication, foreign target, mismatched source revision, unexpected field, insufficient estimated resource reservation, paid/unknown model or apparent JSON approval.
- Maps an **unverified actual local model proposal** to COORDINATOR's current seven-field `RESULT_FIELDS` record (`task_id/source_sha/model/text/local_only/published/mode`) after validating proposed file digest, exact model/task/source, required observed-local-response digest and non-publication markers.
- Does not write project files, claim CORE tasks, possess credentials for approval, prove model identity independently, or authorize a release. Its `text` field contains the **untrusted proposed file content**, and COORDINATOR computes a new digest of that text (not necessarily the full raw model JSON digest).

**Pending explicit agreement:** CORE #9 must authorize exact task/source/target and provide the authenticated lease + sandbox writer; COORDINATOR #3 must confirm the two-layer payload binding and interpretation of the text digest. A `trusted_core_call=True` opt-in in the older PROVIDERS entrypoint is not itself authentication and may not be exposed directly as a public endpoint.

This bridge was tested with offline fabricated inputs only; hosted focused Linux/Windows tests are author-owned, not an independent origin or live inference proof.

## Updated COORDINATOR wire adapter — current PR #12 candidate

After the first compatibility implementation, the coordinator introduced an additional pure-data adapter at `bridge/neurofactory/coordination/mvp_provider_wire.py` (read-only source blob `f9a59efaf598fcc064fba51886b0776aab17d2f0`). PROVIDERS now supports **both** historical `proposal+prepared_request` preview and the newer `neurofactory.coordination.provider_bridge.v1` preview without changing any coordinator-owned file.

The **newer** read-only packet has exactly four top-level fields:

- `schema` (fixed coordinator-wire version)
- `request` (exact provider request v1: schema, task_id, project_id, input_sha256, target_path, instruction)
- `binding` (task_id, project_id, source_sha, source_sha256, core_target, provider_target, model, input_sha256)
- `permissions` (execution=false, retry=false, publication=false, paid_api=false; no extra fields)

`parse_new_coordinator_wire(..., trusted_budget_units=...)` checks strict JSON including duplicate-key rejection, exact source/task/model correlation, CORE-approved path namespace versus separate `src/` or `docs/` provider proposal path, and a bounded reservation amount provided **separately by a trusted CORE host**. The wire packet itself grants **no execution permission**. No local/remote model is invoked or file written by this parser.

The coordinator's `summarize_reply(packet, result)` accepts the **full** PROVIDERS result shape, not the older seven-field `record_provider_result` envelope. The full result returned by `execute_one` is the candidate for independent correlation; `coordinator_result` is retained only for the older pure-data exchange. The model proposal itself remains unverified, and permissions stay false.

**Unresolved before integration:** COORDINATOR #3 must explicitly select the canonical packet and approve mapping semantics; CORE #9 must provide authenticated task approval, exact file mapping, durable lease and separately trusted resource budget. This provider module does not verify identities or turn coordinator `permissions.execution=false` into true. Windows has an installed Ollama executable and Qwen manifest(s) but current Windows RAM is insufficient; no real Qwen result exists.

## Локальная запись доказательств ответа (кандидат PROVIDERS, 15.10.2026)

В `evidence_receipt.py` и `ollama_worker.py` добавлен **опциональный** локальный журнал фактического ответа. Это не утверждение о выполненном Qwen-запросе: на текущем Windows-хосте RAM по последнему разрешённому наблюдению **934338560 байт (<2 GiB)**, Ollama process отсутствовал, ни одной генерации не было.

- Вызов `execute_one` с `evidence_dir` требует заранее существующий доверенный каталог, без symlink; на POSIX с ограниченными правами (0700). Windows ACL и происхождение пути обязан отдельно проверить доверенный хост. По умолчанию CORE-интерфейс `execute_one` не меняет протокол результатов и не выводит сырой текст. Для будущей live-приёмки владелец CORE должен **потребовать** обязательный evidence_dir, а не обходить запись.
- После ровно одного разрешённого Ollama-вызова, **до** принятия предложения файла, провайдер создаёт ровно один локальный файл с именем SHA-256 устойчивого task_id. Запись exclusive/no-overwrite с `fsync` и readback, и отдельными SHA-256 входного снимка, финального prompt, точного **текстового поля ответа модели** и байтов квитанции. Сохраняются модель, UTC timestamp, измеренный период, исходный текст ответа для будущей независимой проверки, флаги `review_approved=false`, `source_applied=false`, `published=false`.
- В этой версии квитанция **не** содержит полного HTTP-JSON Ollama, а только точный текст `response` после проверки ответа адаптером. Отметка `transport_claim=ollama-ipv4-loopback` — **самоутверждение локального процесса**, не криптографическое происхождение модели. Файл не обладает независимой подписью и может быть изменён владельцем машины, хотя процедура readback позволяет обнаружить изменения относительно сохранённого вне машины SHA-256.
- Повторная запись того же task_id отклоняется; повреждённая или частично записанная квитанция НЕ автоматически восстанавливается. При неопределённой записи после получения ответа возвращается `UNKNOWN_EVIDENCE_WRITE`, а устойчивая резервация задания сохраняется: **ни при каких обстоятельствах не повторять генерацию автоматически**.
- Файлы со сырым текстом держать локально в приватном каталоге PROVIDERS; запрещена автоматическая выгрузка содержимого в GitHub Actions, комментарии Issues или публичные артефакты. В логе одноразового локального smoke разрешены только SHA, task ID, тайминг, модель и имя квитанции без сырого текста; независимый reviewer отдельно получает копию из разрешённого источника.
- Для CLI безопасного дымового теста теперь **обязателен** новый явный `--task-id`; постоянный ID предыдущего smoke исключён из нового кода. Ранее существовавшие Windows workflow с привязкой к старому SHA не считаются пригодными доказательствами для этого механизма и не будут заново запущены, пока RAM и Ollama не подтверждены READY.

**Только адресные author-owned offline тесты**: GitHub Actions run [38653360508](https://github.com/DSLitvinov1/my_first_repo/actions/runs/38653360508), exact code/test SHA `c6a933e7d9e92d29f5bf8ca1a14d90473e9c48de`, Ubuntu 14/14 PASS, Windows 13 PASS + 1 POSIX-only SKIP, Python 3.11. Использована подмена сетевого ответа — НЕ настоящая Qwen и НЕ независимый audit. Исторические 71+ тестов не повторялись.

До разрешения координатора и независимого REVIEW: `BLOCKED_RESOURCE` / CORE integration blocked / paid API 0 / HANDOFF paused / model calls 0 / публикаций 0.
