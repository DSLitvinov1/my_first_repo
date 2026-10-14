# PROVIDERS ↔ CORE — proposed request/result contract v1 (2026-10-15)

**Status: CANDIDATE, not integrated or approved.** Owner: PROVIDERS #5. Coordination reference: `bridge/neurofactory/coordination/MVP_READ_ONLY_INTERFACE_CONTRACT_20261015_RU.md` in the COORDINATOR branch. This contract is a proposal for coordinator (#3) and CORE (#9) agreement, **not** authority to alter their code.

## Input from a trusted CORE caller

JSON object, exact mandatory fields, all other keys rejected:
- `schema`: literal `neurofactory.providers.request.v1`
- `task_id`: stable, unique, never re-used within a provider ledger; safe identifier (max 64 chars)
- `project_id`: approved sandbox project identifier (max 64 chars)
- `input_sha256`: 64 lowercase hex bytes digest of trusted task/input snapshot, provided by CORE
- `target_path`: approved relative path under `src/` or `docs/`, extensions `.py`, `.md`, `.txt`, `.json`, no hidden/traversal/absolute components
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
