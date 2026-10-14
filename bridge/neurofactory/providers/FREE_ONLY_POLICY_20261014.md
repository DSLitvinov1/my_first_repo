# PROVIDERS / Free-only provider policy (research snapshot 2026-10-14)

The only enabled-capable implementation in this candidate is LOCAL QWEN via Ollama at `http://127.0.0.1:11434/api/generate`; adapter is disabled by default, contains no API credentials, cloud endpoint, remote delivery, queue or publisher.

## Primary official sources and verdicts
- DeepSeek official API pricing: https://api-docs.deepseek.com/quick_start/pricing/ . API requests are token-billed, from granted or topped-up balance. Balance endpoint https://api-docs.deepseek.com/api/get-user-balance/ is not sufficient to prove an absolute no-charge request, so **no production DeepSeek API adapter**. Free web chat does not authorize API automation.
- Claude official API pricing: https://platform.claude.com/docs/en/about-claude/pricing . Anthropic may grant a small new-account trial; credit expiry, eligibility, and billing are account-specific. Official subscription separation: https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-is-claude-api-usage-billed-separately-from-my-paid-claude-plan . **No production Claude API adapter**. This project has not checked an account's actual credits.
- Qwen Alibaba Model Studio quota: https://www.alibabacloud.com/help/en/model-studio/new-free-quota and https://www.alibabacloud.com/help/en/model-studio/model-usage-statistics . Singapore/International model-scoped 90-day promotional quota may exist. **Free Quota Only** must be activated in the user's console; it is disabled by default and the account's current setting/remaining entitlement has not been verified. **No production Model Studio API adapter**.
- Qwen open local models official: https://qwenlm.github.io/blog/qwen3/ . Apache-2.0 Qwen3-0.6B/4B open weights support local inference, with no cloud inference API charge. Ollama official local API reference: https://github.com/ollama/ollama/blob/main/docs/api.md . Local runtime, memory, bandwidth for optional download, and electricity may carry non-API costs.
- Official Alibaba per-token prices: https://www.alibabacloud.com/help/en/model-studio/model-pricing . Default is pay-as-you-go; pricing promotions or chat availability are **not** a zero-spend control.

## Hard stops and intentional exclusions
1. API costs: no remote DeepSeek, Claude or Alibaba inference calls, no API keys or billing accounts in this candidate; observed API spend through this code is zero by construction.
2. Ollama interface: a literal IPv4 loopback address and only three named local Qwen models; HTTP proxy disabled; redirects blocked; no automatic pulls or cloud model aliases.
3. Request guards: disabled until explicitly enabled in a containing application; maximum output/token window, timeout, prompt length, per-process attempt/reservation cap; no automatic retry of ambiguous transport outcomes.
4. Response guards: complete answer required, exact model match, invalid and duplicate-key JSON rejected, reply byte limit.
5. Fallback: ONLY mock Claude `QuotaExhausted` to local Qwen; auth, timeout, unknown errors stop; **no real Claude quota-monitoring** implemented. A real Claude -> Qwen automatic handoff is not approved or claimed.
6. No scheduler, main-branch changes, GitHub Actions dispatch, global jobs, live tasks, merge or production switch.

## Evidence and limitations
- Local Linux standard-library unittest: 29/29 PASS, including a local loopback HTTP stub and concurrency/error simulations.
- Local syntax compileall PASS.
- Each submitted source and test blob was read back and its Git blob SHA matched the files actually used in tests.
- Tested pre-existing `offline_router.py` blob: `4d2df763743152237c737f8dbfe5ec520af6907e`.
- New source blob (local_qwen.py): `cb202c072c3aa353144547e21a22f6752645e0cc`.
- New controller blob: `47422baebf978532f1b09fe387e97c30ddeafbef`.
- New test blob: `1792db6f744c7f06e539665273baba5f3b82e41a`.
- This is **not** a Qwen model inference test, not a Windows validation, not independent REVIEW, not a durable process-restart budget, and not a release approval.
- Cloud API availability, actual account balance and Alibaba's Free Quota Only setting remain UNKNOWN. Any request for live paid-backed API must remain BLOCKED.

## Independent reviewer acceptance checklist
Use the **exact final commit** and corresponding file blobs; independently rerun Python test suite on Linux and Windows, verify no network egress except explicit IPv4 loopback, force proxy/redirect/duplicate-JSON/unknown-transport failures, test concurrent reservations, task replay, model spoofing, truncated output, installed-model absence, and read-only source ownership. Confirm no source outside `bridge/neurofactory/providers/`, no secrets, no billable APIs, and no external queue coupling. Record an independent verdict; do not merge or activate before coordinator review.
