# ONE Agent — SEO/GEO, CRM, browser tabs and ChatGPT control
Status checkpoint: 2026-11-14. This is an extension of the existing Work ONE code; do not recreate it.

## User intent

A Russian-language single-agent assistant that can understand the user's goal and, under project-scoped grants, work through browsers and tabs, Bitrix24, Yandex Metrica, Yandex Webmaster, Google Search Console, Yandex Direct, and coordinate SEO/GEO activities; receive commands from ChatGPT and return verified results.

## Confirmed inherited state

- Existing ONE UI, CORE/HOST separation, Qwen 3.5 9B proposal stage, restricted Windows desktop worker and private services remain untouched.
- Last physically installed Windows build: `b9fcd4337f0f76cca0bcbb41c150e9cfe2582cc8` (PR #121); newer PR #122 changes are not physically accepted on the owner's computer.
- Current development branch starts from PR #122 head `5f69be7ff06add545134f1cd368f5bf5096bb069`.
- Desktop Commander has hit the current-month quota, so direct Windows update or live acceptance is impossible this session. Keep the installation unchanged.

## New code in this branch

### Browser tabs

- Isolated, non-persistent Chromium only; same approved HTTPS origin, up to four concurrent tabs and 16 created tabs per session.
- Owner/project-bound tab IDs; new/switch/close/list tab API and UI.
- Form submissions, password entry, arbitrary system commands, redirects to other origins and nonapproved network requests remain blocked.
- This is **not** access to the user's existing authenticated Chrome profile or other opened browsers.

### Search Console

- New Google OAuth permission `webmasters.readonly` via per-Windows-user DPAPI vault.
- Read available Google properties and top 25 queries over 28 completed days, with permission and response limits. No site changes.
- Requires owner OAuth Desktop client configuration and explicit account consent; not exercised on a live account.

### Yandex Metrica and Webmaster

- Owner-supplied, separately authorized Yandex OAuth tokens, stored with Windows DPAPI, one read-only scope for each service.
- Read counter list, 28-day visit/user/pageview totals; read Webmaster site list and verified site's indexation summary.
- Read-only API methods and validated resource ownership; no Yandex Direct authentication or write support. Live tokens are not connected.

### Bitrix24 CRM read-only view

- Existing dedicated CRM OAuth token path is reused; no CRM read is allowed through only a task token.
- A new fixed-schema method reads at most the latest 50 lead/deal records to show stage/category/source/date and total, with no names or contact details.
- No create/update/delete CRM actions were added; real portal OAuth and read-only acceptance remain pending.

## Remaining implementation and physical acceptance (not represented as complete)

1. **Browser and tab live E2E:** test actual Chromium on Windows owner session, label matching, cookies and safety boundaries; authorization to work with existing Chrome tabs requires dedicated extension/browser pairing with explicit tab and site grants, not copying cookies or passwords.
2. **Bitrix24 CRM:** finish real CRM-permission OAuth, per-project portal mapping and dedicated sandbox read-back for new lead/deal list; reserve writes for explicit approved operations.
3. **Yandex Metrica/Webmaster:** get owner consent, verify read-only endpoints, handle OAuth renewal/revoke; test real counters and host reports; honor service quotas and API policy.
4. **Google Search Console:** owner OAuth consent, verify property list and query data on a user-granted property, add delta comparisons and privacy-preserving reporting.
5. **Yandex Direct:** register and obtain separate API application approval, read campaigns and spend first; draft campaigns without publishing; budget limits, second confirmation and post-change verification before any ad writes. **Never launch advertising silently.**
6. **SEO and GEO workflow:** cross-source project dashboard, technical crawl/HTTP diagnostics, sitemap/indexability/metadata/internal links, competitor/public SERP checks, content briefs, schema/FAQ where applicable, observability of AI mentions and citations. Don't claim a guaranteed AI recommendation or search ranking.
7. **ChatGPT command transport:** custom connector/MCP via authenticated broker and explicit account pairing to local host, dedicated token scopes, signed jobs, task-ID+approval, replay prevention, user-visible steps, audit receipts, restricted egress; model output remains data, never an automatic command. Expose read-only status/reporting first; separately reviewed and approved writes later.
8. **Reliability:** tests for per-project isolation, malicious web prompt instructions, network failures, API expiry, retries/no-repeat, role boundaries, token revocation and rollback. Preserve old verified installation and create a backup before any upgrade.

## Delivery rules

- Never publish Yandex Direct campaigns or spend money from a read-only audit.
- No unverified third-party account access, unapproved CRM writes, deletion, paid action, or security-grant escalation.
- Reports must differentiate *implemented*, *unit-tested*, *connected*, *real-account verified*, *deployed*, and *production-verified*.
- This branch is for review and CI, not automatic merge into CORE/production or physical Windows upgrade.
