# Oleg Legal — Chrome + Desktop Commander + Playwright QA checkpoint
Date: 18.11.2026 (Moscow); continuation after V25 `LIVE_VERIFIED`.

## Workstation and tool recovery
- Target: `WIN-LIDC05TBOQD`, Windows Chrome, Desktop Commander remote agent online.
- Desktop Commander command execution recovered spontaneously (read-only `whoami` / diagnostics and scripts executed); it was **not** necessary to restart Chrome or the remote agent.
- Chrome CDP listeners `127.0.0.1:9222` and `:9333` reachable. Existing browser Playwright package found in local npm cache. Playwright `connectOverCDP(:9222)` **PASS** (1 context, 1 page), but creation of a new isolated page **failed**: `Target crashed`. On `:9333`, Playwright reached the WebSocket but context enumeration timed out; the full Playwright E2E suite therefore **cannot be called PASS**.
- Read-only local diagnostics at checkpoint: RAM ~5.6 GiB, free ~472 MiB; 62 Chrome processes totaling ~2.67 GB working set. Resource pressure **possible, not proven root cause**. User browser processes and existing profiles were not killed.
- For the remaining readback and interactive checks used Chrome's **native local CDP page endpoints via Desktop Commander**; this is direct Chrome control, not successful Playwright E2E.

## Live V25 Chrome QA: both legal domains
- Reused previously open *QA form tabs* in authorized Chrome, navigated temporarily to each public site with `utm_source=qa_chrome_1811&utm_medium=organic&utm_campaign=v25_analytics_acceptance&phone=SHOULD_NOT_TRANSFER`, then restored original QA form URL. No CRM submits or other POST actions.
- Pages actually rendered in Chrome, legal assistant toggle found, each correct domain-specific Bitrix24 form link present:
  - `potrebpravo.ru` -> `crm_form_fhi3n`; Metrika counter `114249897`.
  - `semya-yurist.ru` -> `crm_form_ep5fd`; Metrika counter `114251443`.
- Chrome consent run performed per domain:
  - Fresh/no consent: `__olegAnalyticsStarted=false`, `typeof ym=undefined`; consent allow and deny controls visible.
  - Explicit deny: saved consent `no`; `__olegAnalyticsStarted=false`; `ym` remains undefined. For family site the browser's `performance` Yandex-resource list was empty after denial.
  - Explicit allow: saved consent `yes`, `__olegAnalyticsStarted=true`, `ym=function`.
  - Spy-wrapper forwarded calls to the original `ym` function. After assistant toggle and a non-navigating CRM-link click: exact `reachGoal` calls observed for `oleg_consultation_open` and `oleg_crm_form_open`, with the correct per-domain counter on **both sites**.
  - CRM direct link includes exactly allowed UTM values and does **not** include the deliberately supplied `phone` query value.
- Tests were **real Chrome DOM/UI handlers**, not mocked Yandex function calls, but **Yandex backend receipt and Metrika dashboard conversion count remain unverified** because CDP Network.enable timed out and there was no authenticated analytics report confirmation.
- Consent value was restored after each test; both original QA-form tabs restored. No `lead_success` was emitted, and no Bitrix POST submitted.

## Bitrix24 authenticated UI: real historical data but detail readback blocked
- Chrome `:9333` was authenticated to `b24-xlzm11.bitrix24.ru`; direct CDP readback obtained the real deal automation list (not a simulated page).
- Six old deal links found: `#12, #10, #8, #6, #4, #2`. #12 = Family CRM form, #10 = Consumer CRM form; list names `Олег Лёвин` as responsible. Existing source is generic `Прочий трафик / Сайт24 / CRM-форма`; it cannot prove new V25 UTM persistence.
- Direct navigation to `/crm/deal/details/10/` and `/crm/deal/details/12/` showed only partial loading shells (roughly 365–421 characters). Clicking the real deal links on the automation page opened same-origin Bitrix sidepanel iframes, but each also contained only partial shell (375/365 characters) without source/UTM/notification fields. The alternative `/crm/deal/list/` view also remained in a short loading shell. All test-opened #10/#12 sliders explicitly closed, parent tab restored.
- **No independent CRM detail readback**, no newly verified two deal IDs, no proof that Oleg personally received push/email. The previously pending Mail.ru OAuth owner authorization remains unresolved.
- **No new synthetic submissions**, because the evidence gate preventing duplicate/unverifiable CRM test records remains unmet.

## Decisions and next gate
1. Treat Chrome site launch, UTM allowlisting, consent gating and two client-side Metrika goal-invocation pairs as live QA **PASS**, with no claim of server-acknowledged goals.
2. Diagnose CRM details SPA/iframe boot failure inside authenticated Chrome (system resource pressure and Bitrix CDN availability are candidates, not proven causes). Re-test readback without losing the owner session.
3. Only once detail/UTM readback is reliable, submit **at most one** uniquely identified test application per domain; verify in CRM the new deal ID, source, all UTM, responsible Oleg, and delivery of notification. No blind retries.
4. Keep V25 production unchanged, PR #125 draft/unmerged, Yandex Direct OFF.
