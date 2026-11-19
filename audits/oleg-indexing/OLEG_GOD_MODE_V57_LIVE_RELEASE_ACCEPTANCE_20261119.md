# OLEG LEGAL — GOD MODE V57 | verified SEO Release A published 2026-11-19

## Verdict: RELEASE A = LIVE_VERIFIED ON BOTH PRODUCTION SITES

This checkpoint documents **real Timeweb production execution**, not only an isolated build.

### Production, release and sources

- Consumer: https://potrebpravo.ru
- Family law: https://semya-yurist.ru
- Timeweb account `cl664853`, host `vh460.timeweb.ru`, home `/home/c/cl664853`
- GitHub `DSLitvinov1/my_first_repo`, audit branch `oleg-site-public-link-qa-20261119`
- Release script: `audits/oleg-indexing/v55_timeweb_atomic_release.py` (previously committed as `4656189478b84c342c4377dc6af490a8c30d4a2e`)
- Release manifest `.private-v55-offline/v55-release-manifest.json` on Linux
- Release archive `.private-v54-offline/v54-release-a-full-168-v25-to-v53-20261119.tar.gz`; SHA256 **`61cdd5902f389863adb53385a1e3cbd224c9e348be388a54012cb096aec7aa1b`**
- 168 files (87 consumer, 81 family) and **53 changed files** relative to V25.
- Production journal: `/home/c/cl664853/.oleg-seo-ops/v55-release-a/release-state.json`
- Journal version: `v55-release-a-20261119`, phase: **`LIVE_VERIFIED`**; the previous V25 journal remains at `.../.oleg-seo-ops/v25-utm/release-state.json`.

### Authorization and secure preflight

The user approved using the **pre-existing project SSH identity** from the dedicated Linux agent. Authorized batch SSH confirmed account user `cl664853` and correct home directory. Private key contents were not exposed in chat, saved to GitHub or modified. No bypass of authorization.

On Timeweb, checked remaining storage, original V25 journal and live files. A read-only deployment preflight produced `PREFLIGHT_PASS` with exact 168 files and 53 changes; deployed archive SHA was verified on Timeweb independently.

### Backup — both server and external copy, verified

After preflight and before switching sites, `prepare` created and validated a new **full V25 backup**:

`/home/c/cl664853/.oleg-safe-backups/oleg-managed-daily/v55-oleg-live-20261119T184123Z.tar.gz`

This was copied to a separate protected Linux directory:

`/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118/.private-v57-offline/v55-oleg-live-20261119T184123Z.tar.gz`

SHA256 of BOTH backups: **`4c16747cc120b5d215e33f7c4c8caa9962d134113d03a847fb7e16b55b58831c`**.

Independent Linux inspection: all **168 backup files** matched the exact V25 baseline manifest. This backup is **not** dependent on the provider's earlier troubled backup service.

Previous V25 `public_html.v55-a-prior` trees remain on the server (87 + 81 files), and their SHA values match V25 baseline. **Do not delete the backups or prior trees without a separate retention decision.**

### Actual production publish

Existing guarded manager executed `deploy` on Timeweb after backup validation and staging. Server returned:

`{"state":"LIVE_VERIFIED","http":{"potrebpravo.ru":"PUBLIC_HTTPS_SHA_PASS","semya-yurist.ru":"PUBLIC_HTTPS_SHA_PASS"}}`

Independent read-only Timeweb SHA audit **after deploy** found:

- Consumer live files: 87/87 match target exactly, old V25 rollback 87/87 match baseline.
- Family live files: 81/81 match target exactly, old V25 rollback 81/81 match baseline.

No rollback was triggered. There were no new legal articles in this release; only 53 previously agreed changed files.

### Production HTTP and SEO acceptance

Performed a new read-only HTTPS request audit against all URLs from both LIVE Sitemap files:

- `https://potrebpravo.ru/sitemap.xml`: 23 distinct URLs, response HTTP 200, exact sitemap bytes equal to release artifact.
- `https://semya-yurist.ru/sitemap.xml`: 18 distinct URLs, response HTTP 200, exact sitemap bytes equal to release artifact.
- **41/41 pages PASS**: HTTP 200, exact SHA256 of live HTTP response equal to the intended release candidate, correct HTTPS self-canonical, non-empty Title, Description, exactly one H1. **0 failures.**
- Robots.txt: both domains HTTP 200.
- The service links on published pages use the correct native Bitrix public form host; see below.

Private acceptance evidence: `.private-v57-offline/v57-live-41-page-acceptance.json` (includes per-URL audit).

### Real Chromium production browser regression

New production-only Playwright scripts committed on audit branch:
- `audits/oleg-indexing/v57_live_service_qa.cjs`: **24 cases = 12 services × mobile/desktop, 264/264 checks PASS**. Confirmed visible direct form action, correct unique CRM form per site, no disabled-form text, canonical, exactly one H1, no mobile overflow, assistant/analytics scripts, no client-side JavaScript errors under mocked external calls.
- `audits/oleg-indexing/v57_live_attribution_qa.cjs`: **4 consent scenarios (allow/deny per site), 66/66 checks PASS** using LIVE HTTPS pages. Validated accepted/denied analytics initialization, consent storage, UTM/YCLID on first and internal second page, legal-assistant form links, no forwarding of `phone`, `email` or `token` query values, and the proper isolated Bitrix form for each site. All external analytics calls in this test were mocked; do **not** claim this proves a server-recorded conversion or current Metrika reports.
- `audits/oleg-indexing/v57_live_public_crm_forms_qa.cjs`: **2/2 forms rendered PASS** in live mobile Chromium, both HTTP 200, one visible form, name/phone fields, consent checkbox, submit button. All attempted non-GET requests were *blocked* by the test harness (4 blocked background requests); **0 actual submissions to the CRM**.

Private logs and JSON:
- `.private-v57-offline/v57-live-service-qa.log`, `v57-live-service-qa.json`;
- `.private-v57-offline/v57-live-attribution-qa.log`, `v57-live-attribution-browser-qa.json`;
- `.private-v57-offline/v57-live-public-crm-forms.log`, `v57-live-public-crm-forms.json`.

### Important CRM URL diagnostic correction

An early read-only diagnostic mistakenly tested `https://b24-xlzm11.bitrix24.ru/crm_form_fhi3n/` and `...ep5fd/`: these URLs redirect to Bitrix24 login because `bitrix24.ru` is the **private portal**, not the public form hosting domain.

The production sites in fact link to the **correct** public form URLs previously verified on Nov 17–18:
- Consumer: `https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/`
- Family: `https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/`

Read-only HTTP tests and live Chromium rendering confirmed BOTH public forms HTTP 200 with visible fields and consent. **No production correction was needed.** Original concern was a false alarm in the acceptance probe, not a bug in the published site. Form page titles remain generic, an optional cosmetic issue. **Do not create replacements or switch to the authenticated portal domain.**

### What is NOT yet verified or finished

- The live site→public CRM-form display flow has been confirmed, and prior real marked test deal #20 from consumer was accepted with source/UTM, Oleg task/chat in older report. **No new form submission was generated in this V57 acceptance.**
- **Bitrix24 deal→actual Yandex Metrika confirmed server conversion**: NOT verified. Metrika 114249897 consumer, 114251443 family. Prior read-only official integration pages had limited availability during Yandex maintenance. Do not confuse a goal configured in Metrika with its actual firing and deal linkage.
- **Yandex Webmaster:** last known 7 consumer reindex requests «Заявка обработана», 7 family requests «Ошибка». Index coverage not proven and no resubmission in V57.
- **Google Search Console:** authorized legal property access unverified; no invented index numbers.
- **Release B:** two new articles (service cancellation and division of marital debts) awaiting legal sign-off, not included or published.
- **Yandex Direct:** OFF, no budget spent.

### Next V58 — EXACTLY ONE main priority

**Prove the Bitrix24 CRM deal → correct Metrika conversion and source association for each domain, without duplicating real or test deals.** Start with read-only CRM integration state, verify whether the native Yandex connector is already active and whether data transfer is legally authorized. Reuse evidence of existing marked deals #16, #18, #20; don't install duplicate integrations or export personal data without verified lawful basis. Once actual linked conversion is demonstrated, refine goals for each site and document report evidence. Only after that work on additional Yandex indexing errors and GSC access. Ads remain OFF unless independently authorized.

**Release A production and technical SEO deployment are CLOSED and VERIFIED.** Do not rebuild or republish it unless a reproducible regression is found. Search rankings and indexing are external outcomes and are not promised.
