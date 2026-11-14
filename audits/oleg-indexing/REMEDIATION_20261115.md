# Oleg websites — indexability remediation checkpoint

Evidence: OpenSEO early-2026-11-14 completed crawls. **These crawls predate subsequent verified same-day server edits.** This file is a preparation checkpoint and does not claim that new production changes were made in this turn.

## Confirmed

### semya-yurist.ru

- Crawl: 21 pages, 21 returned HTTP 200. 19 technically indexable. 18 indexable candidates in sitemap.
- Intentional exclusions: https://semya-yurist.ru/consent.html, https://semya-yurist.ru/privacy.html.
- /index.html is canonicalized to /; confirm 301 redirect before altering (not necessarily an urgent indexing defect).
- Issue summary: thin-content=4; meta-description-too-long=5; title-too-long=4; meta-description-too-short=3; noindex-page=2; canonicalized-page=1.
- Google Search Console: no account is connected in this OpenSEO project. Submission and Google index coverage unverified.

### URLs requiring content or metadata review

- **thin-content**: https://semya-yurist.ru/practice/cases/family-alimony-appeal.html — 116 words
- **thin-content**: https://semya-yurist.ru/practice/cases/family-alimony-cassation.html — 129 words
- **thin-content**: https://semya-yurist.ru/practice/cases/family-divorce-public-example.html — 111 words
- **thin-content**: https://semya-yurist.ru/practice/cases/family-invalid-marriage.html — 114 words
- **meta-description-too-long**: https://semya-yurist.ru/
- **meta-description-too-long**: https://semya-yurist.ru/index.html
- **meta-description-too-long**: https://semya-yurist.ru/specialists/levin-oleg.html
- **meta-description-too-long**: https://semya-yurist.ru/specialists/nikolaeva-alena.html
- **meta-description-too-long**: https://semya-yurist.ru/specialists/obyknovennova-yulia.html
- **meta-description-too-short**: https://semya-yurist.ru/practice/cases/family-divorce-public-example.html
- **meta-description-too-short**: https://semya-yurist.ru/practice/cases/family-invalid-marriage.html
- **meta-description-too-short**: https://semya-yurist.ru/practice/index.html
- **title-too-long**: https://semya-yurist.ru/practice/cases/family-divorce-public-example.html
- **title-too-long**: https://semya-yurist.ru/services/alimenty.html
- **title-too-long**: https://semya-yurist.ru/services/razdel-imushchestva.html
- **title-too-long**: https://semya-yurist.ru/services/razvod.html

### potrebpravo.ru

- Crawl: 26 pages, 26 returned HTTP 200. 24 technically indexable. 23 indexable candidates in sitemap.
- Intentional exclusions: https://potrebpravo.ru/consent.html, https://potrebpravo.ru/privacy.html.
- /index.html is canonicalized to /; confirm 301 redirect before altering (not necessarily an urgent indexing defect).
- Issue summary: thin-content=9; duplicate-meta-description=5; title-too-long=10; noindex-page=2; meta-description-too-short=2; canonicalized-page=1.
- Google Search Console: no account is connected in this OpenSEO project. Submission and Google index coverage unverified.

### URLs requiring content or metadata review

- **duplicate-meta-description**: https://potrebpravo.ru/practice/cases/developer-four.html
- **duplicate-meta-description**: https://potrebpravo.ru/practice/cases/developer-one.html
- **duplicate-meta-description**: https://potrebpravo.ru/practice/cases/developer-three.html
- **duplicate-meta-description**: https://potrebpravo.ru/practice/cases/developer-two.html
- **duplicate-meta-description**: https://potrebpravo.ru/practice/cases/zpp-staircase.html
- **thin-content**: https://potrebpravo.ru/practice/cases/consumer-refunded.html — 120 words
- **thin-content**: https://potrebpravo.ru/practice/cases/developer-four.html — 124 words
- **thin-content**: https://potrebpravo.ru/practice/cases/developer-one.html — 120 words
- **thin-content**: https://potrebpravo.ru/practice/cases/developer-three.html — 123 words
- **thin-content**: https://potrebpravo.ru/practice/cases/developer-two.html — 116 words
- **thin-content**: https://potrebpravo.ru/practice/cases/rental-dispute.html — 122 words
- **thin-content**: https://potrebpravo.ru/practice/cases/rental-money.html — 115 words
- **thin-content**: https://potrebpravo.ru/practice/cases/traffic-accident.html — 115 words
- **thin-content**: https://potrebpravo.ru/practice/cases/zpp-staircase.html — 122 words
- **meta-description-too-short**: https://potrebpravo.ru/practice/cases/rental-money.html
- **meta-description-too-short**: https://potrebpravo.ru/practice/index.html
- **title-too-long**: https://potrebpravo.ru/
- **title-too-long**: https://potrebpravo.ru/index.html
- **title-too-long**: https://potrebpravo.ru/practice/cases/developer-four.html
- **title-too-long**: https://potrebpravo.ru/practice/cases/developer-one.html
- **title-too-long**: https://potrebpravo.ru/practice/cases/developer-three.html
- **title-too-long**: https://potrebpravo.ru/practice/cases/developer-two.html
- **title-too-long**: https://potrebpravo.ru/practice/cases/traffic-accident.html
- **title-too-long**: https://potrebpravo.ru/practice/cases/zpp-staircase.html
- **title-too-long**: https://potrebpravo.ru/privacy.html
- **title-too-long**: https://potrebpravo.ru/services/vozvrat-deneg.html

## Prior verified actions (2026-11-14, separate session)

- All five duplicate meta descriptions detected in the early crawl on **potrebpravo.ru** were already edited and HTTP-checked in production later on 2026-11-14. Treat the old audit findings as stale until a fresh crawl verifies them. Do not reapply blindly.
- Seven main URLs for each site were submitted to Yandex Webmaster Reindex; status was **queued**, not indexed. Do not submit duplicates unnecessarily.
- Both sites had accessible sitemap files referenced in robots.txt. Yandex Webmaster reportedly had a temporary sitemap-submission read-only outage. Google Search Console properties remained unverified.
- Existing backups at Timeweb are recorded in `Oleg_status_2026-11-14.md` in the user's Library; check their current existence on hosting before any further deployment.
- Fresh post-edit read-only OpenSEO audits were started 2026-11-15 local date: semya `90c3b32e-b295-40ac-af86-61272c769fe1`; potreb `2fe561ef-f8c5-46c3-9ac5-6bcaf7cc483e`. Do not mark them complete before fetching status and issues.

## Remediation and release gates

1. Keep legal privacy/consent pages noindex; they should not be indexed or in sitemap.
2. Expand 13 thin legal-case summaries ONLY from verified court document content: court/date (if verified), factual background, claims, legal reasoning, result, practical significance. No invented cases, no disclosure of client personal data.
3. Make the five consumer-law case meta descriptions unique and relevant to each case; review longer/shorter titles and meta descriptions. Search snippets may differ from tags.
4. After backup and read-only diff of production site files, apply a minimal metadata/content patch in a change-controlled deployment; avoid rebuilding the sites.
5. Validate HTTP→HTTPS and www canonical redirects; check /index.html canonical and consider a permanent redirect to / if compatible with navigation.
6. Re-crawl both live sites, compare issue counts and request logs; submit their actual sitemap URLs to Yandex Webmaster and Google Search Console under verified owner permissions.
7. Check actual search index coverage only from verified Webmaster/GSC accounts; technical eligibility does not equal inclusion.

## Blockers and current evidence gaps

- Current remote computer connector reports that monthly usage is exhausted. No production hosting read/write access in this turn.
- Browser connector is read-only for the available Yandex tab; no authorized browser submission action is available.
- OpenSEO GSC account lists are empty for both projects.
- GitHub Action Playwright scan was committed on branch; actual workflow execution and results have not been confirmed.
- New production changes in this turn: **NOT DONE** (prior 2026-11-14 metadata fixes and Yandex reindex submissions are described above). New sitemap submissions and Google submissions: **NOT DONE**. Post-fix crawl: **RUNNING**.

## Full-sitemap Playwright verification — 2026-11-15 (completed)

- CI: [GitHub Actions #43650559048](https://github.com/DSLitvinov1/my_first_repo/actions/runs/43650559048), branch head `3c4f66c173ce7a6a27cf285d06b396e5f2e3dadf`, **PASS**. Full sitemap audit is `audits/oleg-indexing/audit.cjs`.
- `potrebpravo.ru`: `robots.txt` 200, `sitemap.xml` 200, 23/23 canonical sitemap URLs loaded with HTTP 200, 0 technical critical issues, 16 advisory warnings (mostly brief case summaries and some long titles). The 3 extra discovered internal URLs were reachable.
- `semya-yurist.ru`: `robots.txt` 200, `sitemap.xml` 200, 18/18 canonical sitemap URLs loaded with HTTP 200, 0 technical critical issues, 9 advisory warnings (brief case summaries and some long titles). The 3 extra discovered internal URLs were reachable.
- Bot restrictions for `*`, Googlebot, Yandex root /: no global root disallow was flagged; no `noindex` among the 41 sitemap pages; canonicals all matched their URL; duplicate sitemap URLs, duplicate titles/descriptions, and orphan sitemap URLs were not flagged.
- 41/41 sitemap URLs are **technically crawlable**, not proof of inclusion in either engine's search index.
- Existing privacy/consent pages outside sitemap are intentionally noindex: 2 per site, verified by the full OpenSEO crawl earlier the same day.
- Last known Yandex state: 7 URLs each placed in reindex queue on 2026-11-14. Verify actual indexing from Yandex Webmaster after robot revisit. Separate sitemap/metric-counter submissions **not confirmed**.
- Google Search Console connection through OpenSEO was explicitly tested on both properties and returned `not_connected`; no Google index coverage or indexing submission is authorized from the connected accounts.
- Potential Yandex boost: bind each verified Webmaster site to its Yandex Metrica counter and enable 'Обход по счётчикам' **after verifying installation/owner authorization**. Official: https://yandex.ru/support/metrica/ru/general/link-webmaster . Nothing has been changed in the Webmaster/Metric settings in this turn.
- Do not publish a claim of full indexing, merge the draft PR, or execute metadata updates until hosting access, source guard/diff and rollback are verified.

## IndexNow attempt — 2026-11-15

- A free OpenSEO IndexNow notification was attempted for **five genuinely updated** consumer-law case metadata pages (2026-11-14 edits). Result: **FAILED — key file not found on host**; there is no proof of submission to Yandex/Bing or other participants.
- OpenSEO generated a public verification key. The exact file is staged in the isolated PR under `audits/oleg-indexing/staged-host-files/potrebpravo.ru/57b3c551867d47f49d6d76567e5485df.txt`, containing only its filename stem.
- To complete (requires authorized Timeweb write): publish it as `https://potrebpravo.ru/57b3c551867d47f49d6d76567e5485df.txt`, verify `HTTP 200` and the exact body, then retry the **same five changed pages** with OpenSEO IndexNow. Do not claim the notification was accepted until host status is `submitted`.
- Do not deploy this file anywhere else or change existing site code merely to force indexation.

## Owner browser follow-up — 2026-11-15

- Browser tab enumeration **succeeded** from the connected extension for the user's Oleg browser session.
- Read-only inspection of the authenticated **semya-yurist.ru Yandex Webmaster reindex** page succeeded: it explicitly lists **seven URLs, each status `В очереди`**, all submitted **2026-11-14 13:24**. No subsequent indexing is confirmed; no duplicate reindex submission was made.
- Reads of other relevant open browser tabs (potrebpravo.ru Yandex Webmaster pages, Yandex Metrica, and Google Search Console) were denied by the connected browser extension's **host permission gate**. The browser action provides no authorization to click or submit.
- The currently open Google Search Console tab is tied to `sc-domain:rentabkhazia.ru`, not Oleg's two domains, and cannot establish that either Oleg property is verified.
- OpenSEO reconfirmed `accounts: []` for Google Search Console on **both** Oleg projects; no site inspection or new Google submission possible through that connection.
- Public `site:` search attempts yielded no useful search results and cannot establish zero pages indexed; do not infer indexed counts from them.
- Next permitted step depends on owner/browser host granting access for `webmaster.yandex.ru`, `metrika.yandex.ru`, and `search.google.com` in an authorized interactive session or on a properly connected Search Console account. Do not attempt browser-host bypass, raw CDP, credential/cookie extraction, or cross-browser workarounds.
- Previously verified full sitemap **41/41 HTTP 200** and Playwright operator simulated UI tests **PASS** (GitHub Actions #43652024913). The local operator is **not** a completed authenticated production submission.
- No production files or search console settings were modified in this follow-up. Yandex Direct not touched.
