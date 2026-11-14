# Oleg websites — indexability remediation checkpoint

Evidence: OpenSEO completed crawls dated 2026-11-14. This file is a preparation checkpoint, **not** a claim that production changes or webmaster submissions were made.

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
- Production changes, sitemap submissions, and post-deployment checks: **NOT DONE**. Do not represent these as done.
