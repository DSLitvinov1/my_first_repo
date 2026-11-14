# Oleg — authorized Playwright indexing operator

## Purpose
This tool is a **browser UI assistant** for the verified owners of `potrebpravo.ru` and `semya-yurist.ru`. It checks live sitemap integrity before using authenticated Yandex Webmaster and Google Search Console. It never launches Yandex Direct, changes ads, submits unrelated URLs, edits a website, or attempts to export a signed-in Chrome profile.

## Preflight already completed
- Read-only GitHub Actions Playwright full crawl: 23 consumer + 18 family sitemap URLs with HTTP 200, valid canonical and no critical issues. See prior CI report in PR #125.
- Each Sitemap and robots.txt returned HTTP 200.
- Yandex had 7 priority URLs queued for each site on 2026-11-14; this tool **does not duplicate reindex submissions**.
- Search Console was not connected to the available OpenSEO projects.
- **Do not equate submitted sitemaps with indexed URLs.**

## Browser operation
- Install supported Playwright and Chromium on the **owner's authorized desktop**. Browser cookies belong to that desktop and must stay private; do not copy them into GitHub, CI artifacts, messages, or logs.
- In the audit directory run the CLI `node sitemap_operator.mjs --login` to sign into Yandex Webmaster and Search Console in its **dedicated Playwright Chrome profile**. It opens the official site URLs and persists the session only locally; the owner completes MFA on the actual websites.
- `node sitemap_operator.mjs` is a safe **dry-run**. It visits the two domains, checks exact Sitemap URL count, verifies selected domain and property, and reports either existing listing, readiness, or access/selector issues. It does not submit.
- `node sitemap_operator.mjs --apply` explicitly submits only if a matching authenticated property page, a unique Sitemap field, a unique submission button and a public sitemap preflight are confirmed. The result is recorded in `oleg-playwright-operator-report.json` locally. An ambiguous outcome is reported **unconfirmed**, not submitted.
- Browser UI changes and unsupported selectors cause safe refusal. Never weaken account/property guards to force a submission.
- If the page already lists Sitemap, skip resubmission and instead review existing processing details.
- Browser login is separate from the user's existing Chrome or Opera tabs, as Playwright cannot legitimately assume their cookies or browser-debugging connection. If ChatGPT is running in an unconnected mobile conversation, the local operator cannot be invoked here.

## Important limitations
- The full search-index coverage and individual URL inspection statuses have to be read from the corresponding authenticated Webmaster and GSC accounts; the public Playwright crawl cannot verify search engine index inclusion.
- Google asks that Sitemap be submitted at the correct verified property. Google indexing requests have limits; repeated requests do not improve priority.
- Yandex includes sitemap from robots.txt, but explicit Webmaster submission can show processing status; do not duplicate an existing accepted entry.
- No guarantee of full indexing. Improve 13 short court-case summaries only with verified source documents, without inventing legal outcomes.
- Site metadata patch proposal `METADATA_PROPOSALS_20261115.json` is **not deployed**. Apply only after real hosting backup and guarded source diff; test after deployment.
- IndexNow key file is staged separately, not deployed. Current IndexNow request status is failed until HTTP 200 key verification and accepted retry.
- Connected Desktop Commander monthly quota is exhausted; it must not be circumvented via other remoting methods.

## Test state
- GitHub CI tests the Playwright operator **against simulated UI**, no real account submission.
- Run full read-only site audit with `node audit.cjs` on GitHub-hosted runners.
- Run simulated UI tests with `node --test test_sitemap_operator.mjs`.
- Check `.github/workflows/oleg-playwright-indexability.yml` and workflow run status before claiming a test passed.
