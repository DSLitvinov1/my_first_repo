# Yandex Webmaster — Oleg's two websites — 2026-11-15

## Ground truth: production Playwright check

- [PASS public Yandex-specific Playwright run #43704098744](https://github.com/DSLitvinov1/my_first_repo/actions/runs/43704098744). Each site was requested through Chromium with an **emulated YandexBot User-Agent**, not an actual Yandex IP.
- `potrebpravo.ru`: `robots.txt` 200 and declares `https://potrebpravo.ru/sitemap.xml`; Sitemap 200, **23 unique canonical indexable pages**, 23/23 HTTP200, 0 robots/noindex/canonical errors.
- `semya-yurist.ru`: `robots.txt` 200 and declares `https://semya-yurist.ru/sitemap.xml`; Sitemap 200, **18 unique canonical indexable pages**, 18/18 HTTP200, 0 robots/noindex/canonical errors.
- HTTP host and HTTPS www aliases redirect to canonical HTTPS origin on both sites.
- Minor technical duplication: `/index.html` still responds 200 on both sites, with canonical pointing to `/`. Recommend 301 from `/index.html` to `/` **only after inspecting live web server configuration, backing up and checking redirect rules**, with Playwright post-deployment regression. This is not a critical indexing blocker.
- Public robots Sitemap directive is a valid discovery mechanism under Yandex's official guidance: https://yandex.ru/support/webmaster/ru/indexing-options/sitemap

## Search console facts, distinct from public eligibility

- 2026-11-14: seven priority HTML URLs per domain had already been submitted for Yandex reindex, not confirmed included in search.
- A prior authorized read-only view of the family `Переобход страниц` table showed seven queued entries (`В очереди`). Do not repeat priority submissions blindly or waste daily quota.
- Today Browser list_tabs confirms the target Oleg Webmaster tabs open for `semya-yurist.ru` reindex and `potrebpravo.ru` searchable URLs; however **get_tab_context** for each Webmaster page fails with browser extension **manifest host-permission** error. The Chat/Browser plugin has no browser-control action.
- Live Yandex Webmaster property verification details, Sitemap processing status (`OK`, `В очереди`, `Ошибка`), indexed URL totals, excluded page reasons, crawler problems, and region are **not read**, and cannot be fabricated.
- Official help: Sitemap can be discovered via robots or added in Webmaster; processing may take up to two weeks; repeated uploading of unchanged Sitemap is not necessary. https://yandex.ru/support/webmaster/ru/indexing-options/sitemap
- Official help: `Страницы в поиске` numbers reflect index/search changes with delay. https://yandex.ru/support/webmaster/ru/service/searchable

## Authorized Playwright tools added in draft PR #125

- `yandex_webmaster_preflight.cjs`: read-only public crawler, robot rules, Sitemap, canonical URLs, YandexBot-like user agent, host redirect aliases; JSON report from GitHub Actions.
- `test_yandex_webmaster_preflight.cjs`: pure regression tests for robot directives, precedence and XML parsing.
- `yandex_webmaster_auth_inspector.mjs`: **read-only, local** Playwright persistent profile; exact allowed property paths only. Can capture Sitemap, reindex queue and searchable page table statuses **after actual owner login in its isolated profile**; never exports browser cookies, uses a password, or changes the account. Has never been run against Oleg's authenticated account in this ChatGPT session.
- `test_yandex_webmaster_auth_inspector.mjs`: false-property and read-only status filter unit tests. In GitHub Actions it tests parsing only, **not authenticated access**.

## Real completion gate

1. Use a supported authorized **interactive Playwright session** with access to Oleg's actual Yandex Webmaster account. Do not bypass extension host permissions or harvest cookies from an existing Chrome profile.
2. Confirm both properties correspond to exact `https://<domain>/` origins. Check each `Индексирование → Файлы Sitemap` row and timestamp. If Sitemap already present `OK` or queued, do not re-add. If missing from UI, robots declaration already informs the crawler; optionally add explicitly after confirming appropriate rights and no existing entry.
3. Check `Индексирование → Переобход страниц` current status and then `Страницы в поиске`, `Исключённые страницы`, `Диагностика`. Save actual accepted/indexed/removed counts with date. A valid Sitemap does **not** guarantee search inclusion.
4. If real errors are found, identify whether they are page quality, server, robots, canonical or not-found; fix actual hosting source under backup/rollback. Re-run public Playwright audit and then resubmit **only genuinely updated URLs**.
5. Preserve the existing Yandex Direct pause; no campaigns launched.

## Change status

- Public diagnosis: **verified**.
- Yandex authenticated dashboard inspection: **blocked by extension permission**.
- Webmaster settings changed / new Sitemap submitted today: **NO**.
- SEO metadata and internal link package published to actual hosting today: **NO**.
- Actual number of indexed URLs: **unconfirmed**.
