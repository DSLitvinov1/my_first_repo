# Oleg Legal — V131 production acceptance, 21 November 2026

## Verified externally this turn
- Both legal sites respond HTTP 200, have the expected Bitrix24 CRM form IDs and ClientID bridge, and refuse GET `/legal-lead.php` with 405. Prior V68 44/44 live HTTP and 48/48 isolated consent browser QA PASS remain relevant to the deployed bridge, but **do not establish CRM delivery**.
- The two Google Search Console URL-prefix properties are now connected to OpenSEO, each with `siteOwner` permission. Neither requires reconnection.
- GSC URL Inspection examined all **41 sitemap URLs** individually: `potrebpravo.ru` 5 indexed / 23; `semya-yurist.ru` 3 indexed / 18. Homepages indexed, crawled as MOBILE, fetched successfully on 2026-11-21 (consumer 10:54:28 UTC; family 10:56:30 UTC). Other pages mostly `Обнаружена, не проиндексирована`; a few unknown to Google. 8 indexed / 41 in total, 33 not indexed.
- GSC Search Performance last 28 days (2026-10-22 through 2026-11-18) returns 0 page rows on both; no proven organic clicks/impressions.
- OpenSEO IndexNow submitted all 23 consumer and all 18 family sitemap URLs; provider status `submitted` for both hosts. This is only a submission to IndexNow-supporting search engines, **not** proof of Yandex indexing. Google does not support IndexNow.
- Yandex Metrika goals existing and previously observed in authenticated UI (Windows `v123_metrika_goals_after_create.json`): consumer counter 114249897: confirmed lead goal ID 688078495 (`oleg_crm_lead_confirmed`), completed consult goal 688074736, contract goal 688079852; family counter 114251443: lead goal 688081208, consult 688082535, contract 688083707. This is **goal creation only**, not actual CRM offline conversion counting.

## CRM evidence and blocker
- Historical family **test** submitted 2026-11-21 at 01:45 UTC; Bitrix deal **#22** created. Authenticated list readback reports named form `Заявка — Семейное право`, numeric `ClientID` on grid, owner Олег Лёвин, robot-created followup task with state `Создана, не просмотрена`. Deal #22 is synthetic and must **never** count as a qualified lead.
- Historical consumer test submitted 2026-11-21 at 01:36 UTC and another attempt 01:55 UTC; both browser confirmation and fresh CRM-deal readback **ambiguous**, no new deal found. `v83_consumer_send_result.json`, `v87_consumer_send_result.json`. These were already reserved; do not retry identical submissions until cause diagnosed.
- Live form preflight for both passed fields, mask, privacy consent, ClientID and UTM values in iframe URL. Consumer failed at/after POST or post-submit confirmation; cannot infer the cause from evidence.
- Both form admin editors reachable. Read-only comparison of anti-spam panels `v129_compare_spam_settings.json` found identical Yandex SmartCaptcha choices in two forms; this does not prove CAPTCHA is the cause. No anti-bot settings were changed.
- Family notification task created for Oleg; the owner **has not yet confirmed actually receiving** this new alert. Earlier Oleg confirmed some older alerts (19 Nov), and reported deal #20 invisible in one context. No new Oleg email after 20 Nov discovered.
- Consumer source UTM in actual deal not established, the family field value numeric but lack verified full deal-card readback, and no independently verified real conversion posted to Yandex Metrika. Do not count test deals as real conversions.

## Deployment gate
No paid Yandex Direct campaign may be launched until consumer form succeeds with independently verified real deal, duplicate suppression and notification receipt have been demonstrated, both sites deliver proper consented ClientID and distinct UTM into the CRM, and qualified real conversions can be attributed to correct counter. Real advertising budget and campaign targeting must be approved separately. Do not mass-import B24 deals via shared official connector without confirmed partitioning.

## Immediate remaining actions
1. Use authenticated Chrome / B24 to compare complete native form submission configuration and network errors. Do not blind-submit synthetic leads again. Investigate whether identical dummy phone duplicate rules, masked phone, invisible captcha, or Bitrix back-end rejection explains consumer response. If new controlled test is unavoidable, reserve unique synthetic marker and use a strictly authorized non-real test channel.
2. Audit deal #22 readback and notification robot through readable deal list; confirm future leads' source, UTM, named form, ClientID, owner and whether Oleg receives them. Prefer a read-only status until blocker is understood.
3. Configure strictly source-scoped offline conversion upload **only for qualified non-test deals**, with opt-in and client privacy basis. Verify actual count in corresponding Yandex Metrika counter. Goals already exist; don't recreate.
4. Inspect Yandex Webmaster authenticated dashboard for indexing/errors; GSC is already connected and indexed pages are measured.

## Trace
- GitHub draft PR #131, branch `oleg-v65-clientid-crm-20261120`. 
- Windows files: `C:\ChatGPTProjects\OlegLegal\v83_family_send_result.json`, `v83_consumer_send_result.json`, `v87_consumer_send_result.json`, `v88_deal22_grid_fields.json`, `v123_metrika_goals_after_create.json`, `v129_compare_spam_settings.json`.
- Server monitor: `/home/cloudagent/.local/share/oleg-site-ops-v23/latest_public.json`; at 2026-11-21 11:07 UTC public healthy, **crm_real_delivery_checked=false**.
