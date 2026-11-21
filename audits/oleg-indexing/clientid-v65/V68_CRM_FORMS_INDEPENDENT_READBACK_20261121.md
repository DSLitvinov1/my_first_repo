# OLEG LEGAL — V68 CRM ClientID forms readback / 21 Nov 2026

Scope: existing production sites **potrebpravo.ru**, **semya-yurist.ru**, Bitrix24 portal **b24-xlzm11.bitrix24.ru**. This is a checkpoint, not a release.

## Verified / read-only
1. CRM form 10, family, site editor `/sites/site/4/view/38/`: fresh separate authenticated CDP tab opened and rendered settings. The independently loaded **saved** hidden field is:
   - CRM deal field ID: `DEAL_UF_CRM_DEAL_1795186664753`
   - Display label: `ClientID Яндекс Метрики · Сделка`
   - Parameter expression: `%metrica_client_id%`
   - Result: `SAVED_CLIENTID_VISIBLE` from `C:\ChatGPTProjects\OlegLegal\v68_form10_fresh_tab_readback.json`. New tab was closed after checking, no CRM writes.
2. CRM form 8, consumer, editor `/sites/site/4/view/36/`: independent readback from 20 Nov 2026 recorded the same field and expression, `C:\ChatGPTProjects\OlegLegal\v67_form8_readback_6s.json`. An additional new-tab check on 21 Nov 2026 timed out during CDP rendering, so it does **not** supersede the earlier positive result.
3. The prior editor snapshot taken too early, immediately after opening settings, had displayed zero items; waiting for the asynchronous form settings to finish loading revealed the saved field. Do not remove or recreate the field on that basis.
4. Production sites on 21 Nov were HTTP 200, indexable sitemap URLs 23/23 + 18/18 HTTP 200, proper canonical. `/assets/oleg-clientid-bridge-v1.js` gives 404 on **both** production sites; V65 bridge is still staged only, so attribution is not live.
5. Linux backup and uptime monitor exist and run. Latest run reported both public sites reachable but `crm_real_delivery_checked=false`.
6. Non-interactive authorized SSH attempt to Timeweb `cl664853@vh460.timeweb.ru` on 21 Nov returned `Permission denied (publickey,password)`. No publication was attempted and no bypass performed. Browser Timeweb connector reported insufficient host permissions; cannot claim write access.

## Blockers for truthful completion
- With working authorized Timeweb deployment rights: compare exact live tree/backups against staged V65, release atomically only if checks match, preserve rollback. Do not deploy if the host rejects authorization.
- Run real browser QA on both sites with explicit new analytics consent, inspect actual `ym(...,'getClientID')` call in the proper counter and ensure only the site's form receives `metrica_client_id`.
- Carry out one uniquely tagged, consented controlled submission per site once an independent CRM deal readback is available. Verify ID, source/site/form, UTM, assigned owner, ClientID field, and actually delivered notification. Never create uncontrolled duplicates or use real customer phone numbers as test fixtures.
- Route verified stages to `114249897` (consumer) and `114251443` (family) separately; require proper privacy basis and actual conversion match. Official Bitrix24 connector mass import is not appropriate without confirmed per-site filtering.
- Fix CRM robot messages containing no deal number/link, prove Oleg receives in-app/email notifications. Confirm GSC properties and Yandex index coverage.
- Keep Yandex Direct **OFF** and PR #131 **DRAFT** until live acceptance. No claim of completed conversion integration, SEO index inclusion or production release.

References: `audits/oleg-indexing/clientid-v65/README.md`; official docs https://helpdesk.bitrix24.ru/open/25978110/ and https://yandex.ru/support/metrica/ru/data/offline-conversion-data.
