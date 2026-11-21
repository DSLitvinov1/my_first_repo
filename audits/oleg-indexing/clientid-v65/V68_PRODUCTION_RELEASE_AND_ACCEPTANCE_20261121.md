# OLEG LEGAL — V68 live release + independent acceptance (21 Nov 2026, MSK)

**Two existing production domains remain live:** https://potrebpravo.ru and https://semya-yurist.ru. No changes to domain ownership, lead API, CRM deals, Yandex Direct, or SEO URLs.

## Authoritative production release
- Hosting: authenticated official Timeweb WebConsole session, account `cl664853` on `vh460`. This is a native authorized channel; direct SSH had refused login.
- Existing live base preserved: `v55-release-a-20261119`, prior `phase=LIVE_VERIFIED`. For the six critical live files the installer enforced known source SHA256 before accepting any write.
- Script: `audits/oleg-indexing/clientid-v65/v68_atomic_clientid_release.py`; verified downloaded SHA256 `c875cea03402ebafefd199b4d544764a9472c565ce253849e2364c3c8713e480`.
- Client bridge exact source: `audits/oleg-indexing/clientid-v65/v68-clientid-bridge-runtime.js`; SHA256 `1b60a68b27ee7eafecbca192ff2c3351a6592d7ec60e24c1a7cdca19fc4f46af`.
- Protected server preflight returned `DRY_RUN_OK_NO_WRITES`, target 51 files, expected 25/20 HTML, correct site/counter pair. Complete copy rehearsal performed on isolated 168-file backup: dry-run PASS, staged apply 51/51 and post-patch assertions PASS.
- Protected **production release applied**, server stdout `LIVE_WRITTEN_NEEDS_EXTERNAL_QA`, `files_written=51`. Server release+recovery material is private under `/home/c/cl664853/.oleg-seo-ops/v68-clientid/20261121T002136Z`, including `full-before.tar.gz`, private originals, prepared assets, and `manifest.json`. The installer has automatic rollback on a caught error. It preserves all other production files, including V55/V57 SEO metadata and case links. No mass CRM integration enabled.
- The updated analytics and assistant JS cache keys change according to the exact newly deployed asset digest; the consent banner explicitly describes ClientID and uses new opt-in choice v2; privacy disclosure updated. Original service links preserved.

## Independent external acceptance after deploy
- Linux `evidence/v68_live_http_full_qa.json`: **44/44 PASS**, 22 per domain, including GET/HTTPS, 23+18 sitemap URLs HTTP200, self-canonical, H1, indexability, all three published JS assets SHA256 exact, JS syntax, privacy disclosure, robots and 405 for GET /legal-lead.php. Each public native B24 form responds HTTP 200.
- Windows isolated real Chrome CDP `C:\ChatGPTProjects\OlegLegal\v68_live_consent_cdp_qa.json`: **48/48 PASS**, four cases (both domains, consent yes/no). Actual Yandex Metrika `getClientID` callback returns a valid numeric real visitor ID for both separate counters; that ID is attached to the **correct site's** CRM iframe URL only when consented. Denial sends none; no other-site form, no PII in URL and no JS exceptions. Browser contexts disposed; **0 form submissions**, 0 synthetic CRM deals.
- Evidence reports do **not** contain any real ClientID, phone, email, or applicant data.

## Bitrix24 form config separately verified
- Family form #10 `crm_form_ep5fd`: independent fresh authorized UI readback on 21 Nov shows saved deal field `DEAL_UF_CRM_DEAL_1795186664753`, label `ClientID Яндекс Метрики · Сделка`, expression `%metrica_client_id%` (`v68_form10_fresh_tab_readback.json`).
- Consumer form #8 `crm_form_fhi3n`: independent authorized UI readback from 20 Nov shows the exact same saved deal field and expression (`v67_form8_readback_6s.json`). A 21 Nov fresh UI attempt timed out; don't misread initial asynchronous empty panel as missing field.
- A freshly authenticated Bitrix24 sales funnel list was readable on 21 Nov; previous deals #16 family and #18/#20 consumer were still shown, no extra deals created by V68.

## Remaining acceptance gates / no unsupported claims
1. Two separately consented **real form submissions**, each with independent CRM deal card readback: saved field ClientID, correct form/site/source/UTM, assigned Oleg, actual notification receipt, no duplicates. **Not yet performed** — opening a form and passing ClientID in the URL is not proof the value was persisted in a deal.
2. Confirm two qualified CRM stage conversions actually appear in their respective Yandex Metrika accounts. Local `conversion_router.py` is ready but upload/synchronization is not configured; **do not** enable official B24 connector bulk-import without confirmed site-source filtering, lawful basis, and permissions.
3. Resolve unclear Bitrix notification robot messages (#20 indistinguishable from other messages), verify e-mail sender/recipient and Oleg's actual receipt. Source history contains real notices but end-to-end delivery still incomplete.
4. Search Console verified properties for both legal domains are missing in the connected Google account; Yandex Webmaster index coverage/cause of 7 family reindex errors not confirmed. OpenSEO default US/en cannot replace Moscow/RU search data. Improve 13 thin judicial-case pages only with verified source documents.
5. Monitor real CRM delivery and actual counters; current Linux public monitor covers uptime, not complete post-submit CRM flow. Review deployment recovery on an isolated stage before touching production.

**No Yandex Direct campaigns launched. Do not interpret these tests as evidence of search index inclusion or a successful recorded CRM conversion.** PR #131 should stay draft until two genuine deal tests and CRM conversion acceptance are complete.
