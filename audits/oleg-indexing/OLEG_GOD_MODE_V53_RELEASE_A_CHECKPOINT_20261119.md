# OLEG LEGAL — GOD MODE V53 | Release A checkpoint 2026-11-19

**Status: RELEASE A OFFLINE PREPARED AND TESTED. Not deployed. Current production remains V25.**

## Latest proven state

Production sites: `https://potrebpravo.ru/` and `https://semya-yurist.ru/`.

Linux repository: `/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118`, source branch `oleg-v25-utm-attribution-20261118`, baseline HEAD `9d3c82fd88ccf3c4a03c09d6b0c171f66d74f0cf`.

Isolated GitHub records: branch `oleg-site-public-link-qa-20261119`. V52 checkpoint commit `17389cb88d76c8750d918d755c6aa32e125ae99f` already exists.

## V53 actual implementation: two independent releases instead of a combined unapproved release

A separate **safe Release A** was generated from the exact V25 snapshot (168 original files) instead of deploying the combined 53-file V52 archive blindly. Only the 12 existing service pages and the accepted analytics/assistant improvements are included. The two V51 new legal articles were **fully excluded**, together with their homepage and internal links and extra sitemap URLs.

The existing 12 service pages no longer say that forms are disabled; they link to the appropriate existing Bitrix24 CRM forms. Consent-sensitive attribution records only allowlisted UTM and numeric YCLID within a 30-minute session after consent. Unknown URL keys, email, phone and tokens never appear in Bitrix URLs. Site-specific counters and forms remain unchanged.

All 41 baseline sitemap URLs remain in this release: 23 consumer + 18 family. No new public URLs were added, and no broken references to unpublished legal pages are left in HTML.

V53 Release A artifact (private Linux): `.private-v53-offline/v53-release-a-v25-safe-delta-20261119.tar.gz`.

- ZIP/TAR: gzipped TAR, 53 updated files; 168-file entire candidate in `.private-v53-offline/release-a`.
- Exact SHA256: `d4a32d3932ee9b7537bbf2b5bd91f0b592f00512d8efafbd2265c1fce5b311be`.
- SHA manifest: `.private-v53-offline/v53-release-a-manifest.json`.
- SOURCE baseline: V25 manifest 168 SHA matches, confirmed in V52 release preparation.
- Stage isolated, zero Timeweb writes.

## Tests passed V53 Release A

- `v53_release_a_attribution_qa.cjs`: **66/66 PASS**, 4 sessions (2 sites × consent/denial), genuine isolated Chromium. No production CRM POST or real analytics uploads.
- `v53_release_a_service_qa.cjs`: **264/264 PASS**, 24 scenarios (12 services × mobile/desktop).
- SHA of release TAR verified; 53 safe regular members, no path traversal; 23+18 URLs and two future legal URLs absent.
- Production V25 has not been overwritten by tests, Webmasters not resubmitted.
- Tests only verify staged HTML, UI, links and browser events; they do **not** prove live Bitrix-to-Metrika conversion delivery.

## Obstacles and unverified dependencies

1. **TIMEWEB**: Direct SSH attempt `cl664853@vh460.timeweb.ru` continues returning `Permission denied (publickey,password)`. No confirmed logged-in browser session has been found for the hosting account; do not decrypt or retrieve passwords from email. Production upload is blocked until owner logs in at `https://hosting.timeweb.ru/login` or legitimate server access is restored. Verify real production V25 SHA and backup before release.
2. **LEGAL REVIEW**: Two new pages `otkaz-ot-uslug.html` and `razdel-dolgov.html` remain in the separate V52 candidate and require appropriate legal sign-off before release B. This does not block release A.
3. **YANDEX WEBMASTER**: Seven historical family reindex errors; actual index status undetermined. Do not interpret HTTP 200 as proof of index inclusion.
4. **GOOGLE SEARCH CONSOLE**: No authorized access to the two domains in currently connected Google account; do not invent coverage/click data.
5. **CRM/METRIKA**: Verified goals and real page visit tracking exist from V51 evidence, but a **server-confirmed lead/deal matched to a true CRM conversion in Metrika is not verified**. Do not create false conversion goal events.
6. **YANDEX DIRECT**: OFF, no spend authorized.

## Next execution

1. Restore authorized Timeweb session. Compare live current content hashes to V25 expected values. Save backup and rollback.
2. Publish isolated Release A only. Immediately verify 41 production sitemap pages, form links, mobile screens, analytics consent and attribution, errors and server logs.
3. Independently check legal text and publish separate Release B when approved, preserving rollback.
4. Connect the CRM and Metrika in an authorized, compliant way; confirm real accepted deal and source and exact Metrika conversion (not `submit_attempt`).
5. Obtain GSC permission, resolve 7 Yandex reindex errors based on official statuses, and verify actual indexed pages.
6. Prepare Direct, do not start paid campaigns.
7. Write subsequent V54 checkpoint with exact production commit/release and real E2E acceptance, not hypothetical status.

**Do not claim V53 published; current result is reproducible staged release A.**
