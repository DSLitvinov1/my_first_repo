# OLEG LEGAL — V126 | CRM, Metrika and Search Console acceptance, 21 November 2026

Status: **technical updates deployed; business end-to-end conversion acceptance NOT COMPLETE**. This is a factual checkpoint. No new branch/replacement sites. Timeweb production roots are `/home/c/cl664853/{potrebpravo.ru,semya-yurist.ru}/public_html`.

## Shipped and independently verified

**V68 site release:** guarded 51-file update with full pre-release backup, HTTPS/SEO/consent/CRM ClientID bridge; 44/44 external HTTP tests including every sitemap URL; 48/48 four real-browser consent/ClientID cases.

**V100 Google and IndexNow:** verified ownership of BOTH `https://potrebpravo.ru/` and `https://semya-yurist.ru/` URL-prefix properties through independent owner readback. Both linked correctly to their distinct OpenSEO projects. GSC sitemaps submitted and independently re-read:
- consumer `/sitemap.xml`: status **Успешно**, **23** discovered pages, last processed 21 November 2026;
- family `/sitemap.xml`: status **Успешно**, **18** discovered pages, last processed 21 November 2026.
- All **41 URL** submitted via authenticated IndexNow API: 23 consumer +18 family. Proof keys present live.
- As of 21 Nov Google URL Inspection for **all 41** had **0 indexed**: 39 unknown and two homepages with **stale historical** robots.txt blocked states from November 3 (consumer) and November 10 (family), before robots.txt corrections. Live Google Search Console URL Test for **both homepages** reports **можно проиндексировать**. Two separate main-page **Запросить индексирование** requests accepted and added to Google's priority queue. Google index inclusion is an external future event; do not claim indexed until official status changes. Yandex Webmaster dashboard returned an ongoing temporary failure to update statistics; live robots parser allows both Googlebot and YandexBot.

**Metrika direct access:** authenticated dashboards are accessible for the ACTUAL counters consumer **114249897** and family **114251443** (do not trust the unrelated-counter account list). Reporting week 15–21 Nov: consumer 30 visits/14 visitors/3 search visits; family 15/11/4. These are analytics counts, not real CRM leads.

**NEW six actual qualified-CRM goals**, saved through the respective authenticated counter and independently re-read in a second session, supported by `C:\ChatGPTProjects\OlegLegal\v123_metrika_goals_after_create.json`:
| Counter | Qualified CRM goal | Yandex goal number | Event ID (offline CSV Target) |
|--|--|--:|--|
| 114249897 | Lead confirmed | 688078495 | oleg_crm_lead_confirmed |
| 114249897 | Consultation completed | 688074736 | oleg_crm_consultation_completed |
| 114249897 | Contract signed | 688079852 | oleg_crm_contract_signed |
| 114251443 | Lead confirmed | 688081208 | oleg_crm_lead_confirmed |
| 114251443 | Consultation completed | 688082535 | oleg_crm_consultation_completed |
| 114251443 | Contract signed | 688083707 | oleg_crm_contract_signed |

The dashboard expresses matching as `идентификатор содержит`. For offline CSV `Target`, use the *string event ID*, not the numeric Yandex goal number. No offline conversion uploads yet.

**CRM ClientID and tests:** family test deal **#22** exists, has a valid 18-digit numeric ClientID in the grid cell per `v101_bitrix_deal_rows.json`, assigned to **Олег Лёвин**, and contains an overdue task 'Связаться с клиентом по новой заявке'. It is **TEST**, in stage **Новая**, NOT a qualified lead, not eligible for offline conversion. Consumer V83/V87 form requests reached the B24 form, ClientID/UTM/consent preflight PASS, but no native thank-you or unambiguous new deal was verified. Each test attempt is reserved; do not blindly repeat or claim success. Existing consumer #18/#20 and family #16 remain listed.

**Safe local conversion routing update:** `audits/oleg-indexing/clientid-v65/conversion_router.py` now recognizes a qualified, verified `В работе` lead as `oleg_crm_lead_confirmed`, plus prior consultation and contract states. Rejects any explicit/missing test flag, unqualified lead, wrong assigned owner, unverified stage, missing user consent, incorrect site/form/source, fake/stale ClientID, expired timestamp, PII-heavy records and duplicates. No network or CRM writes, and exported CSV files private with mode 0600. **10/10 router tests and 24/24 browser bridge assertions PASS on remote Linux**. Tested source in GitHub and remote Linux is same checkpoint; no real conversions fabricated.

## Outstanding gates before claiming business-complete
1. Diagnose consumer native B24 form end-to-end without uncontrolled duplicates. Require actual native thank-you, CRM deal ID, correct owner, site, UTM and ClientID readback and independent receipt. Consumer submissions V83/V87 have ambiguous status, not successful.
2. Verify delivery of each *new* robot/in-app/e-mail notification as Олег, not merely task creation; past November 19 email 'Да, всё пришло' is not evidence for the November 21 deal. Current Oleg task #22 is marked overdue. Authenticated `/crm/deal/automation/2/` renders the deal table rather than a confirmed editable robot configuration; don't claim robots reconfigured.
3. Actual **real** qualified deals and stage transitions, with properly documented user consent, should eventually produce verifiable stage-scoped offline CSV and upload. No valid real qualified conversions were observed; test deal #22 and synthetic contacts must never be counted.
4. Yandex official Bitrix24 connector would potentially bulk-sync history from a **shared multi-site CRM** to both counters; do NOT enable without verified partitioning and privacy basis. Keep Yandex Direct **OFF** until confirmed attribution and budget approval. Don't fake qualified leads or spend.
5. Google external crawl/index progress and Yandex indexing stats remain pending; check in GSC after crawler processing and repeat *without* repeated priority re-submission. Currently **0/41** Google indexed per inspection snapshot, despite 41 discovered via sitemap and live homepage allowance.

## Evidence and continuity
- GitHub branch `oleg-v65-clientid-crm-20261120`, draft PR **#131**, do not merge until actual full CRM acceptance.
- Windows files `C:\ChatGPTProjects\OlegLegal\v119_goal_*.json`, `v123_metrika_goals_after_create.json`, `v105_gsc_sitemap_readback.json`, `v109_gsc_live_url_test.json`, `v112_gsc_request_*.json`, `v101_bitrix_deal_rows.json`, `v83_consumer_send_result.json`, `v87_consumer_send_result.json`.
- Remote Linux: `/home/cloudagent/projects/oleg-seo-v26-clientid-bridge-20261120/code/conversion_router.py`, `tests/test_conversion_router.py`, `tests/test_clientid_bridge.cjs`.
- Existing Linux availability/backup monitoring remains, but `crm_real_delivery_checked=false`; **not** a completed end-to-end CRM alert monitor. Existing 25 ChatGPT automations are disabled; did not automatically re-enable tasks against user preference.
- No secrets, visitor identifiers, test phone numbers or full CRM contact data committed.

**Explicit acceptance states:** site publication = SHIPPED/TESTED; Google property + sitemap = VERIFIED; real indexed pages = NOT VERIFIED; six goal definitions = SAVED/VERIFIED; qualified CRM conversions = NOT VERIFIED; notification delivery as Олег = NOT VERIFIED; paid campaign launch = NOT STARTED.
