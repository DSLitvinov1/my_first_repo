# Oleg Legal V147 — consumer CRM end-to-end + Yandex exact-match goals, 21 Nov 2026

## Production CRM E2E: proven
- Production visitor consented at https://potrebpravo.ru/; native CRM form `crm_form_fhi3n` returned a thank-you.
- **One** newly created CRM deal **#24** in category 2, found by an independent before/after list readback (highest previous #22).
- CRM list: correct consumer site/form, owner **Олег Лёвин**, numeric Yandex Metrika ClientID stored, source `CRM-форма`, explicit synthetic `QA-V135-20261121-CONSUMER TEST NOT CLIENT DO NOT CALL` marker.
- Deal #24 detail sidebar readback confirms `qa_internal` source/UTM, Oleg, QA marker, task. Evidence on authorized Windows `v135_consumer_e2e_result.json`, `v137_deal24_readonly.json`.
- Previously created family **deal #22** was also a labelled QA synthetic, with owner Oleg, native family form, numeric ClientID.
- None of these are legitimate qualified leads and neither may become a real CRM offline conversion.
- On the `Новая` stage three Bitrix robots were read via authenticated automation iframe: `Добавить уведомление` **recipient `Ответственный`**, `Поставить задачу` recipient `Ответственный`, `Отправить сообщение сотруднику в чат`. First robot message: “Новая заявка на юридическую консультацию. Откройте сделку в Битрикс24 и свяжитесь с клиентом.” Sender is Дмитрий Сорокин. For #24 a task is **Создана, не просмотрена**. **Human notification receipt/read by Oleg NOT verified**. Do not pretend task creation proves recipient saw notification.

## Metrika: actual settings changed and independently checked
Official requirement: offline JS goals must have condition `exact` / «Совпадает»; existing six had `contain` / «Содержит».
**All six goals changed in existing Yandex Metrika counters**, preserving IDs, names and event values:
- Consumer counter `114249897`: `688078495` = `oleg_crm_lead_confirmed`, `688074736` = `oleg_crm_consultation_completed`, `688079852` = `oleg_crm_contract_signed`.
- Family counter `114251443`: `688081208` = `oleg_crm_lead_confirmed`, `688082535` = `oleg_crm_consultation_completed`, `688083707` = `oleg_crm_contract_signed`.
- Saved result: Windows `v144_goal_exact_first.json`, `v145_metrika_exact_goals.json`. **Independent fresh authenticated read-only verification ALL 6/6 PASS**, Windows `v146_six_exact_independent_readback.json`.
- No fake conversion imported, and Yandex Metrika reporting still needs an actual eligible non-test customer to validate matching.

## Secure upload implementation staged, not activated
Existing Linux project: `/home/cloudagent/projects/oleg-seo-v26-clientid-bridge-20261120`.
- `code/conversion_router.py` existing strict CRM eligibility / 2-site routing / ClientID and consent checks.
- Added `code/v147_offline_uploader.py` (versioned also in this GitHub folder). Default is **dry-run no network**; if authorized in future, reads only consented qualified non-test deal export, calls Yandex official goals API to prove all IDs remain exact, rejects cross-domain traffic, uploads source-filtered `ClientId,Target,DateTime` CSV to ONLY that site's counter, logs only counts, protects secrets, stores private SQLite reservation before network, never blindly retries ambiguous POST.
- Added tests `tests/test_v147_offline_uploader.py`. **11/11 uploader tests and 10/10 existing router tests PASS**, including missing OAuth, wrong goal condition, test records, mixed-site records, de-duplication, ambiguous network and qualified examples with fake HTTP (no real upload, no PII).
- **Not activated:** Yandex OAuth `OLEG_METRIKA_OAUTH_TOKEN` not configured on Linux, and Bitrix24 verified read-only REST/webhook API export is not connected. Current Windows Chrome authentication is insufficient for reliable long-term Linux API sync. Native Bitrix24 REST/webhooks in RU cloud require BitrixGPT + Marketplace subscription or its trial, per official docs; do not activate paid trial/plan without appropriate approval. Official Yandex-Bitrix broad bulk connector risks mixing the two sites' customers and QA test deals, so it was NOT switched on.
- The test #24 is excluded even though its real numeric ClientID and UTM are stored; **do not send QA as real conversion**. Need truly qualified real deal, explicit proof of consent, authenticated readback, and actual Metrika upload/processing status and later per-visit match to call CRM offline reporting fully live.

## Final public regression 21 Nov 2026
External read-only recheck after Metrika edits: `potrebpravo.ru`: 23/23 HTTP 200, ClientID bridge HTTP 200; `semya-yurist.ru`: 18/18 HTTP 200, bridge HTTP 200. No production site edits in this phase. Existing V68 backup on Timeweb unchanged.

## Remaining owner/admin access steps
1. To prove **Oleg personally saw/read notification #24**, use a genuinely authenticated session of Oleg's user, not admin/operator's current account; no password should be posted in chat. His in-app notifications and B24 messenger can be checked against deal #24. The robot already targets `Ответственный` and created task.
2. Confirm whether B24 REST/webhook subscription is available, create least-privilege *read-only* CRM integration and Yandex OAuth grant stored only in protected Linux env (not chat or public GitHub).
3. Once a genuine qualified non-test client deal exists, verify CRM owner/site/source/UTM/ClientID+consent, upload only that deal with dedup and check processing and matching in the correct Metrika property. No launch of paid advertising without separate budget approval.
4. PR #131 remains DRAFT; avoid merging a large historical patch over already-live SEO release.

Sources:
- https://yandex.ru/dev/metrika/ru/management/offline-conv
- https://yandex.ru/dev/metrika/ru/management/openapi/goal/goals
- https://helpdesk.bitrix24.ru/open/20886106
