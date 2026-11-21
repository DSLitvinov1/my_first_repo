# OLEG LEGAL V135 — consumer website to Bitrix24 acceptance (21 November 2026)

Production: https://potrebpravo.ru → native Bitrix24 consumer form `crm_form_fhi3n` → common category 2 “Юридические консультации”.

**Verified result:** one controlled, labelled QA application submitted 2026-11-21 from the live website; the browser displayed success; the CRM list produced **one and only one NEW deal #24** not present in the pre-submit baseline (previous highest #22). The new deal is explicitly a **TEST, NOT A CLIENT, DO NOT CALL**. Never treat it as a qualified lead, do not call dummy phone, do not upload it to conversion objectives.

Evidence: Windows file `C:\ChatGPTProjects\OlegLegal\v135_consumer_e2e_result.json` from authenticated Chrome CDP.
- The live Yandex counter `114249897` returned a valid numeric ClientID after explicit consent.
- The consumer form iframe URL carried the **same** ClientID and the `qa_internal` UTM source. This proves browser-to-form attribution only; CRM-card UTM persistence remains to verify.
- Form fields and separate consent acceptance validated. Synthetic non-dialable test phone was used and no actual customer details collected.
- Native CRM form displayed a thank-you message with no visible validation error/captcha.
- CRM deal #24 list row: correct consumer form, Oleg Levin assigned, numeric ClientID saved, source CRM-form, unique QA marker present.
- HTTP200 responses seen from the B24 AJAX endpoint; no request/response body or ClientID value logged.
- No second submission. One-shot reservation persisted locally to protect against duplicated tests.

**Remaining separate gates:** independently confirm actual UTM stored on deal #24; read Oleg's account to prove notification received; verify CRM automation robot and task for #24; configure exact-match Yandex Metrika offline goals and authorized upload of qualified **non-test** deals to the correct site counter. The prior test deal #22 is family; both #22 and #24 must be excluded from real conversion statistics. Organic SEO and public runtime remain live. No ads launched.

Related: `V68_PRODUCTION_RELEASE_AND_ACCEPTANCE_20261121.md`, `V131_INDEX_STATUS_CRM_GATES_20261121.md`.
