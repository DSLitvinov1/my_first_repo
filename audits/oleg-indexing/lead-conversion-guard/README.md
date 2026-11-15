# Oleg Legal: proof-based lead receipt and Metrika conversion guard

**DRAFT ONLY. NOT DEPLOYED.** Supports the two published websites, with no production/CRM mutation.

Current public `/assets/site.js` posts `#lead-form` to `/api/leads`, resets fields on any HTTP 2xx and shows a success message. The client-side acknowledgement does not establish a verified CRM deal. GET/HEAD to the API endpoint returned 404; these methods do not prove whether POST exists. External Bitrix24 forms returned HTTP 200 but actual owner receipt is unverified.

The guard requires a **proposed backend contract that is NOT currently proven to exist**: request_id matches the client idempotency key; source_host matches the domain; CRM result has provider bitrix24, status confirmed, readback_confirmed true, entity_type lead/deal, positive entity_id. The backend must make a genuine, authenticated Bitrix24 readback before returning confirmation. A claimed JSON flag alone is insufficient to prove receipt; independently compare the real Bitrix record, owner, source and delivery log.

Without confirmation the UI must retain input and report that delivery is not verified. Only after a verified acknowledgement and explicit analytics opt-in may the frontend emit the proposed Yandex goal `crm_lead_accepted`. The goal must first be configured in each counter account (114249897 / 114251443). No PII, CRM IDs or UTM parameters are sent with the goal; duplicate acknowledgements are suppressed within the tracker instance. This is an isolated design and unit-test gate, NOT integration proof.

Run `node --test lead-confirmation-guard.test.js` with Node 18+. Native JS tests cover HTTP 200 false positives, CRM readback flag, host and idempotency key checks, consent, no PII, dedupe, failure recovery, fabricated objects, and both counters.

Before production: verify Timeweb SSH host key via independently authenticated source, obtain authorized source access, make and verify server backups, implement backend contract with true readback, conduct two permitted CRM test submissions with known authorized test contacts and verify IDs/owner, confirm actual consent and Metrika goals, then perform isolated deploy + Playwright regression. Keep Yandex Direct OFF.
