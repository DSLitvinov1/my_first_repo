# Oleg Legal: proof-based lead receipt and Metrika conversion guard

**DRAFT ONLY. NOT DEPLOYED.** Supports the two published websites, with no production/CRM mutation.

Current public `/assets/site.js` posts `#lead-form` to `/api/leads`, resets fields on any HTTP 2xx and shows a success message. The client-side acknowledgement does not establish a verified CRM deal. GET/HEAD to the API endpoint returned 404; these methods do not prove whether POST exists. External Bitrix24 forms returned HTTP 200 but actual owner receipt is unverified.

The guard requires a **proposed backend contract that is NOT currently proven to exist**: request_id matches the client idempotency key; source_host matches the domain; CRM result has provider bitrix24, status confirmed, readback_confirmed true, entity_type lead/deal, positive entity_id, plus independently established owner_confirmed/source_confirmed/utm_confirmed/dedupe_confirmed/notification_confirmed boolean flags. The backend must make a genuine, authenticated Bitrix24 readback before returning confirmation. A claimed JSON flag alone is insufficient to prove receipt; independently compare the real Bitrix record, owner, source and delivery log.

Without confirmation the UI must retain input and report that delivery is not verified. Only after a verified acknowledgement and explicit analytics opt-in may the frontend emit the proposed Yandex goal `crm_lead_accepted`. The goal must first be configured in each counter account (114249897 / 114251443). No PII, CRM IDs or UTM parameters are sent with the goal; duplicate acknowledgements are suppressed within the tracker instance. This is an isolated design and unit-test gate, NOT integration proof.

Run `node --test lead-confirmation-guard.test.js` with Node 18+. Native JS tests cover HTTP 200 false positives, CRM readback flag, host and idempotency key checks, consent, no PII, dedupe, failure recovery, fabricated objects, and both counters.

Before production: verify Timeweb SSH host key via independently authenticated source, obtain authorized source access, make and verify server backups, implement backend contract with true readback, conduct two permitted CRM test submissions with known authorized test contacts and verify IDs/owner, confirm actual consent and Metrika goals, then perform isolated deploy + Playwright regression. Keep Yandex Direct OFF.


## V6 progress — 2026-11-16 (OFFLINE, NOT DEPLOYED)

- bitrix-readback-contract.js is a dependency-injected fail-closed backend contract. Requires authenticated Bitrix entity readback, approved source mapping, correct owner, requestId+UTM correlation, durable duplicate query yielding one record and independent delivery notification readback. No actual CRM APIs called or port-specific field names assumed.
- lead-confirmation-guard.js now rejects missing, falsy or nonboolean owner/source/UTM/dedupe/notification proof flags. This client-side shape is NOT itself a security boundary: only the server may set flags after real Bitrix verification.
- oleg-metrika-goals-v1.js has a consent-gated native #lead-form submit-attempt event. Cross-origin Bitrix24 iframe submission cannot be observed by this listener. crm_lead_accepted requires actual verified CRM readback plus a configured Yandex goal.
- timeweb_readonly_route_inventory.py scans explicitly supplied server directories for route candidates using boolean patterns and SHA; never outputs credential values or modifies files. It has not been run on real Timeweb.
- CI 43780550562 passed 55/55 offline tests for unified release, backups/rollback, fake receipt defenses, analytics and safe source inventory.
- Still blocked: Desktop Commander quota 0; Bitrix browser host permission; Timeweb webconsole is read-only to ChatGPT and SSH host key trust/write access not established; OpenSEO US/en and GSC accounts=[] on both properties.
- PR #125 remains draft. NO production files, CRM objects, Metrika goals, Webmaster or ads modified.
