# One-time authorized Bitrix24 CRM intake verification — 2026-11-15

Owner explicitly requested confirmation that inquiries from both Oleg lawyer websites reach Bitrix24 CRM.
Creates **at most one** visibly marked synthetic test inquiry per distinct website form, only after a read-only Playwright form journey passes.

- Consumer: `https://potrebpravo.ru/` → `crm_form_fhi3n`
- Family: `https://semya-yurist.ru/` → `crm_form_ep5fd`
- The contact telephone is dynamically read from the site owner's public `tel:` link, not a stranger's number.
- Test description begins with 'ТЕСТОВАЯ ПРОВЕРКА ... Не клиент, не звонить и не обрабатывать как реальный лид'.
- All submissions are performed through the real public form UI, not by trying to bypass browser access to a signed-in CRM account.
- The workflow is restricted to this exact commit message and the first GitHub Actions attempt. Normal CI runs never send leads.
- Record the HTTP statuses and Bitrix form confirmation in a JSON artifact. A form success message does **not** prove lead visibility or correct funnel stage inside the private CRM; an authenticated read-back is still required.

Do not trigger again or re-run the workflow for the same marker.

Preflight: Playwright both-site form journeys 30/30 PASS on GitHub Actions run 43662807471. YAML conditional quoting fixed before this run.

Retry authorization: Previous one-time run 43663214149 completed without any live submission (preflight consumer iframe timed out; submit step was skipped). Added one iframe GET reload and exact native form fallback before submission. This is the first live attempt.
