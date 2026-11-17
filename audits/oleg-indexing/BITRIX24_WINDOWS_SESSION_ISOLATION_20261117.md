# Oleg Legal / Bitrix24 — Desktop Commander Chrome session isolation (17.11.2026)

## Evidence
- User supplied a screenshot of an authenticated Bitrix24 CRM-forms page with five visibly enabled forms: two intended (family law and consumer protection) and three extra "Контактные данные" dated 12–13 November. The screenshot depicts the interactive desktop, not Desktop Commander's managed Chrome.
- Desktop Commander on WIN-LIDC05TBOQD has command access, but its GUI process sees a 1024×768 display and no active window. Chrome processes run in Windows sessions 0 and 2.
- Chrome's only discovered remote debugging port, 9222, belongs to process 4752 in Windows session 0. Its open page is an unauthenticated Bitrix24 OAuth login. The authenticated user Chrome in the interactive session 2 is not attached to this remote-control endpoint.
- A separate Browser connector could read the authenticated form list, but offers only read access in Chat mode. No owner cookies, session tokens, passwords or restricted browser state were extracted or copied. No Windows session boundaries were bypassed.
- Zero changes to CRM forms, automation, notifications, or live Timeweb; zero new CRM submissions.

## Next safe action
Connect Desktop Commander to the current interactive desktop session rather than the Windows session-0 managed Chrome; alternatively, complete normal owner authentication in its managed Chrome. Do not inject privileged tokens or transplant cookies.
Then inspect both correct forms and three extra forms; disable unneeded ones only after confirming they are unused; verify separate deals, Oleg as owner, dedupe/active-deal settings, consent, notifications, source attribution, and actual evidence of successful intake. Do not merge draft PR #125 or publish the 43-file package without production preflight.

State: USER_INTERACTIVE_CHROME_AUTHENTICATED; DESKTOP_COMMANDER_CHROME_NOT_AUTHENTICATED; CRM_WRITE_BLOCKED_BY_WINDOWS_SESSION_ISOLATION.
