# ONE Agent / ChatGPT / Playwright — controlled access checkpoint, 2026-11-15

## Objective
Build a managed Playwright extension-mode browser control path that the owner can pair to the already signed-in Chrome profile, and reuse safely for owner-controlled websites/projects. Browser-only automation must remain separate from native Windows operations (ONE Desktop/Computer Use).

## Existing architecture — do not replace
- Main repo `DSLitvinov1/my_first_repo` candidate branch `workone-human-ui-chatgpt-bridge-20261115`; inherits `workone-safe-browser-tabs-seo-20261114` and draft PR #123, with existing Work ONE Qwen, browser worker (Puppeteer), UI, approval and GitHub Issues command relay. This new Playwright pathway is OPTIONAL and does not rewrite the CORE9/HOST service.
- Windows installed Work ONE baseline was `b9fcd4337f0f76cca0bcbb41c150e9cfe2582cc8` as of the last verified physical readout. The candidate changes in this branch have not been installed into that baseline.
- Existing Windows reserve bridge `DSLitvinov1/lesson3.1` branch `chatgpt-control` is working through GitHub Actions `ChatGPT Universal Control`, unrelated to Remote Desktop Commander monthly quota.

## Verified actual Windows facts
- [Read-only GitHub runner #43729385939](https://github.com/DSLitvinov1/lesson3.1/actions/runs/43729385939), `workone-playwright-readonly-20261115-001`, OK. Computer `WIN-LIDC05TBOQD` online. Chrome running, Node.js and npm available, existing Work ONE staging directory exists. Runner process is Windows **Session 0 and noninteractive**, so it cannot attach by default to the user's desktop window.
- [Read-only security runner #43730055964](https://github.com/DSLitvinov1/lesson3.1/actions/runs/43730055964), `workone-playwright-security-readonly-20261115-002`, OK. Chrome processes were seen in sessions **2 and 0**. Existing localhost CDP port `9222` listens only on `127.0.0.1`, process `chrome`, session 0. It is NOT an authorized route to bypass browser-extension permissions. No listener or firewall settings changed.
- Registry keys under Chrome/Edge Policies exist, but the relevant limited fields did not establish the root cause of `ERR_BLOCKED_BY_ADMINISTRATOR`; the admin policy must not be bypassed or weakened.

## Implemented in this candidate branch
- `playwright_access_policy.py`: fail-closed per-project exact HTTPS host checks (8 core Oleg origins) and action classification; hard-denies credential export, raw CDP, system shell, payment, automatic ad launches, unpaired hosts; marking mutations as PENDING_OWNER_APPROVAL only. **This pure policy is not yet wired as an MCP transport enforcement gateway.** Do not claim it already guards arbitrary external MCP callers.
- `playwright_owner_mcp.json`: official Microsoft Playwright MCP `extension: true`, localhost only, no saved MCP session, no unrestricted file access, and documented allowlisted network origins. An allowlist in Playwright MCP is only a convenience defense, **not** a sandbox/security boundary; actual tab grants must occur in the extension and ONE local client permissions.
- `playwright_owner_readiness.ps1`: read-only local owner Windows diagnostics for Chrome/Edge, Node/npm, policy hints; never reads cookies/passwords or changes browser settings.
- `playwright_stage_owner.ps1`: dry-run first, nonadmin INTERACTIVE Windows user only; optional explicit `-Apply` stages config and an example MCP client entry in local user AppData after backups. No extension install, no remote service, no auto-grant and no network opening.
- `test_playwright_access_policy.py` and `test_playwright_owner_config.py`: offline domain/action/config regression tests, integrated into the pre-existing Windows CI.
- [Windows regression run #43730401453](https://github.com/DSLitvinov1/my_first_repo/actions/runs/43730401453) **PASS** at commit `7abebe89dd80902d09b78e54e59c73a9b4e5d1e5`, including policy tests, Python/PowerShell parsing, legacy Work ONE regressions and isolated real Chromium typing on a synthetic page. This is not live account access.

## Optional local staging via reserve bridge
- GitHub bridge task `workone-playwright-stage-20261115-003` **COMPLETED, exit=0, ok=true** under [Actions #43730677202](https://github.com/DSLitvinov1/lesson3.1/actions/runs/43730677202). Inert files staged at `C:\ChatGPTProjects\ONE-Playwright-Candidate-20261115` with SHA-256 and byte-count receipts for `playwright_owner_mcp.json`, `playwright_owner_readiness.ps1` and `playwright_stage_owner.ps1`. Report explicitly confirms: no service started, no firewall changes, no tokens; Playwright Extension not connected by this staging action. This is NOT installation/activation of a browser-control MCP server.

## One-time owner UI pairing that is still REQUIRED
1. On the **interactive Windows desktop** with the already signed-in Chrome profile, use the official Microsoft **Playwright Extension** (not the ChatGPT tab-reader). Open its Manage clients page, connect one local MCP client, and select only approved tabs, e.g. Yandex Metrika, Yandex Webmaster, Timeweb, Bitrix24. The extension groups client-controlled tabs so an unrelated tab stays outside that client.
2. In a compatible local MCP client, register the official `@playwright/mcp` server with `--extension` and this staged config. Do not paste extension authentication token or Chrome cookies into ChatGPT/GitHub. Do not enable 0.0.0.0 CDP or external ports. The Windows user must approve the pairing.
3. In supported ChatGPT **desktop Work** (separate interface from the Chat mode read-only Browser connector), select the managed Chrome browser with `@Chrome` and grant access to the exact websites in Computer Use > Manage as prompted. Browser permissions set by an organization admin cannot be overridden by user or script. Work's browser control is not automatically the same as the local Playwright MCP process.
4. Run actual authenticated tests: read both counter IDs, inspect whether 8 desired Metrika goals exist; verify Webmaster Sitemap rows, check Bitrix24 CRM deal IDs, inspect Timeweb file roots. Each write action (goal creation, publication, form submission, CRM updates) still needs local owner approval and post-action readback.
5. For other projects, enroll exact additional domains and a separate project-local user grant. Never issue a global unlimited browser cookie/session or native Windows administrative grant.

## Status / hard limitations
- Verified: Windows reserve bridge, Chrome runtime and loopback-only existing CDP listener; Windows CI of policy candidate.
- Prepared in source: Playwright MCP extension-mode config and fail-closed policy classification.
- Not verified: Playwright Extension currently installed/paired in the interactive owner's Chrome; the MCP client registered in ChatGPT; actual website permissions; new branch installed in running ONE Agent.
- No writes to real Yandex, Timeweb, Bitrix24; no advertising started; no Windows security or firewall permissions altered.
- No Playwright control of *all Windows applications*: Playwright is browser automation. Desktop-wide native app control belongs to ONE Desktop or supported ChatGPT Computer Use and has separate access boundaries.

Documentation: https://playwright.dev/mcp/configuration/browser-extension ; https://github.com/microsoft/playwright/blob/main/packages/extension/README.md ; https://learn.chatgpt.com/docs/chrome-extension
