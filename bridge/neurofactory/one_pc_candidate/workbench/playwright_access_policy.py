"""ONE Agent / Playwright: owner-approved per-site operation classification.

Review and authorization layer ONLY; no remote browser capabilities are enabled
by importing this module. Browser extension tab selection and Work/ONE local UI
grants remain mandatory. In particular, a caller-provided "approved=True" flag
must never be used as a security authority.
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlsplit

class PlaywrightAccessDenied(ValueError):
    pass

# Exact HTTPS origins. The associated permission is the MAXIMUM POTENTIAL
# classification, not a grant. Never infer user consent from this catalog.
PROJECT_ORIGINS = {
    "oleg-legal": frozenset({
        "https://potrebpravo.ru", "https://semya-yurist.ru",
        "https://webmaster.yandex.ru", "https://metrika.yandex.ru",
        "https://hosting.timeweb.ru", "https://b24-xlzm11.bitrix24.ru",
        "https://b24-s2dosa.bitrix24site.ru", "https://search.google.com",
    })
}
READ_ACTIONS = frozenset({
    "navigate", "snapshot", "inspect", "screenshot", "tabs_list", "tabs_switch",
    "read_counters", "read_indexing", "read_leads",
})
MUTATING_ACTIONS = frozenset({
    "click", "fill", "check", "upload", "download", "submit",
    "create_goal", "edit_goal", "edit_website", "save", "publish",
    "update_crm_record", "send_form", "create_campaign_draft",
})
# Credentials and system-level actions are NOT browser automation permissions.
UNAVAILABLE_ACTIONS = frozenset({
    "export_cookies", "export_passwords", "read_storage_secrets",
    "raw_cdp", "open_remote_debugging_port", "system_shell",
    "grant_system_admin", "disable_security", "start_ads",
    "pay", "delete_account", "bulk_export_personal_data",
})
# Direct mutation requires local ONE owner's verified one-shot grant with
# exact target/operation plus post-change verification; not implemented here.

@dataclass(frozen=True)
class AccessDecision:
    project: str
    origin: str
    action: str
    state: str
    requires_local_owner_approval: bool
    note: str

def exact_origin(raw: str) -> str:
    if type(raw) is not str or len(raw) > 2000:
        raise PlaywrightAccessDenied("INVALID_URL")
    try:
        u = urlsplit(raw)
    except ValueError as error:
        raise PlaywrightAccessDenied("INVALID_URL") from error
    if (u.scheme != "https" or not u.hostname or u.username or u.password or
        u.port not in (None, 443) or u.fragment or any(ord(c) < 32 for c in raw)):
        raise PlaywrightAccessDenied("INSECURE_OR_AMBIGUOUS_URL")
    try:
        origin = "https://" + u.hostname.lower()
        u.hostname.encode("idna")
    except (UnicodeError, ValueError, AttributeError) as error:
        raise PlaywrightAccessDenied("INVALID_HOST") from error
    if u.hostname != u.hostname.lower() or "*" in raw or "\\" in raw:
        raise PlaywrightAccessDenied("INVALID_HOST")
    return origin

def classify(project: str, url: str, action: str) -> AccessDecision:
    if project not in PROJECT_ORIGINS:
        raise PlaywrightAccessDenied("PROJECT_NOT_PAIRED")
    origin = exact_origin(url)
    if origin not in PROJECT_ORIGINS[project]:
        raise PlaywrightAccessDenied("HOST_NOT_PAIRED")
    if type(action) is not str or action in UNAVAILABLE_ACTIONS:
        raise PlaywrightAccessDenied("HIGH_RISK_OPERATION_REFUSED")
    if action in READ_ACTIONS:
        return AccessDecision(project,origin,action,"ELIGIBLE_FOR_READ",False,
           "Requires explicit Playwright Extension tab grant and local client authorization")
    if action in MUTATING_ACTIONS:
        return AccessDecision(project,origin,action,"PENDING_LOCAL_OWNER_APPROVAL",True,
           "Do not execute until ONE validates a one-shot, project- and operation-bound local owner grant")
    raise PlaywrightAccessDenied("UNKNOWN_ACTION_FAIL_CLOSED")

def expected_config_origins(project: str) -> list[str]:
    if project not in PROJECT_ORIGINS:
        raise PlaywrightAccessDenied("PROJECT_NOT_PAIRED")
    return sorted(PROJECT_ORIGINS[project])

def can_mutate_without_owner_receipt(*args, **kwargs):
    # A future integration must validate owner receipts through ONE's existing
    # audited approval system; never trust a model or GitHub JSON field.
    return False
