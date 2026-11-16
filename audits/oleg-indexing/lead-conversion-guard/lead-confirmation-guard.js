/* Oleg Legal: staged, not deployed. CRM confirmation contract. No network/DOM side effects. */
(function (root, factory) {
  'use strict';
  const guard = factory();
  if (typeof module === 'object' && module.exports) module.exports = guard;
  if (root) Object.defineProperty(root, 'OlegLeadConfirmationGuard', {
    value: guard, writable: false, configurable: false, enumerable: false
  });
})(typeof window === 'object' ? window : null, function () {
  'use strict';
  const COUNTERS = Object.freeze({
    'potrebpravo.ru': 114249897,
    'semya-yurist.ru': 114251443
  });
  const TYPES = new Set(['deal', 'lead']);
  const TOKEN = /^[a-zA-Z0-9_.:-]{1,128}$/;
  const CRM_ID = /^[1-9][0-9]{0,18}$/;
  const GOAL = 'crm_lead_accepted'; // Proposed; must exist in both Metrika accounts.
  const verifiedObjects = new WeakSet(); // Block accidental emission from fabricated response objects.

  function verifiedAck({ httpOk, body, hostname, requestId } = {}) {
    if (!httpOk || typeof hostname !== 'string' || !Object.prototype.hasOwnProperty.call(COUNTERS, hostname)) return null;
    if (typeof requestId !== 'string' || !TOKEN.test(requestId)) return null;
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
    if (body.request_id !== requestId || body.source_host !== hostname) return null;
    const crm = body.crm;
    if (!crm || typeof crm !== 'object' || Array.isArray(crm)) return null;
    if (crm.provider !== 'bitrix24' || crm.status !== 'confirmed' || crm.readback_confirmed !== true) return null;
    // Fail closed unless the backend independently checked the real CRM owner,
    // website source, UTM attribution, persistent dedupe and delivery log.
    for (const flag of ['owner_confirmed','source_confirmed','utm_confirmed','dedupe_confirmed','notification_confirmed']) {
      if (crm[flag] !== true) return null;
    }
    if (!TYPES.has(crm.entity_type)) return null;
    const id = crm.entity_id;
    const safeId = typeof id === 'number' ? (Number.isSafeInteger(id) ? String(id) : '') : (typeof id === 'string' ? id : '');
    if (!CRM_ID.test(safeId)) return null;
    const proof = Object.freeze({ requestId, hostname, crmType: crm.entity_type, crmId: safeId });
    verifiedObjects.add(proof);
    return proof;
  }

  function createTracker({ consentGranted, metrikaReady, sendMetrika } = {}) {
    if (typeof consentGranted !== 'function' || typeof metrikaReady !== 'function' || typeof sendMetrika !== 'function') {
      throw new TypeError('Explicit consent and Metrika callbacks are required');
    }
    const sent = new Set();
    return Object.freeze({
      record(ack) {
        if (!ack || typeof ack !== 'object' || !verifiedObjects.has(ack) || !Object.prototype.hasOwnProperty.call(COUNTERS, ack.hostname)) return false;
        if (typeof ack.requestId !== 'string' || !TOKEN.test(ack.requestId) || !TYPES.has(ack.crmType) || !CRM_ID.test(String(ack.crmId))) return false;
        if (!consentGranted() || !metrikaReady()) return false;
        const key = ack.hostname + ':' + ack.crmType + ':' + ack.crmId + ':' + ack.requestId;
        if (sent.has(key)) return false;
        // Never forward phone, name, CRM identifiers or UTM data to the analytics event.
        sendMetrika(COUNTERS[ack.hostname], GOAL);
        sent.add(key);
        return true;
      }
    });
  }

  return Object.freeze({ COUNTERS, GOAL, verifiedAck, createTracker });
});
