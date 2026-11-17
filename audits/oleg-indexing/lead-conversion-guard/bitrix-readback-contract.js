'use strict';
/**
 * DRAFT / OFFLINE ONLY. Backend adapter contract for Oleg's two sites.
 * This module never calls Bitrix24 itself; the production server MUST inject
 * authenticated readback, durable idempotency and notification log readers.
 * Normalized CRM fields are NOT guaranteed to match the user's portal schema.
 */
const ALLOWED_HOSTS = new Set(['potrebpravo.ru', 'semya-yurist.ru']);
const TYPES = new Set(['deal', 'lead']);
const ID = /^[1-9][0-9]{0,18}$/;
const REQUEST_ID = /^[a-zA-Z0-9_.:-]{1,128}$/;
const UTM = Object.freeze(['source', 'medium', 'campaign', 'content', 'term']);
function positiveId(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) return '';
    value = String(value);
  }
  return typeof value === 'string' && ID.test(value) ? value : '';
}
function safeValue(value) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string' || value.length > 300) return null;
  return value.trim();
}
function exactUtms(request, crm) {
  if (!request || typeof request !== 'object' || !crm || typeof crm !== 'object') return false;
  return UTM.every(key => {
    const fromForm = safeValue(request[key]);
    const fromCrm = safeValue(crm[key]);
    return fromForm !== null && fromCrm !== null && fromForm === fromCrm;
  });
}
/**
 * Arguments are DATA and injected functions; no HTTP, secrets or storage here.
 * On failure => null, never a positive receipt.
 *
 * readEntity(type, id): freshly authenticated Bitrix CRM get/list lookup,
 *    returns normalized {id, assignedById, sourceId, sourceHost, requestId, utm}.
 * lookupDuplicates(requestId, type): durable query of matching CRM records,
 *    returns {count:1, entityId:<same id>}. In-memory-only dedupe is insufficient.
 * readNotification(type,id): independent authorized delivery/ack log
 *    returns {delivered:true, entityId:<same id>}.
 *
 * sourceIdByHost MUST come from verified, current Bitrix field mapping.
 */
async function verifyAndBuildReceipt({
  submission, created, expectedOwnerId, sourceIdByHost,
  readEntity, lookupDuplicates, readNotification
} = {}) {
  try {
    if (!submission || typeof submission !== 'object' || !created || typeof created !== 'object') return null;
    const {requestId, sourceHost, utm} = submission;
    if (!ALLOWED_HOSTS.has(sourceHost) || typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) return null;
    const entityType = created.entityType;
    const id = positiveId(created.id), owner = positiveId(expectedOwnerId);
    if (!TYPES.has(entityType) || !id || !owner || !sourceIdByHost ||
        !Object.prototype.hasOwnProperty.call(sourceIdByHost, sourceHost)) return null;
    const expectedSource = sourceIdByHost[sourceHost];
    if (typeof expectedSource !== 'string' || expectedSource.length < 1 || expectedSource.length > 80) return null;
    if (![readEntity, lookupDuplicates, readNotification].every(fn => typeof fn === 'function')) return null;
    const record = await readEntity(entityType, id);
    if (!record || positiveId(record.id) !== id ||
        positiveId(record.assignedById) !== owner ||
        record.sourceId !== expectedSource || record.sourceHost !== sourceHost ||
        record.requestId !== requestId || !exactUtms(utm || {}, record.utm || {})) return null;
    const dedupe = await lookupDuplicates(requestId, entityType);
    if (!dedupe || dedupe.count !== 1 || positiveId(dedupe.entityId) !== id) return null;
    const notification = await readNotification(entityType, id);
    if (!notification || notification.delivered !== true || positiveId(notification.entityId) !== id) return null;
    // No PII/UTMs included in response or Metrika payload.
    return Object.freeze({
      request_id: requestId, source_host: sourceHost,
      crm: Object.freeze({
        provider: 'bitrix24', status: 'confirmed', readback_confirmed: true,
        entity_type: entityType, entity_id: id,
        owner_confirmed: true, source_confirmed: true, utm_confirmed: true,
        dedupe_confirmed: true, notification_confirmed: true
      })
    });
  } catch (_) {
    // Failed/expired permissions or network uncertainty must never be success.
    return null;
  }
}
module.exports = Object.freeze({verifyAndBuildReceipt});
