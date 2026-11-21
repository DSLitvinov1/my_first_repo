/* Oleg Legal V64: consent-gated, strictly site-scoped visitor ID bridge.
 * Values are never logged, persisted or sent until a visitor opens their own Bitrix24 form.
 * Bitrix24 hidden form field parameter 'metrica_client_id' MUST be configured separately. */
(function () {
  'use strict';
  if (window.__olegClientIdBridgeV1) return;
  var host = location.hostname.toLowerCase().replace(/^www\./, '');
  var config = {
    'potrebpravo.ru': {counter: 114249897, form: 'crm_form_fhi3n'},
    'semya-yurist.ru': {counter: 114251443, form: 'crm_form_ep5fd'}
  }[host];
  if (!config) return;

  var choiceKey = 'oleg.analytics.choice.v2';
  var clientId = null;
  var requested = false;
  var token = 0;
  var maxAge = 365 * 86400000;
  var formHost = 'b24-s2dosa.bitrix24site.ru';

  function allowed() {
    try {
      var v = JSON.parse(localStorage.getItem(choiceKey) || 'null');
      return !!v && v.value === 'yes' &&
        typeof v.at === 'number' && v.at <= Date.now() &&
        (Date.now() - v.at) < maxAge &&
        window.__olegAnalyticsStarted === true;
    } catch (_) {
      return false;
    }
  }

  function valid(id) {
    return typeof id === 'string' && /^[0-9]{5,32}$/.test(id);
  }

  function requestId() {
    if (!allowed() || requested || typeof window.ym !== 'function') return;
    requested = true;
    var current = ++token;
    try {
      window.ym(config.counter, 'getClientID', function (received) {
        if (token !== current || !allowed()) return;
        if (valid(received)) clientId = received;
      });
    } catch (_) {
      requested = false;
    }
  }

  function ownForm(url) {
    return url.protocol === 'https:' &&
      url.hostname === formHost && url.port === '' &&
      url.username === '' && url.password === '' &&
      url.pathname === '/' + config.form + '/';
  }

  function augment(href) {
    var url;
    try { url = new URL(href, location.href); }
    catch (_) { return href; }
    if (!ownForm(url)) return href;
    // Never trust user-supplied or stale client-id parameters.
    url.searchParams.delete('metrica_client_id');
    if (allowed() && valid(clientId)) {
      url.searchParams.set('metrica_client_id', clientId);
    } else if (allowed() && !requested) {
      requestId();
    }
    return url.toString();
  }

  window.__olegClientIdBridgeV1 = Object.freeze({augment: augment});

  // Direct links can open in new tabs. Amend only the exact native CRM form
  // URL on this site, never arbitrary outgoing links or another legal site.
  document.addEventListener('click', function (event) {
    var node = event.target && event.target.closest &&
      event.target.closest('a[href]');
    if (!node) return;
    try {
      var target = new URL(node.href, location.href);
      if (!ownForm(target)) return;
      node.href = augment(node.href);
    } catch (_) {}
  }, true);

  // The official analytics bootstrap controls consent. This handler merely
  // attempts a read once that bootstrap has actually accepted consent.
  document.addEventListener('click', function (event) {
    var el = event.target && event.target.closest &&
      event.target.closest('#oleg-analytics-choice [data-allow]');
    if (el) setTimeout(requestId, 0);
  }, false);
  if (allowed()) requestId();

  // Never retain ClientID across a consent-revocation action.
  document.addEventListener('click', function (event) {
    var el = event.target && event.target.closest &&
      event.target.closest('#oleg-analytics-choice [data-deny]');
    if (el) { clientId = null; requested = false; ++token; }
  }, true);
})();
