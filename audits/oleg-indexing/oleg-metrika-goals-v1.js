(function () {
  'use strict';
  // Oleg Metrika goals extension. Deploy by appending to the existing
  // assets/oleg-analytics-v1.js on EACH site, after the consent bootstrap.
  // Never identifies users, records field values, or claims form completion.
  if (window.__olegMetrikaIntentGoalsV1) return;
  window.__olegMetrikaIntentGoalsV1 = true;

  var COUNTERS = Object.freeze({
    'potrebpravo.ru': 114249897,
    'semya-yurist.ru': 114251443
  });
  var FORMS = Object.freeze({
    'potrebpravo.ru': 'crm_form_fhi3n',
    'semya-yurist.ru': 'crm_form_ep5fd'
  });
  var hostname = location.hostname.toLowerCase().replace(/^www\./, '');
  var counter = COUNTERS[hostname];
  if (!counter) return;
  var CHOICE_KEY = 'oleg.analytics.choice.v1';
  var lastGoal = Object.create(null);
  function consentGranted() {
    try {
      return JSON.parse(localStorage.getItem(CHOICE_KEY) || 'null')?.value === 'yes'
        && window.__olegAnalyticsStarted === true;
    } catch (_) { return false; }
  }
  function send(goal) {
    if (!consentGranted() || typeof window.ym !== 'function') return;
    // A user can click a floating button repeatedly; prevent accidental
    // duplicate events caused by an overlay or multiple listeners.
    var now = Date.now();
    if (now - (lastGoal[goal] || 0) < 1500) return;
    lastGoal[goal] = now;
    try { window.ym(counter, 'reachGoal', goal); } catch (_) {}
  }
  function isVisible(element) {
    if (!element || !element.isConnected || element.hidden) return false;
    if (element.closest('[hidden],[aria-hidden="true"]')) return false;
    var rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }
  function onClick(event) {
    var target = event.target;
    if (!target || typeof target.closest !== 'function') return;

    var anchor = target.closest('a[href]');
    if (anchor) {
      var href = anchor.getAttribute('href') || '';
      if (/^tel:\+?\d/i.test(href)) send('oleg_phone_click');
      else if (/^mailto:/i.test(href)) send('oleg_email_click');
    }

    var toggle = target.closest('#legal-help-toggle');
    if (toggle) {
      // The website toggles its panel during the normal click handler.
      window.setTimeout(function () {
        var panel = document.getElementById('legal-help-panel');
        if (isVisible(panel) && toggle.getAttribute('aria-expanded') !== 'false') {
          send('oleg_consultation_open');
        }
      }, 100);
    }

    var button = target.closest('button');
    if (button && /^(Передать вопрос юристу|Оставить заявку юристу)$/.test((button.textContent || '').trim())) {
      window.setTimeout(function () {
        var frame = document.querySelector('#legal-help-form-step iframe.legal-frame');
        if (!frame || !isVisible(frame)) return;
        var intended = 'https://b24-s2dosa.bitrix24site.ru/' + FORMS[hostname] + '/';
        if (frame.src === intended) send('oleg_crm_form_open');
      }, 300);
    }
  }
  document.addEventListener('click', onClick, false);
  // This script intentionally does NOT emit oleg_lead_success:
  // only a server-verified Bitrix24 record can establish a real conversion.
})();
