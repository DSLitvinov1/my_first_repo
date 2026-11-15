(function () {
  'use strict';
  // No submission, personal-data collection, analytics, or automatic redirect.
  // Readable fallback if external Bitrix24 scripts stall on a visitor's network.
  if (window.__olegCrmBackupLinksV1) return;
  window.__olegCrmBackupLinksV1 = true;
  var forms = {
    'potrebpravo.ru':'crm_form_fhi3n',
    'semya-yurist.ru':'crm_form_ep5fd'
  };
  var host = location.hostname.toLowerCase().replace(/^www\./, '');
  var formId = forms[host];
  if (!formId) return;
  var directUrl = 'https://b24-s2dosa.bitrix24site.ru/' + formId + '/';
  function createLink(text, href, openNew) {
    var a = document.createElement('a');
    a.textContent = text;
    a.href = href;
    if (openNew) {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    }
    a.style.cssText = 'display:inline-flex;align-items:center;min-height:40px;padding:5px 8px;text-decoration:underline;text-underline-offset:3px;max-width:100%;';
    return a;
  }
  function approvedExistingLink(prefix, regex) {
    var all = document.querySelectorAll('a[href]');
    for(var i=0; i<all.length; i++){
      var value = all[i].getAttribute('href')||'';
      if(value.slice(0,prefix.length).toLowerCase()===prefix && regex.test(value))return value;
    }
    return null;
  }
  function insert() {
    var formStep = document.getElementById('legal-help-form-step');
    var destination = formStep || document.querySelector('footer');
    if (!destination || destination.querySelector('[data-oleg-crm-backup="v1"]'))return;
    var wrap=document.createElement('div');
    wrap.setAttribute('data-oleg-crm-backup','v1');
    wrap.setAttribute('role','group');
    wrap.setAttribute('aria-label','Дополнительные способы связаться с юристом');
    wrap.style.cssText='margin:12px 0;padding:12px;border:1px solid currentColor;border-radius:10px;background:transparent;line-height:1.55;';
    var description=document.createElement('p');
    description.textContent = formStep
      ? 'Не открывается форма? Попробуйте открыть её в отдельной вкладке или свяжитесь с юристом напрямую.'
      : 'Нужна консультация юриста? Вы можете оставить обращение или связаться напрямую.';
    description.style.cssText='margin:0 0 5px;max-width:100%;';
    wrap.append(description);
    var links=document.createElement('div');
    links.style.cssText='display:flex;flex-wrap:wrap;gap:8px;align-items:center;';
    links.append(createLink('Открыть форму заявки',directUrl,true));
    var phone=approvedExistingLink('tel:',/^tel:\+?[0-9()+\-\s]{7,24}$/i);
    var email=approvedExistingLink('mailto:',/^mailto:[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$/i);
    if(phone)links.append(createLink('Позвонить',phone,false));
    if(email)links.append(createLink('Написать на почту',email,false));
    wrap.append(links);
    destination.append(wrap);
  }
  function start(){
    insert();
    // Some assistant versions render the form step lazily only after a click.
    document.addEventListener('click',function(event){
      if(event.target && event.target.closest &&
        event.target.closest('#legal-help-toggle,#legal-help-panel button')){
        window.setTimeout(insert,100);
        window.setTimeout(insert,650);
      }
    },false);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});
  else start();
})();