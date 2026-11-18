(() => {
  'use strict';
  if (document.getElementById('legal-help-toggle')) return;

  const isFamily = location.hostname === 'semya-yurist.ru' || location.hostname === 'www.semya-yurist.ru';
  const forms = Object.freeze({
    family: 'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/',
    consumer: 'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'
  });
  // Form links preserve only vetted marketing tags from the current page.
  // Do not copy arbitrary URL values, customer data, tokens or identifiers.
  function bitrixFormUrlWithCampaign(input) {
    const link = new URL(input);
    const query = new URLSearchParams(location.search || '');
    for (const key of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
      const v = query.get(key);
      if (v && /^[\p{L}\p{N}_ .:+|{}~-]{1,180}$/u.test(v)) link.searchParams.set(key, v);
    }
    return link.toString();
  }
  const formUrl = bitrixFormUrlWithCampaign(isFamily ? forms.family : forms.consumer);
  const topics = isFamily
    ? [
      ['Развод', 'Уточните, есть ли несовершеннолетние дети, согласен ли второй супруг и где проживают стороны.'],
      ['Алименты', 'Важны возраст ребёнка, сведения о доходах и наличие судебного решения или соглашения.'],
      ['Раздел имущества', 'Подготовьте сведения о дате приобретения имущества и наличии брачного договора.'],
      ['Спор о ребёнке', 'Уточните, что требуется определить: порядок общения, место жительства или иной вопрос.']
    ]
    : [
      ['Возврат товара', 'Важно знать дату покупки, вид товара, наличие дефекта и обращения к продавцу.'],
      ['Некачественная услуга', 'Подготовьте договор, дату оказания услуги и описание обнаруженных недостатков.'],
      ['Спор с продавцом', 'Уточните, направлялась ли претензия и получен ли на неё ответ.'],
      ['Проблема с застройщиком', 'Подготовьте договор, сроки передачи объекта и имеющуюся переписку.']
    ];

  const style = document.createElement('style');
  style.textContent = [
    '#legal-help-toggle{position:fixed;z-index:2147483000;right:16px;bottom:90px;max-width:calc(100vw - 32px);border:0;border-radius:28px;background:#175247;color:#fff;padding:13px 18px;box-shadow:0 5px 20px #0004;font:600 15px/1.3 system-ui;cursor:pointer}',
    '#legal-help-toggle:focus-visible,#legal-help-panel button:focus-visible,#legal-help-panel a:focus-visible{outline:3px solid #e2b965;outline-offset:2px}',
    '#legal-help-panel{box-sizing:border-box;position:fixed;z-index:2147483000;right:12px;bottom:156px;width:min(440px,calc(100vw - 24px));max-height:70dvh;overflow:auto;overscroll-behavior:contain;background:#fff;color:#24332e;border:1px solid #d5e2dd;border-radius:16px;box-shadow:0 10px 42px #0005;padding:17px;font:15px/1.5 system-ui}',
    '#legal-help-panel[hidden],#legal-help-form-step[hidden],#legal-help-topics[hidden]{display:none!important}',
    '#legal-help-panel h2{font:700 20px/1.35 system-ui;margin:0 0 12px;color:#183c34}',
    '#legal-help-panel p{margin:8px 0 12px}',
    '#legal-help-panel .legal-answer{padding:12px;border-radius:9px;background:#f1f8f5;border-left:3px solid #175247}',
    '#legal-help-panel button.legal-choice{display:block;width:100%;text-align:left;border:1px solid #bed4c9;background:#f5faf8;color:#175247;padding:10px 12px;margin:8px 0;border-radius:9px;font:600 14px system-ui;cursor:pointer}',
    '#legal-help-panel .legal-primary{width:100%;border:0;background:#175247;color:white;border-radius:9px;padding:12px 14px;font:600 15px system-ui;cursor:pointer}',
    '#legal-help-panel .legal-close{border:0;background:#eef5f2;color:#175247;border-radius:8px;padding:7px 11px;font:700 19px system-ui;cursor:pointer}',
    '#legal-help-panel .legal-back{border:1px solid #bed4c9;background:white;color:#175247;border-radius:8px;padding:8px 10px;font:600 13px system-ui;cursor:pointer}',
    '#legal-help-panel .legal-small{font:12px/1.5 system-ui;color:#59665f}',
    '#legal-help-panel .legal-frame{display:block;width:100%;height:535px;max-width:100%;box-sizing:border-box;border:1px solid #d6e1df;border-radius:10px;background:white}',
    '#legal-help-panel .legal-open{color:#175247;text-decoration:underline;font-weight:600}',
    '@media(max-width:550px){#legal-help-panel{padding:12px;right:8px;width:calc(100vw - 16px)}#legal-help-panel .legal-frame{height:555px}}'
  ].join('');
  document.head.append(style);

  const create = (tag, text) => {
    const node = document.createElement(tag);
    if (typeof text === 'string') node.textContent = text;
    return node;
  };
  const launch = create('button', 'Помощь юриста');
  launch.id = 'legal-help-toggle';
  launch.type = 'button';
  launch.setAttribute('aria-expanded', 'false');
  launch.setAttribute('aria-controls', 'legal-help-panel');

  const panel = create('section');
  panel.id = 'legal-help-panel';
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Юридический помощник');

  const header = create('div');
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:start;gap:12px';
  const heading = create('h2', isFamily ? 'Помощь по семейному праву' : 'Защита прав потребителей');
  const close = create('button', '×');
  close.type = 'button';
  close.className = 'legal-close';
  close.setAttribute('aria-label', 'Закрыть помощника');
  header.append(heading, close);
  panel.append(header);

  const guide = create('div');
  guide.id = 'legal-help-topics';
  guide.append(create('p', 'Выберите тему. Подскажем, какие сведения понадобятся юристу.'));
  const answer = create('p');
  answer.className = 'legal-answer';
  answer.setAttribute('aria-live', 'polite');
  answer.textContent = 'Это предварительная информация. Юрист оценит ситуацию после изучения деталей.';
  guide.append(answer);
  for (const [name, info] of topics) {
    const button = create('button', name);
    button.type = 'button';
    button.className = 'legal-choice';
    button.addEventListener('click', () => { answer.textContent = info + ' Итоговую оценку даст юрист.'; });
    guide.append(button);
  }
  const next = create('button', 'Оставить заявку юристу');
  next.type = 'button';
  next.className = 'legal-primary';
  guide.append(next);
  const hint = create('p', 'Не указывайте паспортные данные, адреса и конфиденциальные сведения.');
  hint.className = 'legal-small';
  guide.append(hint);
  panel.append(guide);

  const formStep = create('div');
  formStep.id = 'legal-help-form-step';
  formStep.hidden = true;
  const back = create('button', 'Назад к вопросам');
  back.type = 'button';
  back.className = 'legal-back';
  formStep.append(back);
  formStep.append(create('p', 'Заполните форму Битрикс24. Обращение поступит в CRM после нажатия «Отправить» и подтверждения согласия.'));
  const frame = create('iframe');
  frame.className = 'legal-frame';
  frame.title = isFamily ? 'Заявка по семейному праву' : 'Заявка по защите прав потребителей';
  frame.setAttribute('referrerpolicy', 'strict-origin-when-cross-origin');
  frame.setAttribute('loading', 'eager');
  formStep.append(frame);
  const fallback = create('p');
  fallback.className = 'legal-small';
  fallback.style.cssText = 'background:#f1f8f5;border:1px solid #bed4c9;border-radius:9px;padding:10px 12px;margin:10px 0';
  fallback.append(create('span', 'Если форма загружается долго, '));
  const open = create('a', 'откройте форму Битрикс24 напрямую');
  open.className = 'legal-open';
  open.href = formUrl;
  open.target = '_blank';
  open.rel = 'noopener noreferrer';
  const alternative = create('span', '. Если Битрикс24 недоступен, можно ');
  const phoneLink = create('a', 'позвонить');
  phoneLink.href = 'tel:+79172052125';
  phoneLink.className = 'legal-open';
  const mailLink = create('a', 'написать на почту');
  mailLink.href = 'mailto:centr-uprav@inbox.ru';
  mailLink.className = 'legal-open';
  fallback.append(open, alternative, phoneLink, create('span', ' или '), mailLink,
    create('span', '. Передавайте конфиденциальные сведения только после согласования безопасного способа связи.'));
  formStep.insertBefore(fallback, frame);
  panel.append(formStep);

  function position() {
    const dock = document.querySelector('.oleg-contact-dock');
    const heightFromBottom = dock ? Math.max(0, window.innerHeight - dock.getBoundingClientRect().top) : 0;
    const launchBottom = Math.ceil(heightFromBottom + 12);
    launch.style.bottom = launchBottom + 'px';
    const popupBottom = launchBottom + launch.getBoundingClientRect().height + 10;
    panel.style.bottom = popupBottom + 'px';
    panel.style.maxHeight = Math.max(195, window.innerHeight - popupBottom - 12) + 'px';
  }
  function setOpen(value) {
    panel.hidden = !value;
    launch.setAttribute('aria-expanded', String(value));
    position();
    if (value) close.focus();
    else launch.focus();
  }
  launch.addEventListener('click', () => setOpen(panel.hidden));
  close.addEventListener('click', () => setOpen(false));
  next.addEventListener('click', () => {
    guide.hidden = true;
    formStep.hidden = false;
    if (!frame.src) frame.src = formUrl;
    panel.scrollTop = 0;
    back.focus();
  });
  back.addEventListener('click', () => { formStep.hidden = true; guide.hidden = false; panel.scrollTop = 0; next.focus(); });
  panel.addEventListener('keydown', (event) => { if (event.key === 'Escape') setOpen(false); });
  document.body.append(panel, launch);
  window.addEventListener('resize', position);
  if (window.visualViewport) window.visualViewport.addEventListener('resize', position);
  position();
})();