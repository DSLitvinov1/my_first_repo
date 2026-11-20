"use strict";
(() => {
  // Remove only the unwanted ChatGPT referral tag; keep Yandex and other campaign parameters intact.
  try {
    const url = new URL(location.href);
    if ((url.searchParams.get("utm_source") || "").toLowerCase() === "chatgpt.com") {
      url.searchParams.delete("utm_source");
      history.replaceState(history.state, "", url.pathname + url.search + url.hash);
    }
  } catch { /* Non-browser preview, inaccessible history or malformed URL: leave original URL untouched. */ }
  const $ = (selector) => document.querySelector(selector);
  const form = $("#lead-form");
  const status = $("#lead-status");
  const next = $("#step-next");
  const back = $("#step-back");
  const submit = $("#lead-submit");
  const stepOne = $("#step-one");
  const stepTwo = $("#step-two");
  const topic = $("#topic");
  const params = new URLSearchParams(location.search);
  const allowedUtm = ["utm_source","utm_medium","utm_campaign","utm_content","utm_term"];
  const utm = Object.fromEntries(allowedUtm.map(k=>[k,(params.get(k)||"").slice(0,150)]));
  const preview = document.documentElement.dataset.preview === "true";
  const metrikaId = Number(document.documentElement.dataset.metrikaId || 0);
  const consentKey = "oleg_services_landing_analytics_v1";
  const cookie = $("#cookie-banner");
  let currentStep = 1;
  let requestId = crypto.randomUUID();
  let nonce = "";
  let nonceReady = false;
  let sending = false;
  let analyticsInitialized = false;

  const availableServices = ["free","paid","documents","remote","turnkey"];
  function analyticsAllowed() {
    try { return localStorage.getItem(consentKey) === "allow"; } catch { return false; }
  }
  function loadAnalytics() {
    if (preview || analyticsInitialized || !metrikaId || !analyticsAllowed()) return;
    analyticsInitialized = true;
    window.ym = window.ym || function(){ (window.ym.a=window.ym.a||[]).push(arguments); };
    window.ym.l = Date.now();
    const js = document.createElement("script");
    js.async = true;
    js.src = "https://mc.yandex.ru/metrika/tag.js";
    document.head.appendChild(js);
    window.ym(metrikaId,"init",{clickmap:true,trackLinks:false,accurateTrackBounce:false,webvisor:false});
  }
  function goal(name) {
    if (!preview && analyticsAllowed() && analyticsInitialized && typeof window.ym === "function") {
      window.ym(metrikaId, "reachGoal", name);
    }
  }
  const year = $("#year"); if (year) year.textContent = String(new Date().getFullYear());
  function cookieChoice(choice) {
    try { localStorage.setItem(consentKey,choice); } catch {}
    cookie.hidden = true;
    if (choice==="allow") loadAnalytics();
    if (choice==="deny" && analyticsInitialized) location.reload();
  }
  if (cookie) {
    cookie.hidden = preview || (()=>{try{return localStorage.getItem(consentKey)!==null;}catch{return false;}})();
    $("#cookie-allow").addEventListener("click",()=>cookieChoice("allow"));
    $("#cookie-deny").addEventListener("click",()=>cookieChoice("deny"));
    $("#cookie-settings").addEventListener("click",()=>{cookie.hidden=false;});
    loadAnalytics();
  }
  function show(message,type="") {
    status.textContent = message;
    status.className = "form-status" + (type ? " "+type : "");
  }
  function phoneValid(raw) {
    const digits=raw.replace(/\D/g,"");
    return digits.length===11 && (digits[0]==="7" || digits[0]==="8");
  }
  function firstStepValid() {
    const name=$("#client-name").value.trim();
    const phone=$("#client-phone").value.trim();
    const msg=$("#client-message").value.trim();
    if (name.length<2 || name.length>80) {show("Укажите имя (не меньше двух символов).","error");$("#client-name").focus();return false;}
    if (!phoneValid(phone)) {show("Укажите номер телефона с 11 цифрами.","error");$("#client-phone").focus();return false;}
    if (msg.length<5) {show("Коротко опишите ситуацию (от пяти символов).","error");$("#client-message").focus();return false;}
    return true;
  }
  function go(step) {
    currentStep=step;
    stepOne.hidden=step!==1;
    stepTwo.hidden=step!==2;
    $("#step-counter").textContent=step===1?"ШАГ 01 / 02":"ШАГ 02 / 02";
    $("#progress-fill").style.width=step===1?"50%":"100%";
    show("");
    if (step===2) $("#step-two-title").focus({preventScroll:true});
    else $("#client-name").focus({preventScroll:true});
    if (window.matchMedia("(max-width: 760px)").matches) $("#consultation").scrollIntoView({block:"start",behavior:"smooth"});
  }
  next.addEventListener("click",()=>{
    if (!firstStepValid()) return;
    goal("services_step1_completed");
    go(2);
  });
  back.addEventListener("click",()=>go(1));
  const topicParam=params.get("topic")||"";
  if ([...topic.options].some(o=>o.value===topicParam)) topic.value=topicParam;
  function selectService(value) {
    if (!availableServices.includes(value)) return;
    const radio=form.querySelector('input[name="service"][value="'+value+'"]');
    if (radio) radio.checked=true;
  }
  selectService(params.get("service") || "");
  document.querySelectorAll("[data-service]").forEach(link=>link.addEventListener("click",()=>{
    selectService(link.dataset.service);
    goal("services_format_selected");
  }));
  document.querySelectorAll("[data-topic]").forEach(link=>link.addEventListener("click",()=>{
    topic.value=link.dataset.topic;
    goal("services_topic_selected");
  }));
  form.querySelectorAll('input[name="service"]').forEach(radio=>radio.addEventListener("change",()=>goal("services_format_selected")));
  document.querySelectorAll('[data-track="phone"]').forEach(a=>a.addEventListener("click",()=>goal("services_phone_click")));
  async function getNonce() {
    if (preview) return;
    nonceReady=false;
    try {
      const r=await fetch("api/nonce.php",{credentials:"same-origin",cache:"no-store",headers:{"Accept":"application/json"}});
      if(!r.ok)throw new Error("NONCE_UNAVAILABLE");
      const data=await r.json();
      if(!data?.token || typeof data.token!=="string")throw new Error("TOKEN_MISSING");
      nonce=data.token;nonceReady=true;
    } catch {nonce="";nonceReady=false;}
  }
  if(!preview)getNonce();
  form.addEventListener("submit", async (e)=>{
    e.preventDefault();
    if(sending)return;
    if(currentStep!==2){if(firstStepValid())go(2);return;}
    if(!firstStepValid()){go(1);show("Проверьте имя, телефон и описание ситуации.","error");return;}
    const selected=form.querySelector('input[name="service"]:checked');
    if(!selected){show("Выберите формат юридической помощи.","error");$("#service-options").focus();return;}
    if(!$("#lead-consent").checked){show("Для отправки обращения подтвердите согласие на обработку данных.","error");$("#lead-consent").focus();return;}
    if(preview){show("Это предпросмотр сайта. Отправка заявок будет включена после подключения Битрикс24.","error");return;}
    if(!nonceReady)await getNonce();
    if(!nonceReady){show("Сейчас отправка недоступна. Позвоните по указанному номеру.","error");return;}
    sending=true;submit.disabled=true;
    show("Подтверждаем регистрацию обращения…");
    try{
      const payload={
        name:$("#client-name").value.trim(),phone:$("#client-phone").value.trim(),
        message:$("#client-message").value.trim(),topic:topic.value,service:selected.value,
        website:$("#company-site").value,consent:true,csrf:nonce,request_id:requestId,
        page:(location.pathname||"/").slice(0,180),yclid:(params.get("yclid")||"").slice(0,150),...utm
      };
      const response=await fetch("api/lead.php",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify(payload)});
      const data=await response.json().catch(()=>({}));
      if(!response.ok || data.status!=="accepted")throw new Error("CRM_NOT_CONFIRMED");
      form.reset();requestId=crypto.randomUUID();go(1);
      show("Обращение зарегистрировано. С вами свяжутся для уточнения деталей.","success");
      goal("services_crm_accepted");
    }catch{
      show("Не удалось подтвердить регистрацию обращения. Позвоните нам или повторите позже.","error");
    }finally{
      submit.disabled=false;sending=false;await getNonce();
    }
  });
})();
