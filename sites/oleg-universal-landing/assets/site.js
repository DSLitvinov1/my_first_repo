"use strict";
(() => {
  const $ = (s) => document.querySelector(s);
  const form = $("#lead-form");
  const status = $("#lead-status");
  const submit = $("#lead-submit");
  const topic = $("#topic");
  const cookie = $("#cookie-banner");
  const consentKey = "oleg_landing_analytics_v1";
  const metrikaId = Number(document.documentElement.dataset.metrikaId || 0);
  let initialized = false;
  let nonce = "";
  let nonceReady = false;
  let sending = false;
  let requestId = crypto.randomUUID();
  const params = new URLSearchParams(location.search);
  const allowedUtm = ["utm_source","utm_medium","utm_campaign","utm_content","utm_term"];
  const urlTopic = params.get("topic") || "";
  if ([...topic.options].some(o => o.value === urlTopic)) topic.value = urlTopic;
  const utm = Object.fromEntries(allowedUtm.map(k => [k, (params.get(k) || "").slice(0,150)]));
  const sanitizeRoute = () => (location.pathname || "/").slice(0,180);
  const analyticsAllowed = () => {
    try { return localStorage.getItem(consentKey) === "allow"; } catch { return false; }
  };
  function loadAnalytics() {
    if (initialized || !metrikaId || !analyticsAllowed()) return;
    initialized = true;
    window.ym = window.ym || function(){ (window.ym.a=window.ym.a||[]).push(arguments); };
    window.ym.l = Date.now();
    const s = document.createElement("script");
    s.async = true;
    s.src = "https://mc.yandex.ru/metrika/tag.js";
    document.head.appendChild(s);
    window.ym(metrikaId, "init", { clickmap: true, trackLinks: false, accurateTrackBounce: false, webvisor: false });
  }
  function goal(name) {
    if (analyticsAllowed() && initialized && typeof window.ym === "function") {
      window.ym(metrikaId, "reachGoal", name);
    }
  }
  document.querySelectorAll('[data-track="phone"]').forEach(a => a.addEventListener("click", () => goal("landing_phone_click")));
  document.querySelectorAll("[data-topic]").forEach(a => a.addEventListener("click", () => {
    topic.value = a.dataset.topic;
    goal("landing_topic_selected");
  }));
  const year = $("#year"); if (year) year.textContent = new Date().getFullYear();
  function persist(choice) {
    try { localStorage.setItem(consentKey, choice); } catch {}
    cookie.hidden = true;
    if (choice === "allow") loadAnalytics();
    if (choice === "deny" && initialized) location.reload();
  }
  if (cookie) {
    cookie.hidden = (() => { try { return localStorage.getItem(consentKey) !== null; } catch { return false; } })();
    $("#cookie-allow").addEventListener("click", () => persist("allow"));
    $("#cookie-deny").addEventListener("click", () => persist("deny"));
    loadAnalytics();
    const settings = $("#cookie-settings");
    if (settings) settings.addEventListener("click", () => { cookie.hidden = false; });
  }
  async function getNonce() {
    nonceReady = false;
    try {
      const res = await fetch("api/nonce.php", { credentials:"same-origin", cache:"no-store", headers:{"Accept":"application/json"} });
      if (!res.ok) throw new Error("API_UNAVAILABLE");
      const data = await res.json();
      if (!data || !data.token) throw new Error("TOKEN_UNAVAILABLE");
      nonce = data.token; nonceReady = true;
    } catch { nonce = ""; }
  }
  function show(message, isError=false, isSuccess=false) {
    status.textContent=message;
    status.className="form-status"+(isError?" error":isSuccess?" success":"");
  }
  function validPhone(value) {
    const digits=value.replace(/\D/g,"");
    return digits.length===11 && (digits[0]==="7" || digits[0]==="8");
  }
  getNonce();
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    if (sending) return;
    const name=$("#client-name").value.trim();
    const phone=$("#client-phone").value.trim();
    const message=$("#client-message").value.trim();
    if (!topic.value || name.length<2 || name.length>80 || !validPhone(phone) || !$("#lead-consent").checked) {
      show("Укажите тему, имя, телефон из 11 цифр и согласие на обработку данных.",true); return;
    }
    if (!nonceReady) { await getNonce(); }
    if (!nonceReady) { show("Сейчас форма недоступна. Пожалуйста, позвоните по указанному номеру.", true); return; }
    sending=true; submit.disabled=true;
    show("Проверяем отправку обращения…");
    try {
      const payload={topic:topic.value,name,phone,message,website:$("#company-site").value,consent:true,csrf:nonce,request_id:requestId,page:sanitizeRoute(),yclid:(params.get("yclid")||"").slice(0,150),...utm};
      const res=await fetch("api/lead.php",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify(payload)});
      const data=await res.json().catch(()=>({}));
      if (!res.ok || data.status!=="accepted") throw new Error("CRM_NOT_CONFIRMED");
      show("Обращение принято и зарегистрировано. С вами свяжутся для уточнения деталей.",false,true);
      form.reset();
      requestId = crypto.randomUUID();
      goal("landing_crm_accepted");
    } catch {
      show("Не удалось подтвердить регистрацию обращения. Позвоните нам или попробуйте позже.",true);
    } finally {
      sending=false;submit.disabled=false;await getNonce();
    }
  });
})();