import { spawn } from "node:child_process";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";
const root = path.resolve(import.meta.dirname, "..");
const preview = path.resolve(root, "..", "..", "..", "oleg-services-landing-preview");
const port=19264, debug=19265;
const chromium=process.env.CHROME_BIN||"/usr/bin/chromium";
const tmp=mkdtempSync(path.join(os.tmpdir(),"oleg-services-browser-"));
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let server,chrome,ws;
try {
 assert(existsSync(chromium),"Chrome binary unavailable");
 assert(existsSync(preview),"preview folder unavailable");
 server=spawn("python3",["-m","http.server",String(port),"--bind","127.0.0.1","--directory",preview],{stdio:"ignore"});
 chrome=spawn(chromium,["--headless","--no-sandbox","--disable-gpu","--disable-dev-shm-usage","--remote-allow-origins=*","--remote-debugging-port="+debug,"--user-data-dir="+tmp,"about:blank"],{stdio:"ignore"});
 const get=async(path)=>{
  for(let i=0;i<45;i++){
   try{const r=await fetch(path);if(r.ok)return r;}catch{}
   await sleep(100);
  }
  throw Error("server unavailable: "+path);
 };
 await get("http://127.0.0.1:"+port+"/");
 await get("http://127.0.0.1:"+debug+"/json/version");
 const tab=await fetch("http://127.0.0.1:"+debug+"/json/new?about:blank",{method:"PUT"}).then(r=>r.json());
 ws=new WebSocket(tab.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject});
 let n=0;
 const pending=new Map();
 ws.onmessage=(ev)=>{
  const p=JSON.parse(ev.data);
  if(!p.id||!pending.has(p.id))return;
  const {resolve,reject}=pending.get(p.id);pending.delete(p.id);
  if(p.error)reject(Error(p.error.message));else resolve(p.result);
 };
 const call=(method,params={})=>new Promise((resolve,reject)=>{
  const id=++n;pending.set(id,{resolve,reject});
  ws.send(JSON.stringify({id,method,params}));
 });
 const evaluate=async(expr)=>{
  const res=await call("Runtime.evaluate",{expression:expr,returnByValue:true,awaitPromise:true});
  if(res.exceptionDetails)throw Error("Runtime exception: "+JSON.stringify(res.exceptionDetails));
  return res.result.value;
 };
 await call("Page.enable");
 await call("Runtime.enable");
 for(const [width,height] of [[1440,900],[390,844]]){
  await call("Emulation.setDeviceMetricsOverride",{width,height,deviceScaleFactor:1,mobile:width<700});
  await call("Page.navigate",{url:"http://127.0.0.1:"+port+"/?service=documents&topic="+encodeURIComponent("Наследство")+"&utm_source=yandex"});
  await sleep(550);
  const initial=await evaluate("({w:innerWidth,scroll:document.documentElement.scrollWidth,h1:document.querySelectorAll('h1').length,menus:document.querySelectorAll('header nav a').length,steps:[document.querySelector('#step-one').hidden,document.querySelector('#step-two').hidden],service:document.querySelector('input[name=service]:checked')?.value,topic:document.querySelector('#topic').value,preview:document.documentElement.dataset.preview,form:!!document.querySelector('#lead-form')})");
  assert(initial.scroll<=initial.w+1,"horizontal overflow "+JSON.stringify(initial));
  assert(initial.h1===1&&initial.menus===3&&initial.form);
  assert(initial.steps[0]===false&&initial.steps[1]===true);
  assert(initial.service==="documents"&&initial.topic==="Наследство"&&initial.preview==="true");
  // Cannot move forward without required contact data.
  await evaluate("document.querySelector('#step-next').click()");
  assert((await evaluate("document.querySelector('#lead-status').textContent")).includes("имя"));
  await evaluate("document.querySelector('#client-name').value='Тестовый посетитель';document.querySelector('#client-phone').value='+7 (999) 000-00-00';document.querySelector('#client-message').value='Нужна помощь с наследством';document.querySelector('#step-next').click()");
  const second=await evaluate("({a:document.querySelector('#step-one').hidden,b:document.querySelector('#step-two').hidden,count:document.querySelector('#step-counter').textContent,options:document.querySelectorAll('input[name=service]').length})");
  assert(second.a&&!second.b&&second.count.includes("02")&&second.options===5,JSON.stringify(second));
  await evaluate("document.querySelector('#step-back').click()");
  assert(await evaluate("!document.querySelector('#step-one').hidden"));
  await evaluate("document.querySelector('#step-next').click()");
  await evaluate("document.querySelector('#lead-submit').click()");
  assert((await evaluate("document.querySelector('#lead-status').textContent")).includes("согласие"));
  await evaluate("document.querySelector('#lead-consent').checked=true;document.querySelector('#lead-submit').click()");
  assert((await evaluate("document.querySelector('#lead-status').textContent")).includes("предпросмотр"));
  assert(!(await evaluate("!!window.ym")),"analytics loaded in preview");
  // On-screen directions select the correct topic.
  await evaluate("document.querySelector('[data-topic=\"Трудовой спор\"]').click()");
  assert((await evaluate("document.querySelector('#topic').value"))==="Трудовой спор");
  // The newly requested subjects must also preselect the actual CRM value.
  await evaluate("document.querySelector('[data-topic=\"Арбитражные споры по договору подряда\"]').click()");
  assert((await evaluate("document.querySelector('#topic').value"))==="Арбитражные споры по договору подряда");
  assert((await evaluate("document.querySelectorAll('[data-topic]').length"))===14);

  // ChatGPT may append a referral marker. Hide only that marker, retain unrelated parameters.
  await call("Page.navigate", {url:"http://127.0.0.1:"+port+"/?utm_source=chatgpt.com&utm_campaign=original&topic="+encodeURIComponent("Наследство")});
  await sleep(550);
  const clean=await evaluate("({source:new URL(location.href).searchParams.get('utm_source'),campaign:new URL(location.href).searchParams.get('utm_campaign'),topic:document.querySelector('#topic').value})");
  assert(clean.source===null && clean.campaign==="original" && clean.topic==="Наследство", "referral cleanup failed: "+JSON.stringify(clean));
  await call("Page.navigate", {url:"http://127.0.0.1:"+port+"/?utm_source=yandex&utm_campaign=original&topic="+encodeURIComponent("Наследство")});
  await sleep(550);
  assert((await evaluate("new URL(location.href).searchParams.get('utm_source')"))==="yandex", "real paid attribution removed");
  console.log("PASS browser",width,"navigation, wizard, 5 services, preview blocked, attribution, no overflow");
 }
}finally{
 try{ws?.close()}catch{}
 try{chrome?.kill("SIGTERM")}catch{}
 try{server?.kill("SIGTERM")}catch{}
 await sleep(100);
 rmSync(tmp,{recursive:true,force:true});
}
