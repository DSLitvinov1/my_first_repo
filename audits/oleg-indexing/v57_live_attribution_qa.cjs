'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('/home/cloudagent/cloud-browser/node_modules/playwright');
const base='/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118';
const root=base+'/.private-v53-offline/release-a';
const sites=[{host:'potrebpravo.ru',form:'crm_form_fhi3n',counter:114249897,first:'vozvrat-deneg.html',second:'pretenziya-prodavcu.html'},{host:'semya-yurist.ru',form:'crm_form_ep5fd',counter:114251443,first:'alimenty.html',second:'razvod.html'}];
const rows=[];
const check=(r,name,value)=>{r.checks.push({name,pass:!!value});if(!value)r.failures.push(name)};
function ctype(f){if(f.endsWith('.html'))return 'text/html; charset=utf-8';if(f.endsWith('.js'))return 'application/javascript; charset=utf-8';if(f.endsWith('.css'))return 'text/css; charset=utf-8';if(f.endsWith('.svg'))return 'image/svg+xml';if(f.endsWith('.json'))return 'application/json';if(f.endsWith('.xml'))return 'application/xml';return 'application/octet-stream';}
async function context(browser,site){
 const ctx=await browser.newContext({viewport:{width:390,height:844},isMobile:true,locale:'ru-RU'});
 const network={bitrixPost:0,yandex:0,blockedExternal:0,local:0};
 await ctx.route('**/*',async route=>{
  const request=route.request(),u=new URL(request.url());
  if(request.method()==='POST'&&/bitrix24/.test(u.hostname)){network.bitrixPost++;return route.abort()}
  if(u.hostname===site.host){network.local++;return route.continue()}
  if(u.hostname==='mc.yandex.ru'||u.hostname.includes('yandex.')){network.yandex++;return route.fulfill({status:200,contentType:'application/javascript',body:'/* mocked analytics */'})}
  network.blockedExternal++;return route.abort();
 });
 return {ctx,network};
}
async function getLink(page){
 return page.evaluate(()=>{const a=document.querySelector('section.cta .oleg-direct-crm-link a');if(!a)return null;a.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});a.click();return a.href;});
}
const url=(site,page,query='')=>'https://'+site.host+'/services/'+page+query;
function qp(href){return href?Object.fromEntries(new URL(href).searchParams.entries()):{}}
async function run(browser,site,mode){
 const {ctx,network}=await context(browser,site),r={site:site.host,mode,checks:[],failures:[],errors:[],network};
 const page=await ctx.newPage();page.on('pageerror',e=>r.errors.push('PAGE:'+e.message.slice(0,130)));
 try{
  const q='?utm_source=legalsearch&utm_medium=cpc&utm_campaign=olegv52&utm_content=promo&utm_term=razvod&yclid=1234567890&phone=79999999999&email=x%40example.org&token=secret';
  await page.goto(url(site,site.first,q),{waitUntil:'domcontentloaded',timeout:16000});await page.waitForSelector('#oleg-analytics-choice');
  const initial=await page.evaluate(()=>({started:!!window.__olegAnalyticsStarted,stored:sessionStorage.getItem('oleg.campaign.v52')}));
  check(r,'no tracking before choice',!initial.started&&!initial.stored);
  await page.locator('#oleg-analytics-choice [data-'+(mode==='deny'?'deny':'allow')+']').click();
  await page.waitForTimeout(70);
  const state=await page.evaluate(()=>({stored:sessionStorage.getItem('oleg.campaign.v52'),started:!!window.__olegAnalyticsStarted,choice:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value}));
  check(r,'explicit choice persisted',state.choice===(mode==='deny'?'no':'yes'));
  check(r,'consent-controlled storage',mode==='deny'?!state.stored:!!state.stored);
  check(r,'consent-controlled Metrika start',mode==='deny'?!state.started:state.started);
  const direct=await getLink(page),a=qp(direct);
  check(r,'first-page UTM preserved',a.utm_source==='legalsearch'&&a.utm_campaign==='olegv52'&&a.utm_term==='razvod');
  check(r,'YCLID preserved with numeric validation',a.yclid==='1234567890');
  check(r,'PII and arbitrary URL values not forwarded',!('phone' in a)&&!('email' in a)&&!('token' in a));
  check(r,'own form only',direct.includes('/'+site.form+'/')&&!direct.includes(site.form==='crm_form_fhi3n'?'crm_form_ep5fd':'crm_form_fhi3n'));
  await page.goto(url(site,site.second),{waitUntil:'domcontentloaded',timeout:16000});
  await page.waitForTimeout(70);
  const carried=await getLink(page),b=qp(carried);
  check(r,'second-page UTM respects consent',mode==='deny'?!('utm_source' in b):b.utm_source==='legalsearch'&&b.utm_campaign==='olegv52');
  check(r,'second-page YCLID respects consent',mode==='deny'?!('yclid' in b):b.yclid==='1234567890');
  check(r,'no PII after internal navigation',!('phone' in b)&&!('email' in b)&&!('token' in b));
  await page.locator('#legal-help-toggle').click();
  await page.locator('#legal-help-panel button.legal-primary').click();
  const assistant=await page.evaluate(()=>({frame:document.querySelector('#legal-help-form-step iframe')?.src,open:document.querySelector('#legal-help-form-step a.legal-open')?.href,goal:window.ym?.a&&Array.from(window.ym.a).filter(x=>x[1]==='reachGoal').map(x=>x[2])||[]}));
  const f=qp(assistant.frame);
  check(r,'assistant source matches own form',assistant.frame?.includes('/'+site.form+'/')&&assistant.open?.includes('/'+site.form+'/'));
  check(r,'assistant campaign respects choice',mode==='deny'?!('utm_source' in f):f.utm_source==='legalsearch'&&f.utm_campaign==='olegv52');
  check(r,'assistant YCLID respects choice',mode==='deny'?!('yclid' in f):f.yclid==='1234567890');
  check(r,'assistant does not leak PII',!('phone' in f)&&!('email' in f)&&!('token' in f));
  check(r,'no CRM POST',network.bitrixPost===0);
  if(mode==='deny')check(r,'denial never loaded Yandex analytics',network.yandex===0);
 }catch(e){r.errors.push(String(e).slice(0,230))}
 await ctx.close();
 rows.push(r);
 console.log('CASE',JSON.stringify({site:r.site,mode:r.mode,passed:r.checks.filter(x=>x.pass).length,failed:r.failures,errors:r.errors}));
}
(async()=>{let browser;try{
 browser=await chromium.launch({headless:true,executablePath:'/home/cloudagent/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 for(const site of sites)for(const mode of ['deny','allow'])await run(browser,site,mode);
}finally{
 await browser?.close();
 const checks=rows.reduce((x,r)=>x+r.checks.length,0),failed=rows.reduce((x,r)=>x+r.failures.length+r.errors.length,0);
 const report={mode:'LIVE HTTPS production browser, external analytics mocked; NO CRM POST',rows,cases:rows.length,checks,failed};
 fs.writeFileSync(base+'/.private-v57-offline/v57-live-attribution-browser-qa.json',JSON.stringify(report,null,2));
 console.log('SUMMARY',JSON.stringify({cases:rows.length,checks,failed}));
 process.exit(failed?1:0);
}})().catch(e=>{console.error('FATAL',String(e));process.exit(2)});