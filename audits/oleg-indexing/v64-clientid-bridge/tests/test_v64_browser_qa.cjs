'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('/home/cloudagent/cloud-browser/node_modules/playwright');
const ROOT='/home/cloudagent/projects/oleg-seo-v26-clientid-bridge-20261120';
const HOSTS=[
 {host:'potrebpravo.ru',counter:114249897,form:'crm_form_fhi3n'},
 {host:'semya-yurist.ru',counter:114251443,form:'crm_form_ep5fd'}
];
const CLIENT='1700654321987654321';
const results=[];
function mime(file) {
 let ext=path.extname(file).toLowerCase();
 return {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp','.jpg':'image/jpeg','.json':'application/json'}[ext]||'application/octet-stream';
}
function verify(r,name,ok){r.checks.push({name,pass:!!ok});if(!ok)r.failures.push(name)}
async function run(browser,site,consentMode) {
 let ctx=await browser.newContext({viewport:{width:450,height:860},isMobile:true,locale:'ru-RU',serviceWorkers:'block'});
 const r={host:site.host,consent:consentMode,checks:[],failures:[],errors:[],externalPost:0,externalGet:0,yandexGet:0};
 try {
  await ctx.route('**/*',async route=>{
   let req=route.request(),url=new URL(req.url());
   if(req.method()!=='GET'){r.externalPost++;return route.abort()}
   if(url.hostname===site.host){
    let root=path.join(ROOT,'live-rebased',site.host,'public_html');
    let target=path.resolve(root,'.'+decodeURIComponent(url.pathname));
    if(!target.startsWith(root+path.sep)&&target!==root)return route.fulfill({status:403,body:'denied'});
    if(fs.existsSync(target)&&fs.statSync(target).isDirectory())target=path.join(target,'index.html');
    if(fs.existsSync(target)&&fs.statSync(target).isFile())return route.fulfill({status:200,contentType:mime(target),body:fs.readFileSync(target)});
    return route.fulfill({status:404,body:'not found'});
   }
   if(url.hostname==='mc.yandex.ru'&&url.pathname.includes('/metrika/tag.js')){
    r.externalGet++;r.yandexGet++;
    const mock='(function(){var old=window.ym;var q=old&&old.a||[]; window.ym=function(c,m,f){if(m==="getClientID"&&typeof f==="function") f("'+CLIENT+'");};for(var i=0;i<q.length;i++){try{window.ym.apply(null,q[i]);}catch(e){}}})();';
    return route.fulfill({status:200,contentType:'text/javascript',body:mock});
   }
   if(url.hostname==='b24-s2dosa.bitrix24site.ru'){
    r.externalGet++;return route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Blocked CRM mock</title><body>no real posts</body>'});
   }
   r.externalGet++;return route.abort();
  });
  const page=await ctx.newPage();page.on('pageerror',x=>r.errors.push(x.message.slice(0,180)));
  const origin='https://'+site.host+'/';
  const service=site.host==='potrebpravo.ru'?'vozvrat-deneg.html':'alimenty.html';
  await page.goto(origin+'services/'+service,{waitUntil:'domcontentloaded',timeout:22000});
  await page.waitForSelector('#oleg-analytics-choice');
  verify(r,'analytics not loaded before fresh consent',await page.evaluate(()=>!window.__olegAnalyticsStarted));
  const b=await page.evaluate(()=>({bridge:!!window.__olegClientIdBridgeV1,v2:localStorage.getItem('oleg.analytics.choice.v2'),v1:localStorage.getItem('oleg.analytics.choice.v1')}));
  verify(r,'bridge active on exact site',b.bridge);
  verify(r,'old consent remains untrusted',!b.v1&&!b.v2);
  const button=page.locator('#oleg-analytics-choice [data-'+(consentMode==='yes'?'allow':'deny')+']');
  await button.click();
  await page.waitForTimeout(230);
  const state=await page.evaluate(()=>({yes:JSON.parse(localStorage.getItem('oleg.analytics.choice.v2')||'null')?.value,started:!!window.__olegAnalyticsStarted}));
  verify(r,'new consent saved',state.yes===consentMode);
  verify(r,'analytics follows consent',state.started===(consentMode==='yes'));
  await page.goto(origin,{waitUntil:'domcontentloaded',timeout:22000});
  await page.waitForTimeout(250);
  let link=await page.evaluate(()=>{
    let a=document.querySelector('a.ux-link-button[href*="b24-s2dosa.bitrix24site.ru"]');
    if(!a) return null;
    a.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});
    a.click();
    return a.href;
  });
  if(link){
   let p=new URL(link);
   verify(r,'link own hosted form',p.hostname==='b24-s2dosa.bitrix24site.ru'&&p.pathname==='/'+site.form+'/');
   verify(r,'direct link CID gated',p.searchParams.has('metrica_client_id')===(consentMode==='yes'));
   if(consentMode==='yes')verify(r,'true callback ID on form link',p.searchParams.get('metrica_client_id')===CLIENT);
  } else verify(r,'direct link discovered',false);
  await page.locator('#legal-help-toggle').click();
  await page.locator('#legal-help-panel button.legal-primary').click();
  await page.waitForTimeout(110);
  const info=await page.evaluate(()=>({frame:document.querySelector('#legal-help-form-step iframe')?.src||'',link:document.querySelector('#legal-help-form-step a.legal-open')?.href||''}));
  let url=new URL(info.frame);
  verify(r,'iframe exact own form',url.hostname==='b24-s2dosa.bitrix24site.ru'&&url.pathname==='/'+site.form+'/');
  verify(r,'iframe CID gated',url.searchParams.has('metrica_client_id')===(consentMode==='yes'));
  if(consentMode==='yes')verify(r,'iframe CID matches actual Yandex callback',url.searchParams.get('metrica_client_id')===CLIENT);
  verify(r,'no PII query in iframe',!url.searchParams.has('phone')&&!url.searchParams.has('email'));
  verify(r,'no outbound write or CRM submit',r.externalPost===0);
  verify(r,'Yandex never loaded on deny',consentMode==='yes'||r.yandexGet===0);
  await ctx.close();ctx=null;
 }catch(e){r.errors.push(String(e).slice(0,220));}
 finally{try{await ctx?.close()}catch{}}
 results.push(r);
 console.log('CASE',JSON.stringify({site:r.host,consent:r.consent,checks:r.checks.length,failures:r.failures,errors:r.errors}));
}
(async()=>{
 let browser;
 try{
  browser=await chromium.launch({headless:true,executablePath:'/home/cloudagent/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
  for(let s of HOSTS)for(let c of ['no','yes'])await run(browser,s,c);
 }finally{
  await browser?.close();
  const failed=results.reduce((n,r)=>n+r.failures.length+r.errors.length,0);
  let out={mode:'ISOLATED_V64_LOCAL_STAGE_BROWSER_ALL_EXTERNAL_MOCKED',cases:results.length,checks:results.reduce((n,r)=>n+r.checks.length,0),failed,results};
  fs.writeFileSync(ROOT+'/evidence/v64_browser_qa.json',JSON.stringify(out,null,2));
  console.log('SUMMARY',JSON.stringify({cases:out.cases,checks:out.checks,failed}));
  process.exit(failed?1:0);
 }
})().catch(e=>{console.error('FATAL',e.message);process.exit(2)});
