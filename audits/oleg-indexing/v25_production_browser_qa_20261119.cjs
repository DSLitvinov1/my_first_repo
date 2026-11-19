'use strict';
// Real production UI checks, read-only Bitrix. All outgoing Metrika requests mocked.
const fs=require('node:fs');
const {chromium}=require('/home/cloudagent/cloud-browser/node_modules/playwright');
const ROOT='/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118/.private-v25-offline';
const results=[],time=new Date().toISOString();
const sites=[{host:'potrebpravo.ru',form:'crm_form_fhi3n',counter:114249897},{host:'semya-yurist.ru',form:'crm_form_ep5fd',counter:114251443}];
const viewportModes=[{name:'mobile',width:390,height:844},{name:'desktop',width:1440,height:900}];
const report={time,source:'actual public production sites',browser:'isolated Linux headless Chrome, simulated mobile/desktop',safety:'NO POST to Bitrix; Yandex analytics requests intercepted and mocked; no CRM deals created',results};
const check=(r,name,pass,value)=>{r.checks.push({name,pass:!!pass});if(!pass)r.errors.push({name,value})};
const js=async (page)=>page.evaluate(()=>{
 const panel=document.getElementById('oleg-analytics-choice');
 const banner=panel?.getBoundingClientRect();
 const links=[...document.querySelectorAll('a[href*="crm_form_"]')].map(a=>({url:a.href,visible:a.getBoundingClientRect().height>0}));
 return{title:document.title,h1:[...document.querySelectorAll('h1')].map(x=>x.textContent.trim()),innerWidth,scrollWidth:document.documentElement.scrollWidth,consentVisible:!!panel&&!panel.hidden,started:!!window.__olegAnalyticsStarted,brokenImages:[...document.images].filter(x=>x.complete&&!x.naturalWidth).map(x=>x.src.slice(0,120)),banner:banner&&{left:banner.left,right:banner.right},links}
});
async function run(browser,site,mode){
 const ctx=await browser.newContext({viewport:{width:mode.width,height:mode.height},deviceScaleFactor:mode.name==='mobile'?2:1,locale:'ru-RU',isMobile:mode.name==='mobile'});
 const r={site:site.host,viewport:mode.name,checks:[],errors:[],observed:{},pageErrors:[],analyticsIntercepted:0,attemptedCrmPost:0};
 await ctx.route('**/*',async route=>{
  const url=route.request().url(),method=route.request().method();
  if(/(?:^https?:\/\/|\/\/)(?:[^/]+\.)?yandex\.(?:ru|com|net)\//i.test(url)||url.includes('mc.yandex.ru/')){
   r.analyticsIntercepted++;
   await route.fulfill({status:200,contentType:'application/javascript',body:'/* blocked during QA */'});return
  }
  if(method==='POST' && /bitrix24site\.ru|bitrix24\.ru/.test(url)){r.attemptedCrmPost++;await route.abort();return}
  await route.continue();
 });
 const page=await ctx.newPage();page.on('pageerror',e=>r.pageErrors.push(e.message.slice(0,160)));
 try{
  await page.goto('https://'+site.host+'/?utm_source=qa_internal&utm_medium=test&utm_campaign=qa_browser_20261119&utm_content='+mode.name+'&phone=must_not_transfer',{waitUntil:'domcontentloaded',timeout:20000});
  await page.waitForSelector('#oleg-analytics-choice',{timeout:10000});
  await page.waitForTimeout(500);
  const initial=await js(page);r.observed.initial=initial;
  check(r,'public title and single H1',!!initial.title &&initial.h1.length===1,initial.h1);
  check(r,'no horizontal overflow',initial.scrollWidth<=mode.width+2,{actual:initial.scrollWidth,expected:mode.width});
  check(r,'no broken loaded images',initial.brokenImages.length===0,initial.brokenImages);
  check(r,'no analytics before consent',initial.consentVisible&&!initial.started);
  check(r,'consent panel fits viewport',initial.banner?.left>=-1&&initial.banner?.right<=mode.width+2,initial.banner);
  check(r,'own Bitrix form CTA',initial.links.some(x=>x.url.includes('/'+site.form+'/')&&x.visible),initial.links);
  check(r,'no cross-site form CTA',initial.links.every(x=>!x.url.includes(site.form==='crm_form_fhi3n'?'crm_form_ep5fd':'crm_form_fhi3n')));
  if(mode.name==='mobile'){
   await page.locator('#oleg-analytics-choice [data-deny]').click();
   const refused=await page.evaluate(()=>({choice:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value,started:!!window.__olegAnalyticsStarted,panelHidden:document.getElementById('oleg-analytics-choice')?.hidden}));
   check(r,'denial stored and tracking not started',refused.choice==='no'&&!refused.started&&refused.panelHidden,refused);
   const deniedForm=await page.evaluate(()=>{const a=[...document.querySelectorAll('a[href*="crm_form_"]')].find(x=>x.getBoundingClientRect().height>0);if(!a)return{error:'no CTA'};a.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});a.click();return{url:a.href,started:!!window.__olegAnalyticsStarted,queued:window.ym?.a||[]}});
   r.observed.deniedForm=deniedForm;
   check(r,'refused consent still passes safe UTM',deniedForm.url?.includes('utm_source=qa_internal')&&!deniedForm.url?.includes('phone=must_not_transfer'),deniedForm.url);
   check(r,'no goal on declined consent',!deniedForm.started&&!deniedForm.queued.length);
   await page.reload({waitUntil:'domcontentloaded',timeout:15000});
   const afterReload=await page.evaluate(()=>({choice:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value,started:!!window.__olegAnalyticsStarted,panelHidden:document.querySelector('#oleg-analytics-choice')?.hidden}));
   check(r,'refusal survives reload',afterReload.choice==='no'&&!afterReload.started&&afterReload.panelHidden,afterReload);
   await page.locator('#oleg-analytics-settings').click();
   await page.locator('#oleg-analytics-choice [data-allow]').click();
   await page.waitForTimeout(250);
   const allowed=await page.evaluate(()=>({choice:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value,started:!!window.__olegAnalyticsStarted,calls:window.ym?.a||[]}));
   check(r,'correct Yandex counter started only after allow',allowed.started&&allowed.choice==='yes'&&allowed.calls.some(x=>x[0]===site.counter&&x[1]==='init'),allowed);
   const withGoal=await page.evaluate(()=>{const o=window.ym;window.__qaGoals=[];window.ym=function(...a){window.__qaGoals.push(a);return o?.apply(this,a)};window.ym.a=o?.a;const a=[...document.querySelectorAll('a[href*="crm_form_"]')].find(x=>x.getBoundingClientRect().height>0);if(a){a.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});a.click()}return{url:a?.href,goals:window.__qaGoals.map(x=>x.slice(0,3))}});
   r.observed.withGoal=withGoal;
   check(r,'CRM intent goal emitted',withGoal.goals.some(x=>x[0]===site.counter&&x[1]==='reachGoal'&&x[2]==='oleg_crm_form_open'),withGoal.goals);
   check(r,'form URL has allowlisted UTM not phone',withGoal.url?.includes('utm_campaign=qa_browser_20261119')&&!withGoal.url?.includes('phone='),withGoal.url);
   await page.locator('#legal-help-toggle').click();
   await page.waitForTimeout(1450);
   const assistant=await page.evaluate(()=>{
    const toggle=document.querySelector('#legal-help-toggle'),panel=document.querySelector('#legal-help-panel'),box=panel?.getBoundingClientRect();
    return{expanded:toggle?.getAttribute('aria-expanded'),hidden:panel?.hidden,visible:box?.width>0&&box?.height>0,rect:box?{width:box.width,height:box.height}:null,goals:window.__qaGoals?.map(x=>x.slice(0,3))||[],iframes:[...document.querySelectorAll('#legal-help-panel iframe')].map(x=>x.src)}
   });r.observed.assistant=assistant;
   check(r,'assistant opened visibly',assistant.expanded==='true'&&!assistant.hidden&&assistant.visible,assistant);
   check(r,'assistant open goal emitted after UI opens',assistant.goals.some(x=>x[0]===site.counter&&x[2]==='oleg_consultation_open'),assistant.goals);
  }
  check(r,'no Bitrix POST attempted',r.attemptedCrmPost===0,r.attemptedCrmPost);
 }catch(e){r.errors.push({name:'QA_EXCEPTION',value:String(e).slice(0,330)})}
 finally{await ctx.close()}
 console.log('RESULT',JSON.stringify({site:r.site,viewport:r.viewport,passed:r.checks.filter(x=>x.pass).length,failed:r.checks.filter(x=>!x.pass).map(x=>x.name),errors:r.errors,pageErrors:r.pageErrors.slice(0,3)}));
 return r;
}
(async()=>{let browser;try{
 browser=await chromium.launch({headless:true,executablePath:'/home/cloudagent/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 for(const site of sites)for(const mode of viewportModes)results.push(await run(browser,site,mode));
 }catch(e){report.fatal=String(e);console.log('FATAL',String(e))}
 finally{if(browser)await browser.close();fs.writeFileSync(ROOT+'/v25-browser-qa-20261119.json',JSON.stringify(report,null,2));console.log('SUMMARY',JSON.stringify({cases:results.length,checks:results.reduce((n,x)=>n+x.checks.length,0),failures:results.flatMap(x=>x.errors),fatal:report.fatal||null}));process.exit(0)}})();
