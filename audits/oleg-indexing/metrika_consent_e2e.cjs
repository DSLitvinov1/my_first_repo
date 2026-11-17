'use strict';
// Real DOM browser regression test of consent analytics, with external Metrika calls mocked.
// Never submit forms or send analytics event requests to Yandex.
const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const SITES=[
 {host:'potrebpravo.ru',counter:'114249897'},
 {host:'semya-yurist.ru',counter:'114251443'}
];
function assert(value,message){if(!value)throw Error(message)}
async function main(){
 const browser=await chromium.launch({headless:true});
 const report={time:new Date().toISOString(),type:'Playwright Metrika consent interaction, all Yandex requests intercepted',results:[],errors:[]};
 try{
  for(const site of SITES){
   const context=await browser.newContext({viewport:{width:390,height:844},locale:'ru-RU'});
   let intercepted=0;
   await context.route(/https?:\/\/(?:[^/]+\.)?yandex\.(?:ru|com|net)\/.*|https?:\/\/mc\.yandex\.ru\/.*/i,async route=>{
    intercepted++;
    await route.fulfill({status:200,contentType:'application/javascript',body:'/* consent test only: no live analytics */'});
   });
   const page=await context.newPage();
   const result={host:site.host,checks:[],intercepted:0};
   report.results.push(result);
   const check=(name,okay)=>{result.checks.push({name,passed:!!okay});if(!okay)report.errors.push(site.host+' '+name)};
   try{
    await page.goto('https://'+site.host+'/',{waitUntil:'domcontentloaded',timeout:25000});
    await page.locator('#oleg-analytics-choice').waitFor({timeout:10000});
    const pre=await page.evaluate(()=>({
     started:!!window.__olegAnalyticsStarted,
     panelVisible:!document.querySelector('#oleg-analytics-choice')?.hidden,
     assetScripts:[...document.querySelectorAll('script[src]')].filter(s=>/metrika\/tag\.js|mc\.yandex\.ru/.test(s.src)).length,
     geometry:(()=>{
      const rect=document.querySelector('#oleg-analytics-choice').getBoundingClientRect();
      return {left:rect.left,right:rect.right};
     })()
    }));
    check('No tracking before consent',!pre.started&&pre.assetScripts===0);
    check('Consent banner visible',pre.panelVisible);
    check('Banner fits 390px mobile viewport',pre.geometry.left>=0&&pre.geometry.right<=391);
    await page.locator('#oleg-analytics-choice [data-deny]').click();
    const refused=await page.evaluate(()=>({
     started:!!window.__olegAnalyticsStarted,
     panelHidden:document.querySelector('#oleg-analytics-choice')?.hidden,
     saved:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value
    }));
    check('Deny stores choice without analytics',!refused.started&&refused.saved==='no'&&refused.panelHidden);
    await page.reload({waitUntil:'domcontentloaded'});
    const reloadDeny=await page.evaluate(()=>({
     started:!!window.__olegAnalyticsStarted,
     panelHidden:document.querySelector('#oleg-analytics-choice')?.hidden
    }));
    check('Deny survives reload',!reloadDeny.started&&reloadDeny.panelHidden);
    await page.locator('#oleg-analytics-settings').click();
    await page.locator('#oleg-analytics-choice [data-allow]').click();
    const allow=await page.evaluate(()=>({
     started:!!window.__olegAnalyticsStarted,
     saved:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value,
     calls:(window.ym?.a||[]).map(args=>({
      counter:String(args[0]),method:args[1],
      options:args[2]&&{webvisor:args[2].webvisor,clickmap:args[2].clickmap,trackLinks:args[2].trackLinks}
     }))
    }));
    check('Allow starts correct counter and stores consent',allow.started&&allow.saved==='yes'&&allow.calls.some(c=>c.counter===site.counter&&c.method==='init'&&c.options?.webvisor===false&&c.options?.clickmap===false));
    await page.locator('#oleg-analytics-settings').click();
    const didReload=page.waitForEvent('domcontentloaded',{timeout:12000});
    await page.locator('#oleg-analytics-choice [data-deny]').click();
    await didReload;
    const revoked=await page.evaluate(()=>({
     saved:JSON.parse(localStorage.getItem('oleg.analytics.choice.v1')||'null')?.value,
     started:!!window.__olegAnalyticsStarted
    }));
    check('Consent can be revoked',revoked.saved==='no'&&!revoked.started);
    result.intercepted=intercepted;
   }catch(e){
    report.errors.push(site.host+' TEST_EXCEPTION '+String(e.message).slice(0,320));
   }finally{await context.close()}
   console.log('METRIKA_CONSENT',JSON.stringify(result));
  }
 }finally{await browser.close()}
 await fs.writeFile('oleg-metrika-consent-e2e.json',JSON.stringify(report,null,2));
 console.log('METRIKA_CONSENT_RESULT',JSON.stringify({sites:report.results.length,errors:report.errors}));
 if(report.errors.length)process.exitCode=2;
}
main().catch(e=>{console.error('METRIKA_CONSENT_AUDIT_FAILED',e.message);process.exitCode=1});
