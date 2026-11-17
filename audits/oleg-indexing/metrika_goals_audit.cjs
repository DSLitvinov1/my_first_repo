'use strict';
/**
 * Oleg: evidence-first Playwright Yandex Metrika goal audit.
 * Read-only real websites. Intercepts ALL Yandex tracker HTTP traffic and
 * BLOCKS ALL non-GET requests, so never makes a CRM lead or live visit.
 */
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const SITES=[
 {host:'potrebpravo.ru',counter:114249897,form:'crm_form_fhi3n'},
 {host:'semya-yurist.ru',counter:114251443,form:'crm_form_ep5fd'}
];
const truncate=x=>String(x||'').replace(/\s+/g,' ').trim().slice(0,220);
function scan(text){
 const lines=String(text).split(/\r?\n/);
 const refs=[];
 for(let i=0;i<lines.length;i++){
  if(/reachGoal|lead_success|goal[_-]|postMessage|dataLayer|bitrix|ym\(|analytics\.choice|clickmap|trackLinks/i.test(lines[i]))
   refs.push({line:i+1,text:truncate(lines[i])});
 }
 return {length:text.length,reachGoalMentions:(text.match(/reachGoal/g)||[]).length,
   goalIdentifiers:[...new Set([...text.matchAll(/['"]((?:lead|form|consult|call|phone|email|chat|contact|application)[-_][a-z_0-9-]+)['"]/gi)].map(x=>x[1]))].slice(0,40),
   evidence:refs.slice(0,45)};
}
async function main(){
 const browser=await chromium.launch({headless:true});
 const api=await request.newContext({timeout:22000,ignoreHTTPSErrors:false});
 const output={checked:new Date().toISOString(),scope:'actual public Playwright UI, no Yandex telemetry or Bitrix writes',sites:[],warnings:[]};
 try{
  for(const site of SITES){
   const report={host:site.host,counter:site.counter,form:site.form,assets:[],pages:[],trafficBlocked:0,writesBlocked:0};
   output.sites.push(report);
   const context=await browser.newContext({viewport:{width:390,height:844},locale:'ru-RU'});
   const requestOrigins=new Map();
   await context.route('**/*',async route=>{
    const req=route.request(),url=req.url(),method=req.method().toUpperCase();
    if(!['GET','HEAD','OPTIONS'].includes(method)){report.writesBlocked++;return route.abort('blockedbyclient');}
    if(/^https?:\/\/(?:mc\.yandex\.(?:ru|com)|.*\.yandex\.(?:ru|com)\/metrika)/i.test(url)){
      report.trafficBlocked++;return route.fulfill({status:200,contentType:'application/javascript',body:'/* Metrika blocked in Playwright test */'});
    }
    return route.continue();
   });
   const page=await context.newPage();
   const errors=[];page.on('pageerror',e=>errors.push(truncate(e.message)));
   for(const path of ['/','/services/'+(site.host==='potrebpravo.ru'?'vozvrat-deneg':'razvod')+'.html']){
    const v={path};
    report.pages.push(v);
    try{
     const response=await page.goto('https://'+site.host+path,{waitUntil:'domcontentloaded',timeout:28000});
     v.http=response?.status()||0;v.ymPresent=await page.evaluate(()=>typeof window.ym==='function');
     const scriptAssets=await page.locator('script[src]').evaluateAll(xs=>xs.map(x=>x.src).filter(x=>/oleg-analytics|legal-assistant/i.test(x)));
     v.scripts=scriptAssets;
     for(const asset of scriptAssets.filter(x=>!report.assets.some(y=>y.url===x))){
      const data={url:asset};
      report.assets.push(data);
      const res=await api.get(asset,{failOnStatusCode:false});
      data.http=res.status();data.scan=scan(await res.text());
     }
     if(path==='/'){
      const consent=page.locator('#oleg-analytics-choice');
      const allow=page.locator('#oleg-analytics-choice [data-allow]');
      v.consentPresent=await consent.count()===1;
      if(v.consentPresent&&await consent.isVisible()&&await allow.isVisible()){
       await allow.click({timeout:8000});
       await page.waitForTimeout(180);
      }
      v.initCalls=await page.evaluate(()=>Array.isArray(window.ym?.a)?window.ym.a.map(a=>({id:String(a[0]),method:String(a[1])})).slice(0,30):[]);
      // Wrap the local queue function AFTER opt-in. Don't send any events to Yandex:
      // outbound hosts were already intercepted by the context route.
      await page.evaluate(()=>{
       window.__olegGoalCalls=[];
       if(typeof window.ym==='function'){
        const original=window.ym;
        window.ym=function(...args){
         window.__olegGoalCalls.push({counter:String(args[0]),method:String(args[1]),goal:typeof args[2]==='string'?args[2]:null});
         return original.apply(this,args);
        };
       }
      });
      const tel=page.locator('a[href^="tel:"]').first();
      if(await tel.count()){
       await tel.evaluate(el=>{
        el.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});
        el.click();
       });
      }
      v.afterPhone=await page.evaluate(()=>window.__olegGoalCalls||[]);
      const mail=page.locator('a[href^="mailto:"]').first();
      if(await mail.count()){
       await mail.evaluate(el=>{
        el.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});
        el.click();
       });
      }
      v.afterEmail=await page.evaluate(()=>window.__olegGoalCalls||[]);
      const toggle=page.locator('#legal-help-toggle');
      if(await toggle.count()&&await toggle.isVisible()){
       await toggle.click({timeout:6000});
       await page.waitForTimeout(120);
       v.assistantPanelOpened=await page.locator('#legal-help-panel').isVisible();
       v.afterAssistant=await page.evaluate(()=>window.__olegGoalCalls||[]);
       const cta=page.getByRole('button',{name:'Передать вопрос юристу',exact:true});
       if(await cta.count()&&await cta.isVisible()){
        await cta.click({timeout:7000});
        await page.waitForTimeout(500);
        v.iframeUrl=await page.locator('iframe.legal-frame').getAttribute('src');
        v.afterFormShown=await page.evaluate(()=>window.__olegGoalCalls||[]);
       }
      }
     }
     v.pageErrors=errors.splice(0);
    }catch(e){v.error=truncate(e.message);output.warnings.push(site.host+' '+path+' '+v.error);}
   }
   await context.close();
   console.log('METRIKA_GOALS_SITE',JSON.stringify({
    host:site.host,counter:site.counter,
    pages:report.pages.map(p=>({path:p.path,http:p.http,init:p.initCalls,afterPhone:p.afterPhone,afterEmail:p.afterEmail,
     afterAssistant:p.afterAssistant,form:p.iframeUrl,afterFormShown:p.afterFormShown,errors:p.pageErrors,error:p.error})),
    assets:report.assets.map(a=>({url:a.url,http:a.http,reachGoalMentions:a.scan?.reachGoalMentions,goalIdentifiers:a.scan?.goalIdentifiers,evidence:a.scan?.evidence?.slice(0,24)})),
    blockedTrackerCalls:report.trafficBlocked,blockedWrites:report.writesBlocked
   }));
  }
 }finally{await browser.close();await api.dispose()}
 await fs.writeFile('oleg-metrika-goals-audit.json',JSON.stringify(output,null,2));
 console.log('METRIKA_GOALS_SUMMARY',JSON.stringify(output.sites.map(s=>({host:s.host,assetCount:s.assets.length,
  allAssets200:s.assets.every(a=>a.http===200),hasGoalSource:s.assets.some(a=>(a.scan?.reachGoalMentions||0)>0),
  pages:s.pages.map(x=>({path:x.path,http:x.http})),blockedTracker:s.trafficBlocked,
  goalsOnPhone:s.pages[0]?.afterPhone,goalsOnMail:s.pages[0]?.afterEmail,
  goalsOnAssistant:s.pages[0]?.afterAssistant,goalsOnFormOpen:s.pages[0]?.afterFormShown}))));
 if(output.sites.some(x=>x.pages.some(p=>p.http!==200||p.error)))process.exitCode=2;
}
main().catch(e=>{console.error('METRIKA_GOALS_FATAL',truncate(e.message));process.exitCode=1});
