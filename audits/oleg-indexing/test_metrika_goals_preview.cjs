'use strict';
// Playwright evaluates staged, NOT DEPLOYED, consent-gated goal script
// on the existing live two websites. All Yandex traffic and ALL POSTs blocked.
const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const path=require('node:path');
const SITES=[
 {host:'potrebpravo.ru',counter:114249897,expected:'crm_form_fhi3n'},
 {host:'semya-yurist.ru',counter:114251443,expected:'crm_form_ep5fd'}
];
const GOALS=['oleg_phone_click','oleg_email_click','oleg_consultation_open','oleg_crm_form_open'];
const short=s=>String(s??'').replace(/\s+/g,' ').trim().slice(0,240);
async function main(){
 const out={checkedAt:new Date().toISOString(),type:'staged goals Playwright preview on live sites; zero live telemetry',sites:[],failures:[]};
 const browser=await chromium.launch({headless:true});
 try{
  for(const site of SITES){
   for(const viewport of [{width:390,height:844},{width:1440,height:900}]){
    const result={site:site.host,viewport:viewport.width,checks:[],failed:[],blockedAnalytics:0,blockedWrites:0};
    out.sites.push(result);
    const context=await browser.newContext({locale:'ru-RU',viewport});
    await context.route('**/*',async route=>{
     const req=route.request(),url=req.url();
     if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase())){
      result.blockedWrites++;return route.abort('blockedbyclient');
     }
     if(/^https?:\/\/mc\.yandex\.(?:ru|com)\//i.test(url)){
      result.blockedAnalytics++;
      return route.fulfill({status:200,contentType:'application/javascript',body:'/* no real analytics */'});
     }
     return route.continue();
    });
    const page=await context.newPage();
    const check=(name,ok,detail)=>{
     result.checks.push({name,ok:!!ok,detail:detail??null});
     if(!ok){result.failed.push(name);out.failures.push(site.host+' '+viewport.width+' '+name)}
    };
    const clickLink=async prefix=>{
     await page.evaluate(prefix=>{
      const el=document.querySelector('a[href^="'+prefix+'"]');
      if(!el)return;
      el.addEventListener('click',e=>e.preventDefault(),{capture:true,once:true});
      el.click();
     },prefix);
    };
    try{
     const response=await page.goto('https://'+site.host+'/',{waitUntil:'domcontentloaded',timeout:30000});
     check('Homepage 200',response?.status()===200);
     await page.addScriptTag({path:path.resolve(__dirname,'oleg-metrika-goals-v1.js')});
     check('No Metrika initialized before opt-in',await page.evaluate(()=>!window.__olegAnalyticsStarted));
     await clickLink('tel:');await clickLink('mailto:');
     const pre=await page.evaluate(()=>({
      started:!!window.__olegAnalyticsStarted,
      calls:Array.isArray(window.ym?.a)?window.ym.a.filter(x=>x[1]==='reachGoal').length:0
     }));
     check('No goals before consent',!pre.started&&pre.calls===0,pre);

     const allow=page.locator('#oleg-analytics-choice [data-allow]');
     await allow.click({timeout:8000});
     await page.waitForTimeout(200);
     check('Opt-in activates correct counter',await page.evaluate(id=>window.__olegAnalyticsStarted&&Array.isArray(window.ym?.a)&&window.ym.a.some(c=>String(c[0])===String(id)&&c[1]==='init'),site.counter));
     await page.evaluate(()=>{
      window.__olegGoalTestCalls=[];
      const fn=window.ym;
      window.ym=function(...args){
       if(args[1]==='reachGoal')window.__olegGoalTestCalls.push({counter:args[0],goal:args[2]});
       return fn.apply(this,args);
      };
     });
     await clickLink('tel:');
     await clickLink('mailto:');
     check('Phone click emits correct intent goal',await page.evaluate((id)=>window.__olegGoalTestCalls.some(x=>x.counter===id&&x.goal==='oleg_phone_click'),site.counter));
     check('Email click emits correct intent goal',await page.evaluate((id)=>window.__olegGoalTestCalls.some(x=>x.counter===id&&x.goal==='oleg_email_click'),site.counter));
     const toggle=page.locator('#legal-help-toggle');
     await toggle.click({timeout:8000});
     await page.waitForTimeout(220);
     check('Assistant intent fires after panel opens',await page.evaluate(id=>window.__olegGoalTestCalls.some(x=>x.counter===id&&x.goal==='oleg_consultation_open'),site.counter));
     const sendToLawyer=page.getByRole('button',{name:'Передать вопрос юристу',exact:true});
     await sendToLawyer.click({timeout:8000});
     await page.waitForTimeout(600);
     const pathFound=await page.locator('#legal-help-form-step iframe.legal-frame').getAttribute('src');
     check('Live assistant uses correct form URL',pathFound==='https://b24-s2dosa.bitrix24site.ru/'+site.expected+'/',pathFound);
     check('CRM form opened goal after frame shown',await page.evaluate(id=>window.__olegGoalTestCalls.some(x=>x.counter===id&&x.goal==='oleg_crm_form_open'),site.counter));
     const calls=await page.evaluate(()=>window.__olegGoalTestCalls||[]);
     check('No fabricated successful lead goals',!calls.some(x=>/success|submit|lead_received/i.test(x.goal||'')),calls);
     check('Every emitted event uses correct counter',calls.every(x=>x.counter===site.counter&&GOALS.includes(x.goal)),calls);
     result.calls=calls;
     // Second direct click must not emit duplicate phone event within 1.5s.
     const before=await page.evaluate(()=>window.__olegGoalTestCalls.filter(x=>x.goal==='oleg_phone_click').length);
     await clickLink('tel:');
     const after=await page.evaluate(()=>window.__olegGoalTestCalls.filter(x=>x.goal==='oleg_phone_click').length);
     check('Rapid double clicks deduplicated',before===after,{before,after});
    }catch(e){
     check('No runtime errors',false,short(e.message));
    }finally{await context.close()}
    console.log('STAGED_METRIKA_PREVIEW',JSON.stringify(result));
   }
  }
 }finally{await browser.close()}
 await fs.writeFile('oleg-metrika-goals-preview.json',JSON.stringify(out,null,2));
 console.log('STAGED_METRIKA_SUMMARY',JSON.stringify({scenarios:out.sites.length,checks:out.sites.reduce((n,x)=>n+x.checks.length,0),failures:out.failures}));
 if(out.failures.length)process.exitCode=2;
}
main().catch(e=>{console.error('STAGED_METRIKA_FATAL',short(e.stack));process.exitCode=1});
