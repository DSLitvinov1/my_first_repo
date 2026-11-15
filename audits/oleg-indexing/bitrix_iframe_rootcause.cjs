'use strict';
/* Investigates public native Bitrix24 iframe latency. No form fills, no submit clicks. */
const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const cases=[
 {host:'potrebpravo.ru',form:'crm_form_fhi3n'},
 {host:'semya-yurist.ru',form:'crm_form_ep5fd'}
];
const brief=s=>String(s||'').replace(/\s+/g,' ').slice(0,160);
const clock=()=>Math.round(performance.now());
async function main(){
 const browser=await chromium.launch({headless:true});
 const result={checkedAt:new Date().toISOString(),scope:'read-only DOM: NO FILL and NO SUBMIT',sites:[]};
 try{
 for(const c of cases){
  const r={host:c.host,screens:[]};result.sites.push(r);
  for(const v of [390,1440]){
   const ctx=await browser.newContext({viewport:{width:v,height:850},locale:'ru-RU'});
   await ctx.route('**/*',route=>{
    if(/^https:\/\/mc\.yandex\.(?:ru|com)\//.test(route.request().url()))
      return route.fulfill({status:204,body:''});
    return route.continue();
   });
   const page=await ctx.newPage();
   const d={viewport:v,frameRequests:[],frameResponses:[],frameErrors:[],mutationCommands:0};
   r.screens.push(d);
   page.on('request',req=>{
     let url;try{url=new URL(req.url())}catch{return}
     if(url.hostname.endsWith('bitrix24site.ru')||url.hostname.endsWith('bitrix24.ru')){
       d.frameRequests.push({method:req.method(),host:url.hostname,path:url.pathname.slice(0,100)});
     }
   });
   page.on('response',res=>{
     const req=res.request();let u;try{u=new URL(res.url())}catch{return}
     if(u.hostname.endsWith('bitrix24site.ru')||u.hostname.endsWith('bitrix24.ru'))
       d.frameResponses.push({method:req.method(),status:res.status(),host:u.hostname,path:u.pathname.slice(0,90)});
   });
   page.on('requestfailed',req=>{
     let u;try{u=new URL(req.url())}catch{return}
     if(u.hostname.endsWith('bitrix24site.ru')||u.hostname.endsWith('bitrix24.ru'))
       d.frameErrors.push({method:req.method(),path:u.pathname.slice(0,90),cause:brief(req.failure()?.errorText)});
   });
   try{
    let t=Date.now();
    const response=await page.goto('https://'+c.host+'/',{waitUntil:'domcontentloaded',timeout:30000});
    d.homeStatus=response?.status();d.homeMs=Date.now()-t;
    const deny=page.locator('#oleg-analytics-choice [data-deny]');
    if(await deny.count()&&await deny.isVisible())await deny.click();
    await page.locator('#legal-help-toggle').click();
    await page.getByRole('button',{name:/Передать вопрос юристу|Оставить заявку юристу/}).first().click();
    const iframe=page.locator('iframe.legal-frame').first();
    const expected='https://b24-s2dosa.bitrix24site.ru/'+c.form+'/';
    d.actualFrame=await iframe.getAttribute('src');
    d.correctFrame=d.actualFrame===expected;
    const content=page.frameLocator('iframe.legal-frame').locator('form').first();
    const begin=Date.now();
    try{await content.waitFor({state:'attached',timeout:28000});d.embeddedFormVisible=true;}
    catch(e){d.embeddedFormVisible=false;d.iframeError=brief(e.message)}
    d.iframeWaitMs=Date.now()-begin;
    if(d.embeddedFormVisible){
     const details=await content.locator('input,textarea,select').evaluateAll(xs=>xs.map(x=>({tag:x.tagName.toLowerCase(),type:x.type||'',name:x.getAttribute('name')||''})));
     d.fields={name:details.some(x=>x.name==='name'),phone:details.some(x=>x.type==='tel'||x.name==='phone'),description:details.some(x=>x.tag==='textarea')};
    }
    // Direct form on a new tab is a separate, resilient fallback route.
    const direct=await ctx.newPage();
    let t2=Date.now();
    try{
     const directR=await direct.goto(expected,{waitUntil:'domcontentloaded',timeout:30000});
     d.directStatus=directR?.status();await direct.locator('form').first().waitFor({state:'attached',timeout:24000});d.directFormVisible=true;
    }catch(e){d.directFormVisible=false;d.directError=brief(e.message)}
    d.directWaitMs=Date.now()-t2;
    await direct.close();
   }catch(e){d.error=brief(e.message)}
   console.log('BITRIX_IFRAME_DIAGNOSTIC',JSON.stringify({host:c.host,...d,frameRequests:d.frameRequests.slice(0,20),frameResponses:d.frameResponses.slice(0,20),frameErrors:d.frameErrors.slice(0,20)}));
   await ctx.close();
  }
 }
 }finally{await browser.close()}
 await fs.writeFile('oleg-bitrix-iframe-diagnostic.json',JSON.stringify(result,null,2));
 console.log('BITRIX_IFRAME_DIAGNOSTIC_SUMMARY',JSON.stringify(result.sites.map(s=>({host:s.host,screens:s.screens.map(d=>({viewport:d.viewport,embedded:d.embeddedFormVisible,direct:d.directFormVisible,wait:d.iframeWaitMs,postCount:d.frameRequests.filter(x=>x.method==='POST').length}))}))));
 if(result.sites.some(s=>s.screens.some(d=>!d.directFormVisible)))process.exitCode=2;
}
main().catch(e=>{console.error('BITRIX_DIAG_FATAL',brief(e.stack));process.exitCode=1});
