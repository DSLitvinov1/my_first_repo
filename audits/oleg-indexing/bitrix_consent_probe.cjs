'use strict';
/** Diagnostic only: inspect and activate Bitrix24 consent checkbox; block all POST requests. */
const {chromium}=require('playwright');
const forms=['crm_form_fhi3n','crm_form_ep5fd'];
const safe=s=>String(s||'').replace(/\s+/g,' ').trim().slice(0,260);
async function main(){
 const browser=await chromium.launch({headless:true});
 try{
  for(const id of forms){
   const context=await browser.newContext({viewport:{width:1280,height:900},locale:'ru-RU'});
   let writes=0;
   await context.route('**/*',route=>{
    if(!['GET','HEAD','OPTIONS'].includes(route.request().method().toUpperCase())){
      writes++;return route.abort('blockedbyclient');
    }
    return route.continue();
   });
   const page=await context.newPage();
   const result={form:id,steps:[]};
   try{
    const response=await page.goto('https://b24-s2dosa.bitrix24site.ru/'+id+'/',{waitUntil:'domcontentloaded',timeout:30000});
    result.http=response?.status();
    await page.locator('form input[type=checkbox]').first().waitFor({state:'attached',timeout:22000});
    const cb=page.locator('form input[type=checkbox]').first();
    result.element=await cb.evaluate(el=>{
      const root=el.closest('label')||el.parentElement?.parentElement||el;
      return {
       id:el.id,checked:el.checked,outerHTML:el.outerHTML.slice(0,800),
       ancestor:root.outerHTML.slice(0,1800),
       labels:[...document.querySelectorAll('label')].filter(x=>x.htmlFor===el.id).map(x=>x.outerHTML.slice(0,800)),
       nearbyButtons:[...document.querySelectorAll('button')].map(b=>({text:b.innerText?.trim().slice(0,50),visible:getComputedStyle(b).display!=='none'})).slice(0,18)
      };
    });
    const state=async method=>{
      result.steps.push({method,checked:await cb.isChecked().catch(()=>null),
        acceptVisible:await page.getByRole('button',{name:'Принимаю',exact:true}).isVisible().catch(()=>false),
        dialogCount:await page.getByRole('dialog').count().catch(()=>0),
        visibleButtons:(await page.getByRole('button').allTextContents()).filter(Boolean).slice(0,15)});
    };
    await state('initial');
    try{await cb.click({force:true,timeout:5000})}catch(e){result.steps.push({method:'input click error',error:safe(e.message)})}
    await page.waitForTimeout(400);await state('after input click');
    if(!await cb.isChecked()){
      const accept=page.getByRole('button',{name:'Принимаю',exact:true});
      if(await accept.isVisible().catch(()=>false)){
        try{await accept.click({timeout:5000})}catch(e){result.steps.push({method:'accept error',error:safe(e.message)})}
      }
      await page.waitForTimeout(350);await state('after accept');
    }
    if(!await cb.isChecked()){
      const label=page.locator('label[for="'+result.element.id+'"]').first();
      if(await label.count()){
        try{await label.click({timeout:5000})}catch(e){result.steps.push({method:'label click error',error:safe(e.message)})}
      }
      await page.waitForTimeout(350);await state('after label');
    }
   }catch(e){result.error=safe(e.message)}
   result.writesBlocked=writes;
   console.log('CONSENT_DIAG',JSON.stringify(result));
   await context.close();
  }
 }finally{await browser.close()}
}
main().catch(e=>{console.error('CONSENT_DIAG_FATAL',safe(e.message));process.exitCode=1});
