'use strict';
/**
 * Oleg lead readiness audit: public browser E2E, with all mutating HTTP requests blocked.
 * Uses Playwright to load the sites, inspect CTAs and Bitrix24 iframe, and test opening
 * the lead assistant. No personal data entered and no CRM lead submitted.
 */
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const CONFIG=[
 {site:'https://potrebpravo.ru/',path:'/services/vozvrat-deneg.html',form:'crm_form_fhi3n'},
 {site:'https://semya-yurist.ru/',path:'/services/razvod.html',form:'crm_form_ep5fd'}
];
const compact=x=>String(x??'').replace(/\s+/g,' ').trim();
const captureHref=x=>{try{let u=new URL(x);return u.origin+u.pathname}catch{return compact(x).slice(0,220)}};
const scriptInfo=text=>({
 containsBitrixForm:/bitrix24site\.ru\/crm_form_/i.test(text),
 containsLegacyDemoMode:/data-form-mode\s*=\s*["']demo|formMode\s*[:=]\s*["']demo|form-mode["']?\s*,\s*["']demo/i.test(text),
 hasLeadSuccessGoal:/lead_success|reachGoal/i.test(text),
 maybePostMessage:/postMessage|message\s*[,=]/i.test(text),
 contentSize:text.length
});
async function main(){
 const result={date:new Date().toISOString(),mode:'Playwright public UI, all outbound POST/PATCH/PUT/DELETE blocked',checks:[],issues:[],assets:[]};
 const browser=await chromium.launch({headless:true});
 const api=await request.newContext({timeout:25000,ignoreHTTPSErrors:false});
 try {
  for(const config of CONFIG){
   const out={site:config.site,pages:[],consent:{},bitrixFrames:[],blockedWriteRequests:0};
   result.checks.push(out);
   const context=await browser.newContext({viewport:{width:1280,height:900},locale:'ru-RU'});
   await context.route('**/*',route=>{
     const method=route.request().method().toUpperCase();
     if(!['GET','HEAD','OPTIONS'].includes(method)){
       out.blockedWriteRequests++;
       return route.abort('blockedbyclient');
     }
     if(/(?:^https:\/\/mc\.yandex\.ru\/|^https:\/\/.*\.yandex\.(?:ru|com)\/metrika)/i.test(route.request().url())){
       return route.fulfill({status:204,body:''});
     }
     return route.continue();
   });
   const page=await context.newPage();
   const exceptions=[];
   page.on('pageerror',error=>exceptions.push(compact(error.message).slice(0,220)));
   const responses=[];
   page.on('response',response=>{
     const url=response.url();
     if(/bitrix24|legal-assistant|crm_form_/i.test(url)){
       const u=new URL(url);
       responses.push({origin:u.origin,path:u.pathname.slice(0,170),http:response.status()});
     }
   });
   for(const target of [config.site,new URL(config.path,config.site).href]){
    const check={url:target};
    out.pages.push(check);
    try{
     const response=await page.goto(target,{waitUntil:'domcontentloaded',timeout:30000});
     await page.waitForTimeout(1500);
     check.http=response?.status()||0;
     check.title=await page.title();
     check.assets=await page.evaluate(()=>[...document.querySelectorAll('script[src]')].map(x=>x.src).filter(x=>/legal-assistant|bitrix24/.test(x)));
     check.initialFrames=page.frames().filter(f=>f!==page.mainFrame()).map(f=>captureHref(f.url()));
     check.visibleCTAs=await page.evaluate(()=>[...document.querySelectorAll('button,a,[role="button"]')]
       .filter(el=>{
         const r=el.getBoundingClientRect();
         return r.width>0&&r.height>0;
       })
       .map(el=>({
         tag:el.tagName.toLowerCase(),
         text:(el.textContent||el.getAttribute('aria-label')||'').replace(/\s+/g,' ').trim().slice(0,72),
         id:el.id||null,
         className:typeof el.className==='string'?el.className.slice(0,90):'',
         href:el instanceof HTMLAnchorElement?el.href:''
       }))
       .filter(x=>/заявк|написа|задать|помощ|вопрос|консульт|чат|обращ|заказ|отправ|бот/i.test(x.text+' '+x.id+' '+x.className))
       .slice(0,35));
     // Inspect the lead assistant opening mechanism without entering any data.
     const triggers=[
       'button[aria-label*="чат" i]','button[aria-label*="помощ" i]',
       '#legal-assistant-toggle','.legal-assistant-toggle',
       'button:has-text("Помощник")','button:has-text("Задать вопрос")','button:has-text("Написать")',
       'button:has-text("Получить консультацию")','button:has-text("Оставить заявку")'
     ];
     check.openAttempts=[];
     for(const selector of triggers){
       try{
         const el=page.locator(selector).first();
         if(await el.count()!==1||!await el.isVisible())continue;
         const oldFrames=page.frames().length;
         await el.click({timeout:2500});
         await page.waitForTimeout(500);
         const newFrames=page.frames().length;
         check.openAttempts.push({selector,afterFrameCount:newFrames,beforeFrameCount:oldFrames});
         break;
       }catch(e){check.openAttempts.push({selector,error:compact(e.message).slice(0,120)})}
     }
     check.afterFrames=page.frames().filter(f=>f!==page.mainFrame()).map(f=>captureHref(f.url()));
     check.assistantElements=await page.evaluate(()=>[...document.querySelectorAll('[id*="assistant"],[class*="assistant"],[id*="chat"],[class*="chat"],iframe')]
       .slice(0,24).map(el=>({
         tag:el.tagName.toLowerCase(),id:el.id||null,
         className:typeof el.className==='string'?el.className.slice(0,90):'',
         text:(el.textContent||'').replace(/\\s+/g,' ').trim().slice(0,100),
         hidden:el.hidden||getComputedStyle(el).display==='none',
         iframeSrc:el instanceof HTMLIFrameElement?el.getAttribute('src'):''
       })));
     check.formMode=await page.getAttribute('body','data-form-mode');
     check.pageErrors=exceptions.splice(0);
     check.liveResponses=responses.splice(0).slice(0,30);
     if(check.http!==200)result.issues.push({type:'HTTP',url:target,http:check.http});
    }catch(e){
      check.error=compact(e.message).slice(0,250);
      result.issues.push({type:'LOAD_ERROR',url:target,message:check.error});
    }
   }
   // Independent direct read-only inspection of the known Bitrix24 form endpoint.
   const formUrl='https://b24-s2dosa.bitrix24site.ru/'+config.form+'/';
   const bitrix=await context.newPage();
   const frameInfo={url:captureHref(formUrl)};
   try{
     const response=await bitrix.goto(formUrl,{waitUntil:'domcontentloaded',timeout:30000});
     await bitrix.waitForTimeout(2200);
     frameInfo.http=response?.status()||0;
     frameInfo.final=captureHref(bitrix.url());
     frameInfo.title=await bitrix.title();
     frameInfo.body=await bitrix.evaluate(()=>{
       const body=document.body;
       const forms=[...document.querySelectorAll('form')].map(f=>({
         action:f.action?new URL(f.action).origin+new URL(f.action).pathname:'',
         method:f.method||'',
         fields:[...f.querySelectorAll('input,textarea,select')].map(el=>({
           type:el.type||el.tagName.toLowerCase(),required:!!el.required,
           name:el.name?.slice(0,65),placeholder:el.placeholder?.slice(0,80)
         })).slice(0,30),
         hasSubmit:!!f.querySelector('button[type="submit"],input[type="submit"]')
       }));
       const buttons=[...document.querySelectorAll('button')].map(b=>b.textContent.trim()).filter(Boolean).slice(0,15);
       return {
         forms,
         buttons,
         iframes:[...document.querySelectorAll('iframe[src]')].map(f=>new URL(f.src).origin+new URL(f.src).pathname),
         hasConsent:/соглас|обработк.*персональ/i.test(body?.innerText||body?.textContent||''),
         hasFormText:/имя|телефон|почта|email|отправить|оставить/i.test(body?.innerText||body?.textContent||''),
         bodyLength:(body?.innerText||body?.textContent||'').length,
         textPreview:(body?.innerText||body?.textContent||'').replace(/\s+/g,' ').slice(0,220)
       };
     });
     frameInfo.pageErrors=exceptions.splice(0);
     frameInfo.responses=responses.splice(0).slice(0,35);
   }catch(e){
     frameInfo.error=compact(e.message).slice(0,250);
     result.issues.push({type:'FORM_HOST_ACCESS',site:config.site,message:frameInfo.error});
   }
   out.bitrixDirect=frameInfo;
   // HTTP 200 is not proof that the correct CRM form is usable.
   frameInfo.formUiVerified=frameInfo.http===200 &&
       frameInfo.final===captureHref(formUrl) &&
       Array.isArray(frameInfo.body?.forms) &&
       frameInfo.body.forms.some(f=>f.fields?.some(x=>x.type==='tel') && f.hasSubmit) &&
       frameInfo.body.hasConsent===true;
   if(frameInfo.http===200 && !frameInfo.formUiVerified)
     result.issues.push({type:'FORM_UI_NOT_VERIFIED',site:config.site,form:captureHref(formUrl)});
   for(const asset of [...new Set(out.pages.flatMap(p=>p.assets||[]))]){
     const assetInfo={site:config.site,url:captureHref(asset)};
     try{
       const response=await api.get(asset,{failOnStatusCode:false});
       const contents=await response.text();
       assetInfo.status=response.status();
       Object.assign(assetInfo,scriptInfo(contents));
       // Never dump full production JS into CI logs.
     }catch(e){assetInfo.error=compact(e.message).slice(0,250)}
     result.assets.push(assetInfo);
   }
   out.allPageErrors=exceptions.slice(0,15);
   await context.close();
   console.log('LEAD_SITE',JSON.stringify(out));
  }
 }finally{await browser.close();await api.dispose()}
 await fs.writeFile('oleg-bitrix-lead-readiness.json',JSON.stringify(result,null,2));
 console.log('LEAD_READINESS_SUMMARY',JSON.stringify({
    sites:result.checks.map(x=>({
      url:x.site,pages:x.pages.map(y=>({url:y.url,http:y.http,
        initialFrames:y.initialFrames,afterFrames:y.afterFrames,ctas:y.visibleCTAs?.length,
        triggered:y.openAttempts,errors:y.pageErrors
      })),
      bitrixHttp:x.bitrixDirect?.http,
      bitrixFormHost:x.bitrixDirect?.url,
      bitrixFormUiVerified:x.bitrixDirect?.formUiVerified===true,
      bitrixForms:x.bitrixDirect?.body?.forms?.length,
      bitrixButtons:x.bitrixDirect?.body?.buttons,
      consent:x.bitrixDirect?.body?.hasConsent,
      blockedWrites:x.blockedWriteRequests
    })),issues:result.issues,
    assets:result.assets
 }));
}
main().catch(e=>{console.error('LEAD_READINESS_FATAL',e.message);process.exitCode=1});
