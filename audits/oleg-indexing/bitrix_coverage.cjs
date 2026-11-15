'use strict';
// Read-only, owner-authorized Playwright lead coverage audit.
// No CRM writes. Explicitly abort any non-GET request, no form submissions.
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const SITES=[
 {host:'potrebpravo.ru',form:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'},
 {host:'semya-yurist.ru',form:'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/'}
];
const safe=e=>String(e?.message||e||'').replace(/\s+/g,' ').slice(0,260);
const locs=xml=>[...xml.matchAll(/<loc[^>]*>([^<]+)<\/loc>/gi)].map(x=>x[1].trim().replace(/&amp;/g,'&'));
async function main(){
 const api=await request.newContext({timeout:25000});
 const browser=await chromium.launch({headless:true});
 const result={date:new Date().toISOString(),mode:'read-only Playwright, blocked all writes',sites:[],issues:[]};
 try{
  for(const site of SITES){
   const base='https://'+site.host;
   const map=await api.get(base+'/sitemap.xml',{failOnStatusCode:false});
   if(map.status()!==200)throw Error('Site map not accessible '+base);
   const urls=locs(await map.text());
   const output={host:site.host,sitemapCount:urls.length,pages:[],flows:[],forms:[],mutationsBlocked:0};
   result.sites.push(output);
   const context=await browser.newContext({locale:'ru-RU',viewport:{width:390,height:844}});
   await context.route('**/*',route=>{
    const req=route.request();
    if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase())){
     output.mutationsBlocked++;return route.abort('blockedbyclient');
    }
    if(/^https:\/\/mc\.yandex\.ru\//i.test(req.url()))return route.fulfill({status:204,body:''});
    return route.continue();
   });
   const page=await context.newPage();
   for(const url of urls){
    const rec={url};output.pages.push(rec);
    try{
     const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:26000});
     rec.http=response?.status()||0;
     rec.title=await page.title();
     rec.formMode=await page.getAttribute('body','data-form-mode');
     rec.hasAssistantScript=await page.locator('script[src*="legal-assistant-v4.js"]').count()>0;
     rec.assistantButtons=await page.locator('#legal-help-toggle').count();
     rec.contactLinks=await page.locator('a[href^="mailto:"],a[href^="tel:"]').count();
     rec.cmsFormIframes=await page.locator('iframe[src*="bitrix24"]').count();
     if(rec.http!==200)result.issues.push({host:site.host,url,issue:'HTTP '+rec.http});
     if(!rec.hasAssistantScript||rec.assistantButtons!==1)result.issues.push({host:site.host,url,issue:'No CRM assistant present'});
    }catch(e){
     rec.error=safe(e);result.issues.push({host:site.host,url,issue:rec.error});
    }
   }
   // Exercise actual public assistant flow on the landing page, with no form submit.
   for(const url of [base+'/',base+(site.host==='potrebpravo.ru'?'/services/vozvrat-deneg.html':'/services/razvod.html')]){
    const flow={url,expectedForm:site.form};output.flows.push(flow);
    try{
     await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
     const widget=page.locator('#legal-help-toggle');
     flow.widgetExists=await widget.count()===1;
     if(!flow.widgetExists){flow.status='no-assistant';continue;}
     await widget.click({timeout:5000});
     flow.panelVisible=await page.locator('#legal-help-panel').isVisible();
     flow.topicButtons=await page.locator('#legal-help-topics .legal-choice').allTextContents();
     await page.getByRole('button',{name:'Оставить заявку юристу'}).click({timeout:5000});
     const frameEl=page.locator('#legal-help-form-step iframe.legal-frame');
     await frameEl.waitFor({state:'visible',timeout:10000});
     const src=await frameEl.getAttribute('src');
     flow.frameSrc=src;
     flow.frameCorrect=src===site.form;
     flow.frameLoaded=false;flow.formVisible=false;
     const frame=page.frameLocator('iframe.legal-frame');
     try {
      await frame.locator('form').first().waitFor({state:'visible',timeout:25000});
      flow.frameLoaded=true;
      flow.formVisible=await frame.locator('form').first().isVisible();
      flow.fields=await frame.locator('form input,form textarea').count();
      flow.submitButtons=await frame.getByRole('button',{name:'Отправить',exact:true}).count();
      flow.consentText=await frame.locator('body').innerText({timeout:7000}).then(x=>/соглас|персональн/i.test(x));
     }catch(e){flow.frameError=safe(e)}
     const rect=await page.locator('#legal-help-panel').boundingBox();
     flow.dialogFitsMobile=!!rect&&rect.x>=0&&rect.x+rect.width<=391&&rect.y>=0&&rect.y+rect.height<=845;
     flow.status=flow.frameLoaded&&flow.frameCorrect&&flow.formVisible&&flow.submitButtons>0&&flow.dialogFitsMobile?'ready-interface':'not-ready';
     if(flow.status==='not-ready')result.issues.push({host:site.host,url,issue:'Embedded Bitrix form interaction failed'});
    }catch(e){flow.error=safe(e);flow.status='error';result.issues.push({host:site.host,url,issue:flow.error})}
   }
   const direct=await context.newPage();
   try{
    const response=await direct.goto(site.form,{waitUntil:'domcontentloaded',timeout:30000});
    await direct.waitForTimeout(1000);
    const form=await direct.evaluate(()=>{
     const f=document.querySelector('form');
     const texts=(document.body?.innerText||'').replace(/\s+/g,' ');
     return {
      hasForm:!!f,fieldTypes:f?[...f.querySelectorAll('input,textarea,select')].map(x=>x.type||x.tagName.toLowerCase()):[],
      consentVisible:/соглас.*обработ|обработ.*персонал/i.test(texts),
      hasSendButton:[...document.querySelectorAll('button')].some(x=>x.textContent.trim()==='Отправить'),
      bodyPreview:texts.slice(0,230)
     };
    });
    output.forms.push({url:site.form,http:response?.status()||0,finalUrl:direct.url(),...form});
   }catch(e){output.forms.push({url:site.form,error:safe(e)})}
   await context.close();
   console.log('BITRIX_COVERAGE_SITE',JSON.stringify({
    host:site.host,sitemapCount:output.sitemapCount,
    assistantScripts:output.pages.filter(x=>x.hasAssistantScript).length,
    assistantWidgets:output.pages.filter(x=>x.assistantButtons===1).length,
    oldDemoMode:output.pages.filter(x=>x.formMode==='demo').length,
    flows:output.flows,form:output.forms,
    blockedMutations:output.mutationsBlocked
   }));
  }
 }finally{await browser.close();await api.dispose()}
 await fs.writeFile('oleg-bitrix-coverage.json',JSON.stringify(result,null,2));
 console.log('BITRIX_COVERAGE_SUMMARY',JSON.stringify({sites:result.sites.length,issues:result.issues.length,issueSamples:result.issues.slice(0,10)}));
}
main().catch(e=>{console.error('BITRIX_COVERAGE_FATAL',safe(e));process.exitCode=1});
