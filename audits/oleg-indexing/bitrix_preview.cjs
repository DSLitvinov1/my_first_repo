'use strict';
// In-memory preview of the proposed missing assistant <script> on internal service pages.
// Does not deploy and blocks all POST/PUT/PATCH/DELETE. No real lead can be sent.
const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const SITES=[
 {host:'potrebpravo.ru',target:'https://potrebpravo.ru/services/vozvrat-deneg.html',form:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'},
 {host:'semya-yurist.ru',target:'https://semya-yurist.ru/services/razvod.html',form:'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/'}
];
const marker='<script defer src="/assets/legal-assistant-v4.js"></script>';
const safe=e=>String(e?.message||e||'').replace(/\s+/g,' ').slice(0,240);

async function main(){
 const browser=await chromium.launch({headless:true});
 const results=[];
 try{
  for(const site of SITES){
   const result={host:site.host,url:site.target,mode:'Playwright in-memory HTML patch only'};
   results.push(result);
   const ctx=await browser.newContext({viewport:{width:390,height:844},locale:'ru-RU'});
   await ctx.route('**/*',route=>{
    const req=route.request();
    if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase())){
      result.blockedWrites=(result.blockedWrites||0)+1;
      return route.abort('blockedbyclient');
    }
    if(/^https:\/\/mc\.yandex\.ru\//i.test(req.url()))
      return route.fulfill({status:204,body:''});
    return route.continue();
   });
   await ctx.route(site.target,async route=>{
    const response=await route.fetch();
    const body=await response.text();
    if(response.status()!==200||!/</.test(body)||!/<\/body>/i.test(body))
      throw Error('Unexpected live HTML before preview '+site.host);
    if(/legal-assistant-v4\.js/.test(body))throw Error('Already has assistant; preview must not duplicate');
    result.injectionPerformed=true;
    const patched=body.replace(/<\/body>/i,marker+'</body>');
    await route.fulfill({response,body:patched});
   });
   const page=await ctx.newPage();
   try{
    const resp=await page.goto(site.target,{waitUntil:'domcontentloaded',timeout:28000});
    result.http=resp?.status()||0;
    const deny=page.locator('#oleg-analytics-choice [data-deny]');
    if(await deny.count()&&await deny.isVisible())await deny.click();
    const launcher=page.locator('#legal-help-toggle');
    await launcher.waitFor({state:'visible',timeout:15000});
    result.botPresent=true;
    await launcher.click({timeout:6000});
    result.panelVisible=await page.locator('#legal-help-panel').isVisible();
    result.topicChoices=await page.locator('#legal-help-panel button.legal-choice').allTextContents();
    const formLink=page.getByRole('button',{name:'Оставить заявку юристу',exact:true});
    await formLink.click({timeout:7000});
    const frame=page.locator('#legal-help-panel iframe.legal-frame');
    result.iframeVisible=await frame.isVisible();
    result.iframeSrc=await frame.getAttribute('src');
    const nested=page.frameLocator('#legal-help-panel iframe.legal-frame');
    try{
      await nested.locator('form').first().waitFor({state:'attached',timeout:25000});
      result.formLoaded=true;
      result.fieldCount=await nested.locator('input,textarea').count();
      result.submitPresent=await nested.getByRole('button',{name:'Отправить',exact:true}).count()>0;
    }catch(e){
      result.formError=safe(e);
      result.formLoaded=false;
    }
    const box=await page.locator('#legal-help-panel').boundingBox();
    result.mobilePanelFits=!!box&&box.x>=0&&box.x+box.width<=391&&box.y>=0&&box.y+box.height<=845;
    result.preparedPatchWorks=result.injectionPerformed&&result.iframeSrc===site.form&&
      result.panelVisible&&result.mobilePanelFits&&result.formLoaded&&result.submitPresent;
   }catch(e){result.error=safe(e);result.preparedPatchWorks=false}
   finally{await ctx.close();}
   console.log('BITRIX_PREVIEW',JSON.stringify(result));
  }
 }finally{await browser.close()}
 await fs.writeFile('oleg-bitrix-preview.json',JSON.stringify({date:new Date().toISOString(),results},null,2));
 console.log('BITRIX_PREVIEW_SUMMARY',JSON.stringify(results.map(x=>({host:x.host,works:x.preparedPatchWorks,reason:x.error||x.formError||null}))));
}
main().catch(e=>{console.error('BITRIX_PREVIEW_FATAL',safe(e));process.exitCode=1});
