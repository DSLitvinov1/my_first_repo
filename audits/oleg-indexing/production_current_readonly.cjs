'use strict';
/* Playwright read-only production recovery audit for Oleg's two legal sites.
 * No submissions, analytics hits, cookie exports, authenticated tabs, or ads.
 * Required failures get a nonzero exit code; machine-readable artifact saved.
 */
const { chromium, request }=require('playwright');
const fs=require('node:fs/promises');
const sites=[
 {host:'potrebpravo.ru',sitemap:23,form:'crm_form_fhi3n',counter:114249897,service:'/services/vozvrat-deneg.html'},
 {host:'semya-yurist.ru',sitemap:18,form:'crm_form_ep5fd',counter:114251443,service:'/services/razvod.html'}
];
const summarize=s=>String(s||'').replace(/\s+/g,' ').slice(0,230);
async function main(){
 const output={checkedAt:new Date().toISOString(),scope:'public, unauthenticated Playwright',sites:[],issues:[]};
 const browser=await chromium.launch({headless:true});
 const api=await request.newContext({timeout:16000,ignoreHTTPSErrors:false});
 async function get(url){
   try{const response=await api.get(url,{failOnStatusCode:false,maxRedirects:5});
     return {status:response.status(),url:response.url(),contentType:response.headers()['content-type']||'',body:await response.text()};}
   catch(e){return {status:0,url,error:summarize(e.message),body:''};}
 }
 const fail=(o,code,detail)=>{const p={code,detail};o.failures.push(p);output.issues.push({site:o.site,...p})};
 try{
 for(const cfg of sites){
   const origin='https://'+cfg.host;
   const out={site:cfg.host,checked:[],failures:[],warnings:[],screenResults:[]};output.sites.push(out);
   for(const [label,resource] of [['home','/'],['robots','/robots.txt'],['sitemap','/sitemap.xml'],['service',cfg.service]]){
     const r=await get(origin+resource);
     out.checked.push({label,status:r.status,final:r.url,error:r.error||null});
     if(r.status!==200)fail(out,label.toUpperCase()+'_NOT_200',{status:r.status,error:r.error});
     if(label==='robots'&&r.status===200){
       out.robotsSitemap=r.body.includes('Sitemap: '+origin+'/sitemap.xml');
       if(!out.robotsSitemap)fail(out,'ROBOTS_SITEMAP_MISSING','Expected exact sitemap URL');
     }
     if(label==='sitemap'&&r.status===200){
       out.sitemapCount=(r.body.match(/<url(?:\s|>)/gi)||[]).length;
       if(out.sitemapCount!==cfg.sitemap)out.warnings.push({code:'SITEMAP_SIZE_CHANGED',expected:cfg.sitemap,actual:out.sitemapCount});
       if(!r.body.includes('<urlset'))fail(out,'SITEMAP_INVALID','No urlset root');
     }
   }
   const native=await get('https://b24-s2dosa.bitrix24site.ru/'+cfg.form+'/');
   out.nativeBitrix={status:native.status,final:native.url,error:native.error||null};
   if(native.status!==200)fail(out,'NATIVE_BITRIX_FORM_UNAVAILABLE',out.nativeBitrix);
   for(const viewport of [{width:390,height:844},{width:1440,height:900}]){
     const ctx=await browser.newContext({viewport,locale:'ru-RU'});
     let blockedPosts=0;let blockedTrackers=0;
     await ctx.route('**/*',route=>{
        const req=route.request(),url=req.url();
        if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase())){
           blockedPosts++;return route.abort('blockedbyclient');
        }
        if(/^https:\/\/mc\.yandex\.(?:ru|com)\//.test(url)){
           blockedTrackers++;return route.fulfill({status:204,body:''});
        }
        return route.continue();
     });
     const page=await ctx.newPage();
     const screen={viewport:viewport.width,status:0,blockedPosts:0,blockedTrackers:0};
     out.screenResults.push(screen);
     try{
       const r=await page.goto(origin+'/',{timeout:26000,waitUntil:'domcontentloaded'});
       screen.status=r?.status()||0;
       if(screen.status!==200)fail(out,'BROWSER_HOME_NOT_200',{viewport:viewport.width,status:screen.status});
       else {
         const dom=await page.evaluate(()=>({
           title:document.title,
           description:document.querySelector('meta[name=description]')?.content||'',
           canonical:document.querySelector('link[rel=canonical]')?.href||'',
           h1:document.querySelectorAll('h1').length,
           phoneLinks:document.querySelectorAll('a[href^="tel:"]').length,
           tracker:document.querySelector('script[src*="oleg-analytics"]')?.getAttribute('src')||'',
           agent:!!document.querySelector('#legal-help-toggle'),
           consent:!!document.querySelector('#oleg-analytics-choice'),
           formLinks:[...document.querySelectorAll('a[href]')].filter(a=>/b24-s2dosa/.test(a.href)).length
         }));
         screen.dom=dom;
         if(dom.canonical!==origin+'/')fail(out,'HOME_CANONICAL_WRONG',{viewport:viewport.width,canonical:dom.canonical});
         if(!dom.title||!dom.description||dom.h1!==1)out.warnings.push({code:'MISSING_HEAD_CONTENT',viewport:viewport.width,details:{title:!!dom.title,description:!!dom.description,h1:dom.h1}});
         if(!dom.agent)fail(out,'LEGAL_ASSISTANT_ABSENT',{viewport:viewport.width});
         if(!dom.tracker)fail(out,'METRIKA_SCRIPT_ABSENT',{viewport:viewport.width});
         if(dom.agent){
           const consent=page.locator('#oleg-analytics-choice');
           if(await consent.count() && await consent.isVisible()){
             const deny=consent.locator('[data-deny]');
             if(await deny.count())await deny.click({timeout:7000});
           }
           const toggle=page.locator('#legal-help-toggle');
           await toggle.click({timeout:8000});
           const cta=page.getByRole('button',{name:/Передать вопрос юристу|Оставить заявку юристу/}).first();
           await cta.click({timeout:8000});
           const iframe=page.locator('iframe.legal-frame').first();
           const src=await iframe.getAttribute('src');
           const expected='https://b24-s2dosa.bitrix24site.ru/'+cfg.form+'/';
           screen.crmIframe=src||null;
           if(src!==expected)fail(out,'INCORRECT_BITRIX_FORM_LINK',{viewport:viewport.width,actual:src,expected});
           else{
             try{
               const frame=page.frameLocator('iframe.legal-frame').locator('form').first();
               await frame.waitFor({state:'attached',timeout:18000});
               screen.embeddedFormLoaded=true;
               const phones=await frame.locator('input[type=tel],input[name=phone]').count();
               const names=await frame.locator('input[name=name]').count();
               if(!phones||!names)fail(out,'BITRIX_REQUIRED_FIELDS_MISSING',{viewport:viewport.width,phones,names});
             }catch(e){
               screen.embeddedFormLoaded=false;out.warnings.push({code:'BITRIX_IFRAME_DELAYED',viewport:viewport.width,error:summarize(e.message)});
             }
           }
         }
       }
     }catch(e){fail(out,'BROWSER_FAILURE',{viewport:viewport.width,error:summarize(e.message)});}
     finally{screen.blockedPosts=blockedPosts;screen.blockedTrackers=blockedTrackers;await ctx.close();}
   }
   console.log('OLEG_CURRENT_PROD_SITE',JSON.stringify({
     site:out.site,checked:out.checked,nativeBitrix:out.nativeBitrix,
     summary:out.screenResults.map(x=>({viewport:x.viewport,status:x.status,iframe:x.crmIframe,loaded:x.embeddedFormLoaded,tracker:x.dom?.tracker,
       canonical:x.dom?.canonical,phoneLinks:x.dom?.phoneLinks})),
     failures:out.failures,warnings:out.warnings
   }));
 }
 }finally{await api.dispose();await browser.close();}
 await fs.writeFile('oleg-production-current-readonly.json',JSON.stringify(output,null,2));
 console.log('OLEG_CURRENT_PROD_SUMMARY',JSON.stringify({sites:output.sites.length,issues:output.issues.length,
   checks:output.sites.map(x=>({site:x.site,failures:x.failures.length,warnings:x.warnings.length}))}));
 if(output.issues.length)process.exitCode=2;
}
main().catch(e=>{console.error('OLEG_CURRENT_PROD_FATAL',summarize(e.stack));process.exitCode=1});
