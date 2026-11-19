'use strict';
const fs=require('node:fs');
const {chromium}=require('/home/cloudagent/cloud-browser/node_modules/playwright');
const ROOT='/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118';
const hosts=[
 {domain:'potrebpravo.ru',port:18751,form:'crm_form_fhi3n',services:['nekachestvennye-uslugi','neustoyka-zastroishchika','pretenziya-prodavcu','strahovye-spory','vozvrat-avtomobilya','vozvrat-deneg']},
 {domain:'semya-yurist.ru',port:18752,form:'crm_form_ep5fd',services:['alimenty','brachnyi-dogovor','ipotechnaya-kvartira','razdel-imushchestva','razvod','spory-o-detyakh']}
];
const modes=[{name:'mobile',width:390,height:844},{name:'desktop',width:1440,height:900}];
const rows=[];
const test=(checks,name,condition,detail)=>checks.push({name,pass:!!condition,detail:condition?undefined:detail});
async function run(browser,host,mode,slug){
 const context=await browser.newContext({viewport:{width:mode.width,height:mode.height},locale:'ru-RU',isMobile:mode.name==='mobile'});
 await context.route(/(?:yandex\.(?:ru|com|net)|bitrix24(?:site)?\.ru)/i,route=>route.abort());
 const page=await context.newPage();const checks=[];const errors=[];
 page.on('pageerror',e=>errors.push(String(e.message).slice(0,130)));
 const url='https://'+host.domain+'/services/'+slug+'.html';
 try{
  const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:16000});await page.waitForTimeout(450);
  const d=await page.evaluate(()=>{
   const a=document.querySelector('section.cta .oleg-direct-crm-link a');
   const c=document.querySelector('section.cta');
   return{title:document.title,h1:[...document.querySelectorAll('h1')].map(x=>x.textContent.trim()),htmlWidth:document.documentElement.scrollWidth,canonical:document.querySelector('link[rel="canonical"]')?.href,link:a?.href,visible:a?!!(a.getBoundingClientRect().width&&a.getBoundingClientRect().height):false,rel:a?.rel,target:a?.target,ctaText:c?.innerText||'',text:document.body?.innerText||'',scripts:[...document.querySelectorAll('script[src]')].map(x=>x.getAttribute('src'))}
  });
  test(checks,'page status',response?.status()===200,response?.status());
  test(checks,'title and exactly 1 H1',!!d.title&&d.h1.length===1,d.h1);
  test(checks,'canonical production URL',d.canonical==='https://'+host.domain+'/services/'+slug+'.html',d.canonical);
  test(checks,'direct Bitrix form link',!!d.link&&d.link.includes(host.form),d.link);
  test(checks,'no other site form',!d.link?.includes(host.form==='crm_form_fhi3n'?'crm_form_ep5fd':'crm_form_fhi3n'),d.link);
  test(checks,'visible direct action',d.visible,d.visible);
  test(checks,'new-window safe rel',d.target==='_blank'&&d.rel.includes('noopener')&&d.rel.includes('noreferrer'),{target:d.target,rel:d.rel});
  test(checks,'no stale form-disabled message',!d.text.includes('Онлайн-заявки на сайте пока отключены')&&!d.text.includes('Электронный приём заявок появится'),d.ctaText);
  test(checks,'no contradictory aside',!d.text.includes('неработающие формы'),d.text.slice(-160));
  test(checks,'no horizontal overflow',d.htmlWidth<=mode.width+2,{width:d.htmlWidth,screen:mode.width});
  test(checks,'original consent and assistant scripts',d.scripts.some(x=>x.includes('oleg-analytics-v1.js'))&&d.scripts.some(x=>x.includes('legal-assistant-v4.js')),d.scripts);
 }catch(e){errors.push(String(e).slice(0,330))}
 const r={site:host.domain,slug,viewport:mode.name,passed:checks.filter(x=>x.pass).length,failed:checks.filter(x=>!x.pass),errors};rows.push(r);
 console.log('CASE',JSON.stringify({site:r.site,slug:r.slug,mode:r.viewport,passed:r.passed,failures:r.failed.map(x=>x.name),errors:r.errors}));
 await context.close();
}
(async()=>{let browser;try{
 browser=await chromium.launch({headless:true,executablePath:'/home/cloudagent/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking']});
 for(const host of hosts)for(const mode of modes)for(const slug of host.services)await run(browser,host,mode,slug);
}finally{
 await browser?.close();
 const total=rows.reduce((s,x)=>s+x.passed+x.failed.length,0),errors=rows.flatMap(x=>[...x.failed,...x.errors]);
 const result={source:'V57 LIVE HTTPS (2026-11-19), CRM/Metrika network calls blocked in browser regression',testedAt:new Date().toISOString(),cases:rows.length,checks:total,failures:errors,rows};
 fs.writeFileSync(ROOT+'/.private-v57-offline/v57-live-service-qa.json',JSON.stringify(result,null,2));
 console.log('SUMMARY',JSON.stringify({cases:rows.length,checks:total,failed:errors.length}));
 process.exit(errors.length?1:0)
}})().catch(e=>{console.error('FATAL',String(e));process.exit(2)});