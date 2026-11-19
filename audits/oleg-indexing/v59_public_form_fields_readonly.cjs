'use strict';
const fs=require('fs'),{chromium}=require('/home/cloudagent/cloud-browser/node_modules/playwright');
const entries=[['consumer','https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'],['family','https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/']];
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:'/home/cloudagent/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',args:['--no-sandbox','--disable-dev-shm-usage']});
 let rows=[];
 for(const [site,url] of entries){
  const ctx=await b.newContext({viewport:{width:390,height:844},locale:'ru-RU'});
  let refused=0;await ctx.route('**/*',async route=>{const m=route.request().method();if(!['GET','HEAD'].includes(m)){refused++;return route.abort()}return route.continue()});
  let p=await ctx.newPage(),a={site};try{
   const r=await p.goto(url,{waitUntil:'domcontentloaded',timeout:20000});await p.waitForSelector('form',{timeout:20000});
   await p.waitForTimeout(1500);
   const dat=await p.evaluate(()=>{
    const f=[...document.forms][0];
    return {url:new URL(location.href).origin,formCount:document.forms.length,
      fields:[...f.querySelectorAll('input,textarea,select')].map(x=>({type:(x.type||x.tagName).toLowerCase(),name:x.getAttribute('name')||'',id:x.id||'',hasValue:!!x.value})),
      external_links:[...f.querySelectorAll('a[href]')].map(x=>({host:new URL(x.href).hostname,text:(x.innerText||'').trim().slice(0,60)})).slice(0,7),
      metricaClientIdField:[...f.querySelectorAll('input,textarea')].some(x=>/^(metrica[_-]?client[_-]?ids?|metrika[_-]?client[_-]?ids?|client[_-]?ids?)$/i.test([x.name,x.id].filter(Boolean).join(' '))),
      present:true};
   });
   a={...a,status:r.status(),...dat,nonGETblocked:refused,forwardedWrites:0};
  }catch(e){a.error=e.message.slice(0,200)}
  rows.push(a);console.log('FORM_FIELDS',JSON.stringify(a));await ctx.close();
 }
 await b.close();
 const p='/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118/.private-v59-offline/v59_public_form_field_check.json';
 fs.writeFileSync(p,JSON.stringify({status:'READ_ONLY_NO_CLIENT_SUBMISSIONS',entries:rows},null,2));
 console.log('CHECK_DONE',rows.length,'GOOD',rows.every(x=>x.status===200&&x.present),'CLIENT_ID_FIELDS',rows.map(x=>x.metricaClientIdField));
 if(!rows.every(x=>x.status===200&&x.present))process.exit(1);
})().catch(e=>{console.log('ERROR',e.message);process.exit(2)});