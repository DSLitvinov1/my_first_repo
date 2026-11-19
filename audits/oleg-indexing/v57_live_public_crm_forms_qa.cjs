'use strict';
const fs=require('fs'),{chromium}=require('/home/cloudagent/cloud-browser/node_modules/playwright');
const specs=[['potrebpravo.ru','https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'],['semya-yurist.ru','https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/']];
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:'/home/cloudagent/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell',args:['--no-sandbox','--disable-dev-shm-usage']});let results=[];
 for(const [host,url] of specs){
  const c=await b.newContext({viewport:{width:390,height:844},isMobile:true,locale:'ru-RU'});
  let posts=0;await c.route('**/*',async r=>{if(r.request().method()!=='GET'&&r.request().method()!=='HEAD'){posts++;return r.abort()}return r.continue()});
  let p=await c.newPage();let row={site:host,url,posts,errors:[]};p.on('pageerror',e=>row.errors.push(e.message.slice(0,140)));
  try{
   const response=await p.goto(url,{waitUntil:'domcontentloaded',timeout:22000});
   await p.waitForSelector('form',{timeout:22000});
   await p.waitForTimeout(500);
   let x=await p.evaluate(()=>({finalUrl:location.href,title:document.title,forms:document.forms.length,inputs:[...document.querySelectorAll('form input')].map(e=>({type:e.type,disabled:e.disabled})),buttons:[...document.querySelectorAll('form button,form input[type=submit]')].filter(e=>e.type==='submit'||e.getAttribute('type')==='submit').length,checkboxes:document.querySelectorAll('form input[type=checkbox]').length,visible:document.forms[0]?.getBoundingClientRect().width>0}));
   Object.assign(row,{status:response.status(),...x});row.pass=row.status===200&&row.forms>=1&&row.inputs.filter(e=>['tel','text','email'].includes(e.type)).length>=2&&row.checkboxes>=1&&row.buttons>=1&&row.visible&&row.finalUrl.startsWith('https://b24-s2dosa.bitrix24site.ru/');
  }catch(e){row.error=e.message.slice(0,220);row.pass=false}
  row.posts=posts;results.push(row);console.log('FORM',JSON.stringify(row));await c.close()
 }
 await b.close();fs.writeFileSync('/home/cloudagent/projects/oleg-seo-v25-utm-attribution-20261118/.private-v57-offline/v57-live-public-crm-forms.json',JSON.stringify({results,allPass:results.every(x=>x.pass),actualFormSubmissions:0,blockedNonGetRequests:results.reduce((n,x)=>n+x.posts,0)},null,2));console.log('SUMMARY',results.every(x=>x.pass),'BLOCKED_NONGET',results.reduce((n,x)=>n+x.posts,0),'ACTUAL_FORWARDED_POSTS',0);
 process.exit(results.every(x=>x.pass)?0:1)
})().catch(e=>{console.log('FATAL',e.message);process.exit(2)});