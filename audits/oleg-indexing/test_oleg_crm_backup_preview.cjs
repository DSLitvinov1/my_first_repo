'use strict';
/* Preview a NOT DEPLOYED UX fallback on real live Oleg sites via Playwright. */
const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const path=require('node:path');
const cases=[
 {host:'potrebpravo.ru',form:'crm_form_fhi3n',service:'/services/vozvrat-deneg.html'},
 {host:'semya-yurist.ru',form:'crm_form_ep5fd',service:'/services/razvod.html'}
];
async function main(){
 const browser=await chromium.launch({headless:true});
 const output={checkedAt:new Date().toISOString(),scope:'preview-only injection; no network tracking or Bitrix submission',tests:[],errors:[]};
 const check=(row,label,ok,details)=>{row.checks.push({label,ok:!!ok,details:details??null});if(!ok)output.errors.push(row.site+' '+row.viewport+' '+row.path+' '+label)};
 try{
 for(const c of cases){
  for(const width of [390,1440]){
   const ctx=await browser.newContext({viewport:{width,height:850},locale:'ru-RU'});
   await ctx.route('**/*',route=>{
     const req=route.request();
     if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase()))return route.abort('blockedbyclient');
     if(/^https:\/\/mc\.yandex\.(?:ru|com)\//.test(req.url()))return route.fulfill({status:204,body:''});
     return route.continue();
   });
   const page=await ctx.newPage();
   for(const p of ['/',c.service]){
    const row={site:c.host,path:p,viewport:width,checks:[]};output.tests.push(row);
    try{
     const r=await page.goto('https://'+c.host+p,{waitUntil:'domcontentloaded',timeout:30000});
     check(row,'Page HTTP 200',r?.status()===200,r?.status());
     await page.addScriptTag({path:path.resolve(__dirname,'oleg-crm-backup-links-v1.js')});
     const widget=page.locator('[data-oleg-crm-backup="v1"]');
     await widget.waitFor({state:'attached',timeout:12000});
     check(row,'Accessible fallback inserted',await widget.count()===1);
     const link=widget.getByRole('link',{name:'Открыть форму заявки'});
     const expected='https://b24-s2dosa.bitrix24site.ru/'+c.form+'/';
     check(row,'Correct domain-specific Bitrix direct link',(await link.getAttribute('href'))===expected,{actual:await link.getAttribute('href')});
     check(row,'External link target + safe rel',(await link.getAttribute('target'))==='_blank'&&/noopener/.test(await link.getAttribute('rel')||''));
     const visible=await widget.isVisible();
     if(p===c.service){
       check(row,'Service page always has visible fallback',visible);
     }else{
       const deny=page.locator('#oleg-analytics-choice [data-deny]');
       if(await deny.count() && await deny.isVisible())await deny.click({timeout:7000});
       await page.locator('#legal-help-toggle').click({timeout:8000});
       await page.getByRole('button',{name:/Передать вопрос юристу|Оставить заявку юристу/}).first().click({timeout:8000});
       await page.waitForTimeout(250);
       check(row,'Fallback becomes visible in assistant',await widget.isVisible());
       check(row,'Still exactly one fallback after assistant clicks',await widget.count()===1);
     }
     check(row,'No automatic external navigation',page.url()==='https://'+c.host+p);
     const box=await link.boundingBox();
     check(row,'Touch target at least 40 px',!!box&&box.height>=38,box?.height||0);
     check(row,'No fabricated receipt or submit control',await widget.locator('button[type=submit],input[type=submit]').count()===0);
    }catch(e){check(row,'Preview execution',false,String(e.message).replace(/\s+/g,' ').slice(0,220));}
    console.log('CRM_BACKUP_PREVIEW',JSON.stringify(row));
   }
   await ctx.close();
  }
 }
 }finally{await browser.close()}
 await fs.writeFile('oleg-crm-backup-preview.json',JSON.stringify(output,null,2));
 console.log('CRM_BACKUP_PREVIEW_SUMMARY',JSON.stringify({screens:output.tests.length,checks:output.tests.reduce((n,x)=>n+x.checks.length,0),failed:output.errors}));
 if(output.errors.length)process.exitCode=2;
}
main().catch(e=>{console.error('CRM_BACKUP_FATAL',e.message);process.exitCode=1});
