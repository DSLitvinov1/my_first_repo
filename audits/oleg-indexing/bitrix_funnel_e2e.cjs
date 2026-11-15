'use strict';
/** Public user journey checks only. All POSTs, analytics, and forms submissions blocked. */
const { chromium } = require('playwright');
const fs = require('node:fs/promises');
const CONFIG = [
  { host: 'potrebpravo.ru', form: '/crm_form_fhi3n/', service: '/services/vozvrat-deneg.html' },
  { host: 'semya-yurist.ru', form: '/crm_form_ep5fd/', service: '/services/razvod.html' },
];
const BITRIX_ORIGIN='https://b24-s2dosa.bitrix24site.ru';
async function main(){
 const output={started:new Date().toISOString(),purpose:'Real Bitrix form UI smoke without creating leads',results:[],errors:[]};
 const browser=await chromium.launch({headless:true});
 try{
 for(const config of CONFIG){
  const site='https://'+config.host+'/';
  const result={site,checks:[],errors:[],failedWrites:0};
  output.results.push(result);
  const context=await browser.newContext({viewport:{width:390,height:844},locale:'ru-RU'});
  await context.route('**/*',r=>{
   const url=r.request().url();
   if(!['GET','HEAD','OPTIONS'].includes(r.request().method().toUpperCase())){
    result.failedWrites++;return r.abort('blockedbyclient');
   }
   if(/^https:\/\/mc\.yandex\.ru\//i.test(url))return r.fulfill({status:204,body:''});
   return r.continue();
  });
  const page=await context.newPage();
  const check=(label,ok,detail)=>{
   result.checks.push({label,ok:!!ok,detail:detail??null});
   if(!ok){result.errors.push(label);output.errors.push(config.host+': '+label)}
  };
  const pageErrors=[];
  page.on('pageerror',e=>pageErrors.push(e.message.slice(0,170)));
  try{
   const res=await page.goto(site,{waitUntil:'domcontentloaded',timeout:30000});
   check('Homepage HTTP 200',res?.status()===200,res?.status());
   const launch=page.locator('#legal-help-toggle');
   await launch.waitFor({state:'visible',timeout:10000});
   check('Legal assistant launch visible',await launch.isVisible());
   await launch.click();
   check('Assistant panel opens',await page.locator('#legal-help-panel').isVisible());
   const topicButtons=await page.locator('#legal-help-topics button.legal-choice').allTextContents();
   check('Common question buttons exist',topicButtons.length>=3,topicButtons);
   await page.getByRole('button',{name:'Оставить заявку юристу'}).click();
   const iframe=page.locator('iframe.legal-frame');
   check('Embedded form visible',await iframe.isVisible());
   const exactFormUrl=BITRIX_ORIGIN+config.form;
   await page.waitForFunction(expected=>{
    const node=document.querySelector('#legal-help-form-step iframe.legal-frame');
    return !!node && (node.src===expected||node.src.startsWith(expected+'?'));
   },exactFormUrl,{timeout:15000});
   check('Correct domain-specific Bitrix form', (await iframe.getAttribute('src')||'')===exactFormUrl,
       {actual:await iframe.getAttribute('src'),expected:exactFormUrl});
   const child=page.frameLocator('iframe.legal-frame');
   await child.locator('form').first().waitFor({state:'attached',timeout:35000});
   const form=child.locator('form').first();
   check('Iframe form loads',await form.count()===1);
   const fields=await form.locator('input,textarea,select').evaluateAll(elements=>elements.map(e=>({
      tag:e.tagName.toLowerCase(),type:e.type||'',name:(e.getAttribute('name')||'').slice(0,50),
      required:e.required,ariaRequired:e.getAttribute('aria-required'),placeholder:e.getAttribute('placeholder')||''
   })));
   check('Contact name field available',fields.some(x=>x.name==='name'));
   check('Phone input available',fields.some(x=>x.type==='tel'||x.name==='phone'));
   check('Description field available',fields.some(x=>x.tag==='textarea'));
   check('Consent checkbox available',fields.some(x=>x.type==='checkbox'));
   const submit=child.getByRole('button',{name:'Отправить',exact:true}).first();
   check('Submit control visible',await submit.isVisible());
   const childText=(await child.locator('body').innerText()).replace(/\s+/g,' ').slice(0,1000);
   check('Personal data processing notice visible',/соглас|персональн/.test(childText));
   result.fields=fields;
   result.formUiPreview=childText.slice(0,200);
   result.assistantErrors=pageErrors;
   const service=await page.goto(site.replace(/\/$/,'')+config.service,{waitUntil:'domcontentloaded',timeout:30000});
   check('Service page HTTP 200',service?.status()===200);
   const serviceLinks=await page.locator('a[href]').evaluateAll(anchors=>anchors.map(a=>a.getAttribute('href'))
     .filter(Boolean).filter(s=>/contact|index\.html#contact/.test(s)||s.startsWith('mailto:')).slice(0,10));
   check('Service provides contact path',serviceLinks.length>0,serviceLinks);
  }catch(e){result.errors.push('EXCEPTION '+e.message.slice(0,250));output.errors.push(config.host+' '+e.message.slice(0,250))}
  finally{await context.close()}
  console.log('BITRIX_FUNNEL',JSON.stringify(result));
 }
 }finally{await browser.close()}
 await fs.writeFile('oleg-bitrix-funnel-e2e.json',JSON.stringify(output,null,2));
 console.log('BITRIX_FUNNEL_SUMMARY',JSON.stringify({sites:output.results.length,errors:output.errors}));
 if(output.errors.length)process.exitCode=2;
}
main().catch(e=>{console.error('BITRIX_FUNNEL_FATAL',e.message);process.exitCode=1});
