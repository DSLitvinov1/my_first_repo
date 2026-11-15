'use strict';
/**
 * Explicit one-shot end-to-end synthetic lead test in Oleg's two native Bitrix24 forms.
 * DO NOT use for continuous health checks. The CI workflow only calls this script for
 * a one-time, precisely named pull-request commit and first workflow attempt.
 * This script does NOT read or write the authenticated Bitrix24 dashboard.
 */
const { chromium } = require('playwright');
const fs = require('node:fs/promises');

const SITES=[
  {host:'potrebpravo.ru',form:'crm_form_fhi3n',key:'consumer'},
  {host:'semya-yurist.ru',form:'crm_form_ep5fd',key:'family'}
];
const expectedHost='b24-s2dosa.bitrix24site.ru';
const compact=s=>String(s||'').replace(/\s+/g,' ').trim();

async function main(){
 if(process.argv.indexOf('--execute-single-live-check')<0 || process.env.OWNER_AUTHORIZED_CRM_TEST !== 'true' ||
   process.env.GITHUB_RUN_ATTEMPT!=='1' || process.env.GITHUB_EVENT_NAME!=='push' ||
   process.env.GITHUB_REF_NAME!=='audit-oleg-sites-playwright-20261115') {
   throw Error('Explicit owner-authorized single-run CI guard not satisfied; no lead submitted.');
 }
 const runToken=String(process.env.GITHUB_RUN_ID||'');
 if(!/^\d{8,20}$/.test(runToken))throw Error('Missing/invalid audit run ID');
 const result={time:new Date().toISOString(),runId:runToken,operator:'Playwright one-time synthetic Bitrix24 lead test',
   leads:[],notice:'Form UI acceptance is not a verified Bitrix24 CRM database record.'};
 const browser=await chromium.launch({headless:true});
 try{
  for(const site of SITES){
   const key='TEST-SEO-CRM-'+runToken+'-'+site.key;
   const details={site:site.host,testKey:key,submitted:false,formAccepted:false,responses:[],errors:[]};
   result.leads.push(details);
   const context=await browser.newContext({viewport:{width:1280,height:900},locale:'ru-RU'});
   const page=await context.newPage();
   page.on('response',res=>{
     if(res.request().method().toUpperCase()!=='POST')return;
     try{
      const u=new URL(res.url());
      if(u.hostname===expectedHost)details.responses.push({path:u.pathname,status:res.status()});
     }catch{}
   });
   try{
    const homepage='https://'+site.host+'/';
    const homepageRes=await page.goto(homepage,{waitUntil:'domcontentloaded',timeout:30000});
    if(homepageRes?.status()!==200)throw Error('Site homepage status not 200');
    const testPhone=await page.locator('a[href^="tel:"]').first().getAttribute('href');
    if(!testPhone||!/^tel:\+7\d{10}$/.test(testPhone))throw Error('Owner phone is not verifiably listed on the page');
    // The owner's own public contact number is used, never a random third party's number.
    const banner=page.locator('#oleg-analytics-choice');
    if(await banner.count() && await banner.isVisible()){
      await banner.locator('[data-deny]').click({timeout:10000});
    }
    await page.locator('#legal-help-toggle').click({timeout:12000});
    await page.getByRole('button',{name:/Передать вопрос юристу|Оставить заявку юристу/}).click({timeout:12000});
    const iframe=page.locator('iframe.legal-frame');
    await iframe.waitFor({state:'visible',timeout:15000});
    const src=await iframe.getAttribute('src');
    const exact='https://'+expectedHost+'/'+site.form+'/';
    if(src!==exact)throw Error('Wrong form iframe: '+compact(src).slice(0,200));
    const frame=page.frameLocator('iframe.legal-frame');
    const form=frame.locator('form').first();
    await form.waitFor({state:'visible',timeout:35000});
    const name=form.locator('input[name="name"]');
    const phone=form.locator('input[name="phone"]');
    const description=form.locator('textarea').first();
    if(await name.count()!==1||await phone.count()!==1||await description.count()!==1)
      throw Error('One or more exact form input fields missing');
    await name.fill('ТЕСТ — ПРОВЕРКА CRM SEO');
    await phone.fill(testPhone.slice(4));
    await description.fill(
      'ТЕСТОВАЯ ПРОВЕРКА ПОСТУПЛЕНИЯ ЗАЯВКИ В CRM. Не клиент, не звонить и не обрабатывать как реальный лид. '+
      'Источник: https://'+site.host+'/; контрольный идентификатор: '+key+'.'
    );
    const checkbox=form.locator('input[type="checkbox"]').first();
    if(await checkbox.count()===1){
      await checkbox.check({force:true,timeout:8000});
      if(!await checkbox.isChecked())throw Error('Form consent checkbox not checked');
    }
    // The user requested a real CRM submission. Click the SEND button just once.
    const submit=frame.getByRole('button',{name:'Отправить',exact:true}).first();
    if(!await submit.isVisible())throw Error('Submit button not visible');
    details.submitted=true;
    await submit.click({timeout:10000});
    // A native Bitrix24 form can ask to reconfirm consent after first submit.
    const accept=frame.getByRole('button',{name:'Принимаю',exact:true});
    if(await accept.count() && await accept.isVisible().catch(()=>false)){
      await accept.click({timeout:8000});
    }
    // Never submit again if outcome is ambiguous; inspect the UI and outgoing response instead.
    await page.waitForTimeout(3200);
    const text=compact(await frame.locator('body').innerText()).slice(0,1200);
    const success=/(спасибо|успешно\s+отправлен|заявк[ау]\s+отправлен|сообщение\s+отправлено|форма\s+отправлена|thank you)/i.test(text);
    const formGone=await form.isHidden().catch(()=>false);
    details.formAccepted=!!success;
    details.postStatus=details.responses.map(x=>x.status);
    details.formHiddenAfterSubmit=formGone;
    details.outcomeText=success?text.slice(0,140):text.slice(0,280);
    if(!success){
      details.errors.push('No native Bitrix24 success message visible after one submit; outcome unconfirmed.');
    }
   }catch(e){
    details.errors.push(compact(e.message).slice(0,360));
   }finally{await context.close()}
   console.log('BITRIX_ONE_OFF',JSON.stringify(details));
  }
 }finally{await browser.close()}
 await fs.writeFile('oleg-bitrix-single-live-leads.json',JSON.stringify(result,null,2));
 console.log('BITRIX_ONE_OFF_SUMMARY',JSON.stringify(result.leads.map(x=>({
  site:x.site,key:x.testKey,submitted:x.submitted,formAccepted:x.formAccepted,postStatus:x.postStatus,errors:x.errors
 }))));
 if(result.leads.some(x=>!x.formAccepted))process.exitCode=2;
}
main().catch(e=>{console.error('BITRIX_ONE_OFF_FATAL',e.message);process.exitCode=1});
