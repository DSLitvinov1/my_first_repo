'use strict';
/**
 * V14 isolated Playwright: real public homepage, V14 helper injected ONLY in
 * browser interception. Entire Bitrix24 form service deliberately unavailable.
 * Browser blocks ALL non-read requests. Never changes either live site.
 */
const { chromium } = require('playwright');
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

const expected = {
  'potrebpravo.ru': 'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',
  'semya-yurist.ru': 'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/'
};
const PHONE = 'tel:+79172052125';
const EMAIL = 'mailto:centr-uprav@inbox.ru';
const ASSET_SHA = 'bdc89e956c80712fdb25c0333d941377d3b1b09afe0bf842a97cea1e9fb64c74';
const contents = fs.readFileSync(__dirname + '/v14-assets/legal-assistant-v4.js');
assert.equal(crypto.createHash('sha256').update(contents).digest('hex'), ASSET_SHA);
async function main(){
  const browser = await chromium.launch({headless:true});
  const report = { state:'OFFLINE_BROWSER_INTERCEPTION_ONLY', checkedAt:new Date().toISOString(), cases:[],production_writes:0,crm_posts:0 };
  try{
    for (const [host,form] of Object.entries(expected)){
      for (const width of [320,390,1365]){
        const context = await browser.newContext({viewport:{width,height:830},locale:'ru-RU'});
        let intercepted=0,blockedBitrix=0,blockedWrites=0;
        await context.route('**/*', async route=>{
          const req=route.request(),url=req.url(),method=req.method().toUpperCase();
          if (!['GET','HEAD','OPTIONS'].includes(method)){blockedWrites++;return route.abort('blockedbyclient');}
          if (/^https:\/\/mc\.yandex\./.test(url)) return route.fulfill({status:204,body:''});
          return route.continue();
        });
        await context.route('**/assets/legal-assistant-v4.js', async route=>{
          const url=new URL(route.request().url());
          if(url.hostname!==host) return route.abort('blockedbyclient');
          intercepted++;
          return route.fulfill({status:200,contentType:'application/javascript; charset=utf-8',body:contents});
        });
        await context.route('https://b24-s2dosa.bitrix24site.ru/**',route=>{
          blockedBitrix++;
          return route.abort('blockedbyclient');
        });
        const page = await context.newPage();
        const item={host,width,pass:false,intercepted:0,blockedBitrix:0,blockedWrites:0};
        report.cases.push(item);
        try {
          const response = await page.goto('https://'+host+'/',{waitUntil:'domcontentloaded',timeout:25000});
          assert.equal(response.status(),200,'public homepage not accessible');
          const deny=page.locator('#oleg-analytics-choice [data-deny]');
          if(await deny.count() && await deny.isVisible()) await deny.click({timeout:8000});
          const launch=page.locator('#legal-help-toggle');
          await launch.waitFor({state:'visible',timeout:10000});
          await launch.click();
          const panel=page.locator('#legal-help-panel');
          assert.equal(await panel.isVisible(),true);
          const classic=page.getByRole('button',{name:'Оставить заявку юристу',exact:true});
          const modern=page.getByRole('button',{name:'Передать вопрос юристу',exact:true});
          await (await classic.count()?classic:modern).click({timeout:8000});
          const step=page.locator('#legal-help-form-step');
          assert.equal(await step.isVisible(),true);
          const hrefs=await step.locator('a[href]').evaluateAll(arr=>arr.map(x=>x.getAttribute('href')));
          assert(hrefs.includes(form),'wrong Bitrix form for '+host);
          assert(hrefs.includes(PHONE),'phone fallback missing');
          assert(hrefs.includes(EMAIL),'email fallback missing');
          const call=step.locator('a[href^="tel:"]').first();
          const mail=step.locator('a[href^="mailto:"]').first();
          assert.equal(await call.isVisible(),true);
          assert.equal(await mail.isVisible(),true);
          await call.scrollIntoViewIfNeeded();
          await mail.scrollIntoViewIfNeeded();
          const frame=await step.locator('iframe.legal-frame').getAttribute('src');
          assert.equal(frame,form,'wrong iframe URL');
          assert((await step.innerText()).includes('Если Битрикс24 недоступен'));
          assert(!(await step.innerText()).includes('Заявка успешно отправлена'));
          assert.equal(intercepted,1,'candidate asset intercept count');
          await page.waitForTimeout(450);
          assert(blockedBitrix>=1,'failure simulation never exercised');
          const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
          assert(overflow<=4,'horizontal overflow: '+overflow);
          item.pass=true;
          item.overflow=overflow;
          item.fallback='phone+email+direct-form-link';
        }catch(e){ item.error=String(e.message).slice(0,400); }
        finally{
          item.intercepted=intercepted;
          item.blockedBitrix=blockedBitrix;
          item.blockedWrites=blockedWrites;
          await context.close();
        }
        report.production_writes += 0;
        console.log('V14_CDN_FAILOVER',JSON.stringify(item));
      }
    }
  }finally{await browser.close();}
  report.passed=report.cases.filter(x=>x.pass).length;
  report.total=report.cases.length;
  fs.writeFileSync('oleg-v14-contact-fallback-e2e.json',JSON.stringify(report,null,2));
  console.log('V14_CDN_FAILOVER_SUMMARY',JSON.stringify({passed:report.passed,total:report.total,production_writes:0,crm_posts:0}));
  if (report.passed!==report.total) process.exitCode=2;
}
main().catch(e=>{console.error('V14_CDN_FAILOVER_FATAL',String(e.message));process.exitCode=1});
