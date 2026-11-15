'use strict';
/**
 * Preview staged, non-deployed HTML through Playwright route interception.
 * Every external Bitrix iframe is replaced with a clearly identified fixture;
 * NO CRM form submission, no analytics telemetry and no production site write.
 */
const { chromium } = require('playwright');
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

const FIXTURES = [
  {host:'potrebpravo.ru',urlPath:'/services/vozvrat-deneg.html',form:'crm_form_fhi3n'},
  {host:'potrebpravo.ru',urlPath:'/practice/cases/consumer-refunded.html',form:'crm_form_fhi3n'},
  {host:'semya-yurist.ru',urlPath:'/services/razvod.html',form:'crm_form_ep5fd'},
  {host:'semya-yurist.ru',urlPath:'/practice/cases/family-alimony-appeal.html',form:'crm_form_ep5fd'},
];
const FORM_HOST='https://b24-s2dosa.bitrix24site.ru';
const results = [];
const blocked = {mutations:0, metrika:0, bitrixMocked:0};

async function run(){
  const browser=await chromium.launch({headless:true});
  try{
    for(const {host,urlPath,form} of FIXTURES){
      for(const mobile of [true,false]){
        const url='https://'+host+urlPath;
        const file=path.join(__dirname,'assistant-stage-output',host,'public_html',urlPath.slice(1));
        const body=await fs.readFile(file,'utf8');
        assert.match(body,/legal-assistant-v4\.js/);
        const context=await browser.newContext({viewport:mobile?{width:390,height:844}:{width:1365,height:900},locale:'ru-RU'});
        await context.route('**/*',async route=>{
          const req=route.request(), requestUrl=req.url();
          if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase())){
            blocked.mutations++;return route.abort('blockedbyclient');
          }
          if(requestUrl===url && req.isNavigationRequest()){
            return route.fulfill({status:200,contentType:'text/html; charset=utf-8',body});
          }
          if(requestUrl.startsWith('https://mc.yandex.ru/')){
            blocked.metrika++;return route.fulfill({status:204,body:''});
          }
          if(requestUrl.startsWith(FORM_HOST)){
            blocked.bitrixMocked++;return route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><html><body>TEST FIXTURE: No CRM submission possible</body></html>'});
          }
          return route.continue();
        });
        const page=await context.newPage();
        try{
          const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:28000});
          assert.equal(response?.status(),200);
          const deny=page.locator('#oleg-analytics-choice [data-deny]');
          if(await deny.count() && await deny.isVisible())await deny.click({timeout:5000});
          const launch=page.locator('#legal-help-toggle');
          await launch.waitFor({state:'visible',timeout:14000});
          assert.equal(await launch.count(),1);
          await launch.click({timeout:6000});
          const panel=page.locator('#legal-help-panel');
          assert.equal(await panel.isVisible(),true,'Assistant dialog should open');
          const primary=panel.locator('button.legal-primary');
          await primary.click({timeout:6000});
          const iframe=panel.locator('#legal-help-form-step iframe.legal-frame');
          await iframe.waitFor({state:'attached',timeout:5000});
          const expected=FORM_HOST+'/'+form+'/';
          assert.equal(await iframe.getAttribute('src'),expected);
          const fallback=panel.locator('#legal-help-form-step a.legal-open');
          assert.equal(await fallback.getAttribute('href'),expected);
          assert.equal(await fallback.getAttribute('target'),'_blank');
          const safeRel=await fallback.getAttribute('rel');
          assert.match(safeRel||'',/noopener/);
          const rect=await panel.boundingBox();
          assert.ok(rect && rect.x>=0 && rect.y>=0 && rect.x+rect.width <= (mobile?392:1367),'Dialog fits viewport');
          const row={host,urlPath,viewport:mobile?'mobile':'desktop',assistant:'visible',dialog:'opens',formUrl:'correct',fallback:'correct',production_modified:false,crm_submitted:false};
          results.push(row);
        }finally{await context.close();}
      }
    }
  }finally{await browser.close();}
  assert.equal(results.length,8);
  assert.equal(blocked.mutations,0,'Unexpected mutating request attempted');
  const result={status:'STAGED_ASSISTANT_BROWSER_SMOKE_PASS',flows:results.length,results,blocked,html_source:'local patched public HTML via Playwright route; live JS asset; fake Bitrix iframe',production_modified:false};
  await fs.writeFile('assistant-stage-output/playwright-smoke.json',JSON.stringify(result,null,2));
  console.log('ASSISTANT_BROWSER_SMOKE='+JSON.stringify({status:result.status,flows:result.flows,blocked,sites:[...new Set(results.map(r=>r.host))]}));
}
run().catch(e=>{console.error('ASSISTANT_BROWSER_SMOKE_FAILED',e.message);process.exitCode=1});
