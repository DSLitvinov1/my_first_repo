'use strict';
/**
 * V15 main contact: real site layout, browser-only HTML patch using actual
 * Python helper; Bitrix and all writes blocked. No production modification.
 */
const { chromium } = require('playwright');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');

const config = {
  'potrebpravo.ru': 'crm_form_fhi3n',
  'semya-yurist.ru': 'crm_form_ep5fd',
};
const status = {
  mode: 'LIVE_HOMEPAGE_HTML_WITH_BROWSER_ONLY_PATCH',
  recordedAt: new Date().toISOString(),
  results: [],
  crmSubmissions: 0,
  productionWrites: 0,
};

const patchSnippet = [
  'import sys',
  'from bitrix_primary_contact_v15 import patch',
  'sys.stdout.write(patch(sys.stdin.read(),sys.argv[1]))'
].join('; ');

async function run(){
  const browser = await chromium.launch({headless:true});
  try{
    for (const [host,formId] of Object.entries(config)){
      for (const width of [320,390,1365]){
        const context=await browser.newContext({viewport:{width,height:850},locale:'ru-RU'});
        let blockedBitrix=0, blockedWrites=0, replacedHTML=0;
        const report = {host,width,success:false};
        status.results.push(report);
        await context.route('**/*',route=>{
          const req=route.request();
          if(!['GET','HEAD','OPTIONS'].includes(req.method().toUpperCase())){
            blockedWrites++;
            return route.abort('blockedbyclient');
          }
          if(/^https:\/\/mc\.yandex\./i.test(req.url())) return route.fulfill({status:204,body:''});
          return route.continue();
        });
        await context.route('https://b24-s2dosa.bitrix24site.ru/**',route=>{
          blockedBitrix++;
          return route.abort('blockedbyclient');
        });
        await context.route('https://'+host+'/',async route=>{
          const response=await route.fetch({timeout:25000});
          if(response.status()!==200) throw new Error('Public site HTTP status '+response.status());
          const html=await response.text();
          const py=spawnSync('python3',['-c',patchSnippet,host],{
            input:html,encoding:'utf8',maxBuffer:1024*1024*3,
          });
          if(py.status!==0)throw new Error('V15 patch refused live HTML: '+String(py.stderr).slice(0,320));
          replacedHTML++;
          await route.fulfill({response,body:py.stdout,contentType:'text/html; charset=utf-8'});
        });
        const page=await context.newPage();
        try {
          const response=await page.goto('https://'+host+'/',{waitUntil:'domcontentloaded',timeout:30000});
          if(response?.status()!==200)throw new Error('Homepage unavailable');
          const deny=page.locator('#oleg-analytics-choice [data-deny]');
          if(await deny.count() && await deny.isVisible())await deny.click({timeout:5000});
          const visible=page.locator('.lead-form-unavailable');
          await visible.waitFor({state:'visible',timeout:8000});
          const correctURL='https://b24-s2dosa.bitrix24site.ru/'+formId+'/';
          const link=visible.locator('a[href="'+correctURL+'"]');
          if(await link.count()!==1||!await link.isVisible())throw new Error('Correct direct CRM link missing');
          if(await link.getAttribute('rel')!=='noopener noreferrer')throw new Error('External link unsafe');
          const phone=visible.locator('a[href="tel:+79172052125"]');
          const mail=visible.locator('a[href="mailto:centr-uprav@inbox.ru"]');
          if(!await phone.isVisible()||!await mail.isVisible())throw new Error('Fallback phone or email unavailable');
          await link.scrollIntoViewIfNeeded({timeout:10000});
          const legacy=page.locator('#lead-form');
          if(await legacy.isVisible())throw new Error('Old unverified form unexpectedly visible');
          if(await page.locator('body').getAttribute('data-form-mode')!=='demo')throw new Error('Legacy form unexpectedly enabled');
          if((await visible.innerText()).includes('успешно отправлена'))throw new Error('False CRM success message');
          const overflow=await page.evaluate(()=>Math.max(0,document.documentElement.scrollWidth-document.documentElement.clientWidth));
          if(overflow>4)throw new Error('Horizontal overflow '+overflow);
          if(replacedHTML!==1)throw new Error('Patched HTML not used exactly once');
          report.success=true;
          report.overflow=overflow;
          report.primary='direct-bitrix-link';
          report.backups=['tel','mailto'];
          report.legacyForm='hidden';
        }catch(e){report.error=String(e.message).slice(0,350)}
        finally{
          report.htmlPatched=replacedHTML;
          report.blockedWrites=blockedWrites;
          report.bitrixBlockedRequests=blockedBitrix;
          await context.close();
        }
        console.log('V15_PRIMARY_CRM_LINK',JSON.stringify(report));
      }
    }
  }finally{await browser.close();}
  status.passed=status.results.filter(x=>x.success).length;
  status.total=status.results.length;
  fs.writeFileSync('oleg-v15-primary-link-browser.json',JSON.stringify(status,null,2));
  console.log('V15_PRIMARY_CRM_BROWSER_SUMMARY',JSON.stringify({passed:status.passed,total:status.total,crmSubmissions:0,productionWrites:0}));
  if(status.passed!==status.total)process.exitCode=2;
}
run().catch(e=>{console.error('V15_PRIMARY_CRM_BROWSER_FATAL',e.message);process.exitCode=1});
