'use strict';
// Read-only Playwright source inspection of Yandex Metrica tags on Oleg's public pages.
// Never consents, sends events, or submits contact forms.
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const SITE_INFO=[
 {host:'potrebpravo.ru',expectedCounter:'114249897'},
 {host:'semya-yurist.ru',expectedCounter:'114251443'}
];
const locs=text=>[...text.matchAll(/<loc[^>]*>([^<]+)<\/loc>/gi)].map(x=>x[1].replace(/&amp;/g,'&').trim());
async function main(){
 const browser=await chromium.launch({headless:true});
 const api=await request.newContext({timeout:20000,ignoreHTTPSErrors:false});
 const page=await browser.newPage({javaScriptEnabled:false});
 await page.route('**/*',r=>['script','image','font','media','stylesheet'].includes(r.request().resourceType())?r.abort():r.continue());
 const result={checkedAt:new Date().toISOString(),method:'Playwright read-only HTML inspection',sites:[]};
 try{
  for(const site of SITE_INFO){
   const base='https://'+site.host;
   const map=await api.get(base+'/sitemap.xml');
   if(map.status()!==200)throw Error('Sitemap cannot be read: '+base);
   const urls=[...new Set([...locs(await map.text()),base+'/privacy.html',base+'/consent.html'])];
   const out={host:site.host,expectedCounter:site.expectedCounter,checked:0,scriptTagged:0,missingScripts:[],assetURLs:[],assetChecks:[],htmlErrors:[]};
   result.sites.push(out);
   const scripts=new Set();
   for(const url of urls){
    try{
     const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:25000});
     if(response?.status()!==200){out.htmlErrors.push({url,status:response?.status()});continue;}
     out.checked++;
     const tags=await page.evaluate(()=>[...document.querySelectorAll('script[src]')].map(e=>e.src));
     const matching=tags.filter(x=>x.includes('oleg-analytics')||x.includes('mc.yandex.ru/metrika/tag.js'));
     if(matching.length){
      out.scriptTagged++;
      for(const src of matching)scripts.add(src);
     }else out.missingScripts.push(url);
    }catch(e){out.htmlErrors.push({url,error:e.message.slice(0,180)});}
   }
   out.assetURLs=[...scripts];
   for(const url of scripts){
    const response=await api.get(url,{failOnStatusCode:false});
    const text=await response.text();
    out.assetChecks.push({
     url,status:response.status(),matchesCounter:text.includes(site.expectedCounter),
     hasConsentPanel:/oleg-analytics-choice/.test(text),disabledWebvisor:/webvisor\s*:\s*false/.test(text)
    });
   }
   out.ready=out.checked===urls.length && out.scriptTagged===urls.length &&
     out.assetChecks.length>0 && out.assetChecks.every(x=>x.status===200&&x.matchesCounter&&x.hasConsentPanel&&x.disabledWebvisor);
   console.log('METRIKA_SOURCE',JSON.stringify(out));
  }
 }finally{await page.close();await browser.close();await api.dispose();}
 await fs.writeFile('oleg-analytics-presence.json',JSON.stringify(result,null,2));
 console.log('METRIKA_SOURCE_RESULT',result.sites.map(x=>({host:x.host,checked:x.checked,tagged:x.scriptTagged,ready:x.ready})));
}
main().catch(e=>{console.error('METRIKA_SOURCE_AUDIT_FAILED',e.message);process.exitCode=1});
