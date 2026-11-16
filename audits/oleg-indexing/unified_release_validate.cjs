'use strict';
/** V9: static Playwright DOM validation of all 41 combined OFFLINE HTML pages.
 * Loads local release bytes only, disables JS/network, never touches Bitrix/Timeweb.
 */
const fs=require('node:fs/promises');
const path=require('node:path');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');

const OUTPUT=path.join(__dirname,'unified-stage-output');
const norm=v=>String(v||'').replace(/\s+/g,' ').trim();
const byKey=(host,rel)=>host+'::'+rel;

async function main(){
 const report=JSON.parse(await fs.readFile(path.join(OUTPUT,'unified-manifest.json'),'utf8'));
 const metas=JSON.parse(await fs.readFile('METADATA_PROPOSALS_20261115.json','utf8'));
 const links=JSON.parse(await fs.readFile('CASE_RELATED_LINKS_20261115.json','utf8'));
 const meta=new Map();
 const related=new Map();
 for(const site of metas.sites)
  for(const entry of site.changes)meta.set(byKey(site.host,entry.path),entry);
 for(const entry of links.changes)related.set(byKey(entry.host,entry.path),entry);
 assert.equal(report.status,'OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT');
 assert.equal(report.production_modified,false);
 assert.equal(report.real_crm_verified,false);
 assert.equal(report.manifest.length,43);

 const results=[];
 const browser=await chromium.launch({headless:true});
 try{
  for(const item of report.manifest.filter(x=>x.path.endsWith('.html'))){
   const file=path.join(OUTPUT,'unified-release',item.host,'public_html',item.path);
   const html=await fs.readFile(file,'utf8');
   const page=await browser.newPage({javaScriptEnabled:false,viewport:{width:390,height:844}});
   try{
    // Absolutely no outside resources: local HTML parsed as a pure DOM snapshot.
    await page.route('**/*',route=>route.abort('blockedbyclient'));
    await page.setContent(html,{waitUntil:'domcontentloaded'});
    const actual=await page.evaluate(()=>({
      title:document.title,
      description:document.querySelector('meta[name="description" i]')?.getAttribute('content')||'',
      canonical:document.querySelector('link[rel="canonical"]')?.getAttribute('href')||'',
      assistant:[...document.querySelectorAll('script[src]')].filter(x=>x.getAttribute('src')?.includes('/assets/legal-assistant-v4.js')).length,
      consentStyle:document.querySelectorAll('style#oleg-consent-priority').length,
      related:[...document.querySelectorAll('nav.article-related')].map(x=>({
        id:x.id,links:[...x.querySelectorAll('a[href]')].map(a=>a.getAttribute('href'))
      })),
      main:document.querySelectorAll('main').length
    }));
    const expectedUrl='https://'+item.host+(item.path==='index.html'?'/':'/'+item.path);
    assert.equal(actual.canonical,expectedUrl,'Wrong canonical '+expectedUrl);
    assert.ok(norm(actual.title).length>7,'Empty/short title '+expectedUrl);
    assert.ok(norm(actual.description).length>=30,'Empty/short description '+expectedUrl);
    assert.equal(actual.main,1,'Wrong main count '+expectedUrl);
    assert.equal(actual.assistant,1,'Assistant must appear once '+expectedUrl);
    assert.equal(actual.consentStyle,item.path==='index.html'?0:1,
      'Wrong consent priority style count '+expectedUrl);
    assert.doesNotMatch(html,/qwen[^<]*\.js|Ответ Qwen|Использовать Qwen 3\.5/i,'Qwen must not be present');

    const key=byKey(item.host,item.path);
    if(meta.has(key)){
      const expected=meta.get(key).proposed;
      for(const prop of ['title','description']){
       if(Object.prototype.hasOwnProperty.call(expected,prop))
        assert.equal(norm(actual[prop]),norm(expected[prop]),'Metadata release mismatch '+expectedUrl+' '+prop);
      }
    }
    if(related.has(key)){
      const planned=related.get(key);
      assert.equal(actual.related.length,1,'Related block must appear once '+expectedUrl);
      assert.equal(actual.related[0].id,'oleg-related-'+path.basename(item.path,'.html'));
      assert.deepEqual(actual.related[0].links,planned.related.map(l=>l.href),
        'Related links differ '+expectedUrl);
    }
    results.push({
      url:expectedUrl,source_sha256:item.original_sha256,proposed_sha256:item.proposed_sha256,
      metadataUpdated:meta.has(key),contextLinksUpdated:related.has(key),
      assistantPresent:1,consentStylePresent:actual.consentStyle,
      status:'offline-dom-verified',production_tested:false
    });
   }finally{await page.close()}
  }
 }finally{await browser.close()}
 assert.equal(results.length,41);
 assert.equal(results.filter(r=>r.metadataUpdated).length,20);
 assert.equal(results.filter(r=>r.contextLinksUpdated).length,13);
 await fs.writeFile(path.join(OUTPUT,'playwright-41-offline.json'),
  JSON.stringify({status:'OFFLINE_41_41_DOM_PASS',type:'Playwright local HTML without scripts or network',
    production_checked:false,real_CRM_checked:false,results},null,2));
 console.log('OLEG_V9_UNIFIED_PLAYWRIGHT_41_41_PASS '+JSON.stringify({
  pages:results.length,metadata:20,related:13,production_checked:false
 }));
}
main().catch(e=>{console.error('OLEG_V9_UNIFIED_PLAYWRIGHT_FAILED',e.stack||String(e));process.exitCode=2;});
