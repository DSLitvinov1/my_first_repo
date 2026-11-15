'use strict';
// Release preflight: verify existing public HTML still matches proposed SEO changes.
// This is a read-only Playwright browser; it neither submits to search engines nor updates hosting.
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const norm=x=>String(x??'').replace(/\s+/g,' ').trim();
const sameOrigin=(url,base)=>{try{return new URL(url).origin===base}catch{return false}};
async function main(){
 const plan=JSON.parse(await fs.readFile('CASE_RELATED_LINKS_20261115.json','utf8'));
 const metadata=JSON.parse(await fs.readFile('METADATA_PROPOSALS_20261115.json','utf8'));
 if(plan.status!=='REVIEW_ONLY_NOT_DEPLOYED'||metadata.status!=='REVIEW_ONLY_NOT_DEPLOYED')throw Error('Review gate missing');
 const checks={time:new Date().toISOString(),type:'Playwright public SEO staged patch release preflight',cases:[],metadata:[],targetUrls:[],errors:[]};
 const browser=await chromium.launch({headless:true});
 const api=await request.newContext({timeout:20000,ignoreHTTPSErrors:false});
 const page=await browser.newPage({javaScriptEnabled:false,ignoreHTTPSErrors:false});
 await page.route('**/*',r=>['image','font','media','script','stylesheet'].includes(r.request().resourceType())?r.abort():r.continue());
 const targets=new Set();
 try{
  for(const item of plan.changes){
   const res=await page.goto(item.url,{waitUntil:'domcontentloaded',timeout:25000});
   const actual=await page.evaluate(()=>({
    title:document.title,
    main:document.querySelectorAll('main').length,
    articles:[...document.querySelectorAll('main article')].filter(x=>x.classList.contains('article')).length,
    links:[...document.querySelectorAll('a[href]')].map(x=>x.href),
    related:!!document.querySelector('[id^="oleg-related-"]')
   }));
   const expected=norm(item.expectedTitle);
   const bad=[];
   if(res?.status()!==200)bad.push('HTTP_'+res?.status());
   if(page.url()!==item.url)bad.push('Redirect');
   if(norm(actual.title)!==expected)bad.push('Title drift');
   if(actual.main!==1||actual.articles!==1)bad.push('Unexpected main/article structure');
   if(actual.related)bad.push('Related links already inserted');
   for(const link of item.related){
    const dest='https://'+item.host+link.href;
    if(!sameOrigin(dest,'https://'+item.host))bad.push('Wrong link host');
    if(actual.links.includes(dest))bad.push('Related link already in page '+dest);
    targets.add(dest);
   }
   checks.cases.push({url:item.url,htmlStatus:res?.status()||0,preflight:bad.length?'blocked':'ready',issues:bad});
   for(const reason of bad)checks.errors.push(item.url+' '+reason);
  }
  for(const site of metadata.sites){
   for(const item of site.changes){
    const res=await page.goto(item.url,{waitUntil:'domcontentloaded',timeout:25000});
    const current=await page.evaluate(()=>({
     title:document.title||'',description:document.querySelector('meta[name="description" i]')?.content||''
    }));
    const bad=[];
    if(res?.status()!==200)bad.push('HTTP '+res?.status());
    if(page.url()!==item.url)bad.push('Redirect');
    for(const field of Object.keys(item.proposed)){
     if(norm(current[field])!==norm(item.expected[field])&&norm(current[field])!==norm(item.proposed[field]))bad.push(field+' drift');
    }
    checks.metadata.push({url:item.url,preflight:bad.length?'blocked':'ready',issues:bad});
    for(const reason of bad)checks.errors.push(item.url+' '+reason);
   }
  }
  for(const url of targets){
   let status=0,canonical='';
   try{
    const r=await page.goto(url,{waitUntil:'domcontentloaded',timeout:25000});
    status=r?.status()||0;
    canonical=await page.locator('link[rel="canonical"]').first().getAttribute('href')||'';
   }catch(e){checks.errors.push('Target inaccessible: '+url+' '+norm(e.message).slice(0,200));}
   if(status!==200||canonical!==url)checks.errors.push('Target invalid '+url+' HTTP '+status+' canonical '+canonical);
   checks.targetUrls.push({url,status,canonical});
  }
 }finally{
  await page.close();await browser.close();await api.dispose();
 }
 await fs.writeFile('oleg-staged-seo-preflight.json',JSON.stringify(checks,null,2));
 console.log('STAGED_SEO_PREFLIGHT',JSON.stringify({
  cases:checks.cases.length,metadata:checks.metadata.length,targets:checks.targetUrls.length,
  readyCases:checks.cases.filter(x=>x.preflight==='ready').length,
  readyMetadata:checks.metadata.filter(x=>x.preflight==='ready').length,
  errors:checks.errors.slice(0,60)
 }));
 if(checks.errors.length)process.exitCode=2;
}
main().catch(e=>{console.error('STAGED_SEO_PREFLIGHT_FAILED',e.message);process.exitCode=1});
