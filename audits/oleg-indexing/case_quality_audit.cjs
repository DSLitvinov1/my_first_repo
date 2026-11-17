'use strict';
// Read-only Playwright case-page content review for legal accuracy and SEO usefulness.
// Public pages only. Never writes to hosting or logs personal data verbatim.
const { chromium }=require('playwright');
const fs=require('node:fs/promises');
const cases={
 'potrebpravo.ru':[
 'zpp-staircase','developer-one','developer-two','developer-three','developer-four',
 'traffic-accident','rental-dispute','rental-money','consumer-refunded'
 ],
 'semya-yurist.ru':[
 'family-invalid-marriage','family-alimony-appeal','family-alimony-cassation','family-divorce-public-example'
 ]
};
function compact(s){return String(s||'').replace(/\s+/g,' ').trim();}
async function main(){
 const result={checkedAt:new Date().toISOString(),tool:'Playwright',mode:'read_only_public_case_quality',cases:[],errors:[]};
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({javaScriptEnabled:false});
 await page.route('**/*',route=>{
  const req=route.request();
  if(['image','media','font','stylesheet','script'].includes(req.resourceType()))return route.abort();
  return route.continue();
 });
 try{
  for(const [host,slugs] of Object.entries(cases)){
   for(const slug of slugs){
    const url='https://'+host+'/practice/cases/'+slug+'.html';
    const item={host,slug,url};result.cases.push(item);
    try{
     const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:25000});
     item.http=response?.status()||0;
     const details=await page.evaluate(()=>{
      const main=document.querySelector('main')||document.body;
      const selectors='h1,h2,h3';
      const headings=[...main.querySelectorAll(selectors)].map(x=>({level:x.tagName.toLowerCase(),text:x.textContent.trim().slice(0,110)}));
      const paragraphs=[...main.querySelectorAll('p,li')].map(x=>x.textContent.trim()).filter(x=>x.length>35);
      const links=[...main.querySelectorAll('a[href]')].map(a=>({
       url:a.href,
       text:a.textContent.trim().slice(0,90)
      }));
      const mainText=main.innerText||main.textContent||'';
      const bodyText=document.body.innerText||document.body.textContent||'';
      return {
       title:document.title,description:document.querySelector('meta[name="description"]')?.content||'',
       headings,paragraphCount:paragraphs.length,
       paragraphLengths:paragraphs.map(x=>x.length).slice(0,30),
       wordCount:mainText.replace(/\s+/g,' ').trim().split(/\s+/).filter(Boolean).length,
       mainHtmlTags:[...main.children].slice(0,12).map(x=>({tag:x.tagName.toLowerCase(),className:x.className?.toString().slice(0,80)})),
       hasPdfLink:links.some(x=>/\.pdf(\?|$)/i.test(x.url)),
       serviceLinks:links.filter(x=>/\/services\//.test(x.url)).slice(0,15),
       hasAuthor:!!main.querySelector('[rel="author"],[itemprop="author"],.author'),
       hasDate:!!main.querySelector('time[datetime]'),
       bodyWordCount:bodyText.replace(/\s+/g,' ').trim().split(/\s+/).filter(Boolean).length
      };
     });
     Object.assign(item,details);
     if(item.http!==200)result.errors.push(url+' HTTP '+item.http);
    }catch(e){
     item.error=compact(e.message).slice(0,180);
     result.errors.push(url+' '+item.error);
    }
    console.log('CASE',JSON.stringify(item));
   }
  }
 }finally{await browser.close();}
 await fs.writeFile('oleg-legal-case-quality.json',JSON.stringify(result,null,2));
 console.log('CASE_AUDIT_RESULT',JSON.stringify({count:result.cases.length,errors:result.errors}));
 if(result.errors.length)process.exitCode=2;
}
main().catch(err=>{console.error('CASE_AUDIT_FAILED',err.message);process.exitCode=1;});
