'use strict';
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const roots=['https://potrebpravo.ru','https://semya-yurist.ru'];
const result={checked_at:new Date().toISOString(),mode:'public_no_auth_readonly',sites:[]};
const good=(url,base)=>{try{return new URL(url).origin===new URL(base).origin}catch{return false}};
const locs=xml=>[...xml.matchAll(/<loc[^>]*>\s*([^<\s]+)\s*<\/loc>/gi)].map(m=>m[1].replaceAll('&amp;','&'));
const clean=x=>String(x||'').replace(/\s+/g,' ').trim().slice(0,220);
async function main(){
 const api=await request.newContext({timeout:20000,ignoreHTTPSErrors:false});
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 for(const base of roots){
  const out={site:base,probes:{},pages:[],issues:[]}; result.sites.push(out);
  async function fetch(url){
   try{let r=await api.get(url,{maxRedirects:6});return {status:r.status(),body:await r.text(),url:r.url(),headers:r.headers()}}
   catch(e){return {status:null,body:'',error:clean(e.message)}}
  }
  const robots=await fetch(base+'/robots.txt');
  out.probes.robots={status:robots.status,error:robots.error,preview:robots.body.slice(0,2500)};
  if(robots.status===200&&/Disallow:\s*\/\s*(\r?\n|$)/i.test(robots.body))out.issues.push('POSSIBLE_ROOT_DISALLOW_ROBOTS: review user-agent grouping');
  const urls=new Set([base+'/']),nested=new Set();
  for(const name of ['/sitemap.xml','/sitemap_index.xml']){
   const resp=await fetch(base+name);
   out.probes[name]={status:resp.status,error:resp.error,content_type:resp.headers?.['content-type']};
   if(resp.status!==200)continue;
   for(const url of locs(resp.body)){
    if(!good(url,base))continue;
    if(/\.xml(\?|$)/i.test(url))nested.add(url);else urls.add(url);
   }
  }
  for(const url of [...nested].slice(0,4)){
   const resp=await fetch(url);
   out.probes[url]={status:resp.status,error:resp.error};
   if(resp.status===200)for(const u of locs(resp.body))if(good(u,base))urls.add(u);
  }
  if(urls.size===1)out.issues.push('NO_SITEMAP_URLS_FOUND: investigate sitemap');
  const page=await browser.newPage({javaScriptEnabled:true,ignoreHTTPSErrors:false});
  await page.route('**/*',r=>['image','font','media'].includes(r.request().resourceType())?r.abort():r.continue());
  for(const url of urls){
   if(out.pages.length>=16)break;
   const line={url};out.pages.push(line);
   try{
    const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:25000});
    line.http=response?.status()??null;line.final=page.url();line.x_robots=response?.headers()?.['x-robots-tag']||'';
    const meta=await page.evaluate(()=>({
     title:document.title,
     desc:document.querySelector('meta[name="description"]')?.content||'',
     canonical:document.querySelector('link[rel="canonical"]')?.href||'',
     robots:[...document.querySelectorAll('meta[name="robots"],meta[name="yandex"],meta[name="googlebot"]')].map(x=>x.content),
     h1:[...document.querySelectorAll('h1')].map(x=>x.textContent.trim().slice(0,120)),
     links:[...document.querySelectorAll('a[href]')].map(x=>x.href).slice(0,250)
    }));
    line.title=clean(meta.title);line.description=clean(meta.desc);line.canonical=meta.canonical;line.meta_robots=meta.robots;
    line.h1=meta.h1;line.internal_links=meta.links.filter(x=>good(x,base)).length;
    if(url===base+'/')for(const link of meta.links){
     if(urls.size>=55)break;
     if(good(link,base)){let next=new URL(link);next.hash='';if(!/\.(jpg|png|gif|svg|webp|pdf|js|css)$/i.test(next.pathname))urls.add(next.href)}
    }
    if(line.http!==200)out.issues.push('HTTP_'+line.http+' '+url);
    if(/noindex|none/i.test([line.x_robots,...meta.robots].join(' ')))out.issues.push('NOINDEX '+url);
    if(!line.title)out.issues.push('MISSING_TITLE '+url);
    if(!line.description)out.issues.push('MISSING_DESCRIPTION '+url);
    if(meta.h1.length!==1)out.issues.push('H1_COUNT_'+meta.h1.length+' '+url);
    if(meta.canonical&&!good(meta.canonical,base))out.issues.push('EXTERNAL_CANONICAL '+url);
   }catch(e){line.error=clean(e.message);out.issues.push('NAVIGATION_FAILED '+url+' '+line.error)}
  }
  await page.close();
  console.log('\nSITE '+base+' robots='+out.probes.robots.status+' sitemap='+out.probes['/sitemap.xml'].status);
  for(const p of out.pages)console.log('PAGE '+(p.http??'ERR')+' '+p.url+' title='+JSON.stringify(p.title||'')+' robots='+JSON.stringify(p.meta_robots||[])+' canonical='+(p.canonical||'')+' error='+(p.error||''));
  for(const issue of out.issues)console.log('ISSUE '+issue);
 }
 await browser.close();await api.dispose();
 await fs.writeFile('oleg-indexability.json',JSON.stringify(result,null,2));
 console.log('RESULT_JSON_WRITTEN');
}
main().catch(e=>{console.error('AUDIT_FAILED',e);process.exitCode=1});