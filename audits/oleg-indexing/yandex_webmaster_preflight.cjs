'use strict';
// Public Yandex Webmaster checks via Playwright Chromium. No login, cookies or writes.
// YandexBot-like UA is only a simulation, not a claim of genuine Yandex IP access.
const {chromium,request}=require('playwright');
const fs=require('node:fs/promises');
const SITES=[{origin:'https://potrebpravo.ru',expected:23},{origin:'https://semya-yurist.ru',expected:18}];
const clean=s=>String(s??'').replace(/\s+/g,' ').trim();
function locs(xml){return [...String(xml).matchAll(/<loc(?:\s[^>]*)?>\s*([^<]+)\s*<\/loc>/gi)].map(m=>m[1].replace(/&amp;/g,'&').trim());}
function parseRobots(text){
 const groups=[],sitemaps=[];let agents=[],rules=[],started=false;
 const flush=()=>{if(agents.length)groups.push({agents:[...agents],rules:[...rules]});agents=[];rules=[];started=false;};
 for(const src of String(text).split(/\r?\n/)){
  const line=src.replace(/#.*$/,'').trim(),m=line.match(/^([\w-]+)\s*:\s*(.*?)\s*$/);
  if(!m)continue;
  const k=m[1].toLowerCase(),v=m[2];
  if(k==='sitemap'){sitemaps.push(v);continue}
  if(k==='user-agent'){if(started)flush();agents.push(v.toLowerCase())}
  else if((k==='allow'||k==='disallow')&&agents.length){rules.push({kind:k,pattern:v});started=true}
 }
 flush();return{groups,sitemaps};
}
function matches(pattern,path){
 if(!pattern)return false;
 const parts=pattern.split('*').map(x=>x.replace(/[.*+?^$()|[\]{}]/g,'\\$&'));
 let regex='^'+parts.join('.*');
 regex=regex.endsWith('\\$')?regex.slice(0,-2)+'$':regex+'.*';
 return new RegExp(regex).test(path);
}
function permitted(robots,path){
 const specific=robots.groups.filter(g=>g.agents.some(x=>x.includes('yandex')));
 const applicable=specific.length?specific:robots.groups.filter(g=>g.agents.includes('*'));
 const rules=applicable.flatMap(g=>g.rules).filter(x=>matches(x.pattern,path));
 rules.sort((a,b)=>b.pattern.replace(/\*/g,'').length-a.pattern.replace(/\*/g,'').length||(a.kind==='allow'?-1:1));
 return rules[0]?{allowed:rules[0].kind==='allow',rule:rules[0]}:{allowed:true,rule:null};
}
function sitemapEntries(xml){
 return [...String(xml).matchAll(/<url(?:\s[^>]*)?>([\s\S]*?)<\/url>/gi)].map(m=>({
  url:locs(m[1])[0]||'',lastmod:m[1].match(/<lastmod(?:\s[^>]*)?>\s*([^<]+)\s*<\/lastmod>/i)?.[1]?.trim()||null
 }));
}
async function main(){
 const browser=await chromium.launch({headless:true});
 const api=await request.newContext({timeout:20000,ignoreHTTPSErrors:false,userAgent:'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'});
 const result={time:new Date().toISOString(),scope:'public browser, unauthenticated',sites:[]};
 async function fetch(url){
  let error='';for(let i=0;i<3;i++)try{
   const r=await api.get(url,{maxRedirects:5,failOnStatusCode:false});
   return {status:r.status(),final:r.url(),body:await r.text(),headers:r.headers()};
  }catch(e){error=clean(e.message).slice(0,160);if(i<2)await new Promise(resolve=>setTimeout(resolve,(i+1)*500))}
  return{status:0,final:url,body:'',headers:{},error};
 }
 try{
 for(const site of SITES){
  const out={origin:site.origin,robots:{},sitemap:{},pages:[],aliases:[],critical:[],warnings:[]};
  result.sites.push(out);
  const critical=(code,value)=>out.critical.push({code,value});
  const warning=(code,value)=>out.warnings.push({code,value});
  const robotsResponse=await fetch(site.origin+'/robots.txt');
  const robots=parseRobots(robotsResponse.body);
  out.robots={status:robotsResponse.status,sitemaps:robots.sitemaps,ruleGroups:robots.groups.length};
  if(robotsResponse.status!==200)critical('ROBOTS_NOT_200',robotsResponse.status);
  if(!robots.sitemaps.includes(site.origin+'/sitemap.xml'))critical('SITEMAP_NOT_IN_ROBOTS',robots.sitemaps);
  if(!permitted(robots,'/').allowed)critical('YANDEX_ROOT_DISALLOWED',permitted(robots,'/').rule);
  if(!permitted(robots,'/sitemap.xml').allowed)critical('YANDEX_SITEMAP_DISALLOWED',permitted(robots,'/sitemap.xml').rule);
  const sitemapResponse=await fetch(site.origin+'/sitemap.xml');
  const entries=sitemapEntries(sitemapResponse.body),urls=locs(sitemapResponse.body);
  out.sitemap={http:sitemapResponse.status,final:sitemapResponse.final,entries:entries.length,contentType:sitemapResponse.headers['content-type']||''};
  if(sitemapResponse.status!==200||sitemapResponse.final!==site.origin+'/sitemap.xml')critical('SITEMAP_INACCESSIBLE',out.sitemap);
  if(!/<urlset\b/i.test(sitemapResponse.body)||entries.length!==urls.length)critical('SITEMAP_INVALID_XML','');
  if(entries.length!==site.expected)warning('SITEMAP_COUNT_CHANGE',{expected:site.expected,actual:entries.length});
  if(new Set(urls).size!==urls.length)critical('SITEMAP_DUPLICATE','');
  if(!urls.includes(site.origin+'/'))critical('SITEMAP_HOME_MISSING','');
  const page=await browser.newPage({javaScriptEnabled:false,userAgent:'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',ignoreHTTPSErrors:false});
  await page.route('**/*',route=>['image','font','media','stylesheet','script'].includes(route.request().resourceType())?route.abort():route.continue());
  for(const entry of entries.slice(0,85)){
   const obj={url:entry.url,lastmod:entry.lastmod};out.pages.push(obj);
   try{
    const u=new URL(entry.url);
    if(u.origin!==site.origin||u.hash||u.search)critical('NONCANONICAL_SITEMAP_URL',entry.url);
    if(entry.lastmod){
     const stamp=Date.parse(entry.lastmod);
     if(!Number.isFinite(stamp))critical('INVALID_LASTMOD',entry.url);
     else if(stamp>Date.now()+86400000)warning('FUTURE_LASTMOD',entry.url);
    }
    const rule=permitted(robots,u.pathname);obj.allowedByRobots=rule.allowed;
    if(!rule.allowed)critical('YANDEX_ROBOTS_BLOCKS_SITEMAP_URL',{url:entry.url,rule:rule.rule});
    const response=await page.goto(entry.url,{waitUntil:'domcontentloaded',timeout:25000});
    obj.http=response?.status()||0;obj.final=page.url();obj.headers=response?.headers()||{};
    const m=await page.evaluate(()=>({
     canonical:document.querySelector('link[rel~="canonical" i]')?.href||'',
     metaRobots:[...document.querySelectorAll('meta[name="robots" i],meta[name="yandex" i]')].map(x=>x.content||''),
     lang:document.documentElement.lang||''
    }));
    obj.canonical=m.canonical;obj.metaRobots=m.metaRobots;
    const xRobots=obj.headers['x-robots-tag']||'';
    if(obj.http!==200)critical('YANDEXBOT_UA_HTTP',{url:entry.url,status:obj.http});
    if(obj.final!==entry.url)critical('SITEMAP_PAGE_REDIRECT',{url:entry.url,final:obj.final});
    if(obj.canonical!==entry.url)critical('SITEMAP_CANONICAL_MISMATCH',{url:entry.url,canonical:obj.canonical});
    if(/noindex|none/i.test(xRobots+' '+m.metaRobots.join(' ')))critical('SITEMAP_NOINDEX',entry.url);
    if(!/^ru\b/i.test(m.lang))warning('MISSING_RU_LANG',entry.url);
   }catch(e){obj.error=clean(e.message).slice(0,220);critical('PAGE_UNAVAILABLE',{url:entry.url,error:obj.error})}
  }
  await page.close();
  const host=new URL(site.origin).host;
  for(const url of ['http://'+host+'/','https://www.'+host+'/','http://www.'+host+'/',site.origin+'/index.html']){
   const a=await fetch(url);const value={input:url,status:a.status,final:a.final};out.aliases.push(value);
   if(a.status!==200)warning('HOST_ALIAS_UNVERIFIED',value);
   else if(url!==site.origin+'/index.html'&&a.final!==site.origin+'/')warning('HOST_ALIAS_NOT_CANONICAL_REDIRECT',value);
   else if(url===site.origin+'/index.html'&&a.final===url)warning('INDEX_HTML_DUPLICATE_STATUS_200',value);
  }
  out.summary={sitemap:entries.length,http200:out.pages.filter(x=>x.http===200).length,
   eligible:out.pages.filter(x=>x.http===200&&x.allowedByRobots&&x.canonical===x.url).length,
   critical:out.critical.length,warnings:out.warnings.length};
  console.log('YANDEX_WEBMASTER_PUBLIC',JSON.stringify({site:site.origin,...out.summary,robots:out.robots,aliases:out.aliases,critical:out.critical,warnings:out.warnings.slice(0,14)}));
 }
 }finally{await api.dispose();await browser.close()}
 await fs.writeFile('oleg-yandex-webmaster-public.json',JSON.stringify(result,null,2));
 if(result.sites.some(x=>x.critical.length))process.exitCode=2;
}
if(require.main===module)main().catch(e=>{console.error('YANDEX_PRECHECK_FATAL',e.message);process.exitCode=1});
module.exports={parseRobots,permitted,locs,sitemapEntries};
