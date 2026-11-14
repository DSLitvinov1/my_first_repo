'use strict';
/* Public, owner-requested, read-only audit. No credentials, submissions or changes. */
const {chromium, request} = require('playwright');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');

const ORIGINS = ['https://potrebpravo.ru', 'https://semya-yurist.ru'];
const MAX_URLS_PER_SITE = 80;
const result = {time: new Date().toISOString(), mode: 'full_sitemap_chromium_readonly', sites: []};
const norm = x => String(x ?? '').replace(/\s+/g,' ').trim();
const xmlLocs = text => [...String(text).matchAll(/<(?:[A-Za-z]+:)?loc(?:\s[^>]*)?>\s*([^<]+)\s*<\/(?:[A-Za-z]+:)?loc>/gi)]
  .map(x => x[1].trim().replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;/g,"'"));
const stripHash = x => {const u = new URL(x);u.hash='';return u.href;};
const sameHost = (x,base) => {try {return new URL(x).origin === base;} catch {return false;}};
const isPageLink = x => !/\.(?:pdf|png|svg|jpe?g|webp|gif|css|js|xml|txt|zip|woff2?|ico|mp4)(?:$|\?)/i.test(new URL(x).pathname);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

function robotsRootRestrictions(body){
  const groups=[];let agents=[],rules=[],rulesStarted=false;
  const flush=()=>{if(agents.length)groups.push({agents:[...agents],rules:[...rules]});agents=[];rules=[];rulesStarted=false;};
  for(const raw of String(body).split(/\r?\n/)){
    const line=raw.split('#')[0].trim();
    if(!line)continue;
    const match=line.match(/^([\w-]+)\s*:\s*(.*)$/);
    if(!match)continue;
    const type=match[1].toLowerCase(),val=match[2].trim();
    if(type==='user-agent'){
      if(rulesStarted)flush();
      agents.push(val.toLowerCase());
    }else if(type==='disallow'||type==='allow'){
      if(!agents.length)continue;
      rulesStarted=true;
      rules.push([type,val]);
    }
  }
  flush();
  return ['*','googlebot','yandex'].filter(agent =>
    groups.some(g=>g.agents.includes(agent)&&g.rules.some(([kind,path])=>kind==='disallow'&&path==='/')&&
      !g.rules.some(([kind,path])=>kind==='allow'&&path==='/')));
}

async function main(){
  const api=await request.newContext({timeout:18000,ignoreHTTPSErrors:false,userAgent:'OlegSEOIndexabilityAudit/1.1 (+public non-authenticated crawl)'});
  const browser=await chromium.launch({headless:true});
  try {
    for(const base of ORIGINS){
      const out={site:base,robots:{},sitemap:{},checks:[],pages:[],critical:[],warnings:[],summary:{}};
      result.sites.push(out);
      const critical=(code,detail)=>out.critical.push({code,detail});
      const warning=(code,detail)=>out.warnings.push({code,detail});
      async function fetch(url){
        try{
          const response=await api.get(url,{maxRedirects:5});
          return {status:response.status(),url:response.url(),body:await response.text(),headers:response.headers()};
        }catch(e){return {status:0,url,body:'',error:norm(e.message).slice(0,220)};}
      }
      const robots=await fetch(base+'/robots.txt');
      out.robots={status:robots.status,blocked_agents:robots.status===200?robotsRootRestrictions(robots.body):[],sitemap_lines:robots.body.split(/\r?\n/).filter(x=>/^\s*Sitemap\s*:/i.test(x))};
      if(robots.status!==200)critical('ROBOTS_UNAVAILABLE',robots.status+' '+(robots.error||''));
      if(out.robots.blocked_agents.length)critical('ROOT_DISALLOW',out.robots.blocked_agents.join(', '));
      const sitemap=await fetch(base+'/sitemap.xml');
      out.sitemap={status:sitemap.status,url:sitemap.url,xml:/(?:<urlset\b|<sitemapindex\b)/i.test(sitemap.body)};
      if(sitemap.status!==200||!out.sitemap.xml)critical('SITEMAP_UNAVAILABLE',sitemap.status+' / XML invalid');
      let rawLocs=sitemap.status===200?xmlLocs(sitemap.body):[];
      const sitemaps=rawLocs.filter(x=>/\.xml(?:\?|$)/i.test(x));
      for(const nested of sitemaps.slice(0,8)){
        if(!sameHost(nested,base)){critical('SITEMAP_EXTERNAL',nested);continue;}
        const r=await fetch(nested);
        if(r.status!==200)critical('NESTED_SITEMAP_UNAVAILABLE',nested+' '+r.status);
        else rawLocs.push(...xmlLocs(r.body));
      }
      rawLocs=rawLocs.filter(x=>! /\.xml(?:\?|$)/i.test(x));
      out.sitemap.entries=rawLocs.length;
      const map=new Map(),dup=[];
      for(const link of rawLocs){
        try{
          const url=new URL(link);
          if(url.protocol!=='https:'||url.origin!==base){critical('INVALID_SITEMAP_HOST',link);continue;}
          if(url.hash||url.search){warning('SITEMAP_HAS_QUERY_OR_FRAGMENT',link);}
          const normalized=stripHash(url.href);
          if(map.has(normalized))dup.push(normalized);
          map.set(normalized,true);
        }catch{critical('INVALID_SITEMAP_URL',link);}
      }
      out.sitemap.unique=map.size;
      if(dup.length)critical('DUPLICATE_SITEMAP_URLS',dup);
      if(!map.size)critical('EMPTY_SITEMAP','No usable page URLs');
      if(map.size>MAX_URLS_PER_SITE)critical('AUDIT_PAGE_CAP','Sitemap has '+map.size+' URLs; audit cap '+MAX_URLS_PER_SITE);
      if(!map.has(base+'/'))critical('HOME_NOT_IN_SITEMAP',base+'/');

      const page=await browser.newPage({javaScriptEnabled:false,ignoreHTTPSErrors:false});
      await page.route('**/*',route=>{
        const req=route.request();
        const kind=req.resourceType(), url=req.url();
        if(['image','media','font','stylesheet','script'].includes(kind)||!sameHost(url,base))return route.abort();
        return route.continue();
      });
      const inbound=new Map();
      const descriptions=new Map(),titles=new Map(),contents=new Map();
      const outgoing=new Set();
      for(const url of [...map.keys()].slice(0,MAX_URLS_PER_SITE)){
        const item={url};
        out.pages.push(item);
        try{
          const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:22000});
          item.status=response?.status()||0;item.final=page.url();
          item.xRobots=response?.headers()?.['x-robots-tag']||'';
          const metadata=await page.evaluate(()=>({
            title:document.title||'',
            description:document.querySelector('meta[name="description" i]')?.content||'',
            canonical:document.querySelector('link[rel~="canonical" i]')?.href||'',
            robots:[...document.querySelectorAll('meta[name="robots" i],meta[name="googlebot" i],meta[name="yandex" i]')].map(e=>e.content||''),
            h1s:[...document.querySelectorAll('h1')].map(e=>e.textContent?.trim()||''),
            lang:document.documentElement.lang||'',
            body:document.querySelector('main')?.innerText||document.body?.innerText||'',
            links:[...document.querySelectorAll('a[href]')].map(e=>e.href),
            ldjson:[...document.querySelectorAll('script[type="application/ld+json"]')].map(e=>e.textContent||'')
          }));
          item.title=norm(metadata.title); item.description=norm(metadata.description);
          item.canonical=metadata.canonical;item.robots=metadata.robots;item.h1count=metadata.h1s.length;
          item.lang=metadata.lang;item.wordCount=norm(metadata.body).split(/\s+/).filter(Boolean).length;
          item.internalLinkCount=0;
          if(item.status!==200)critical('BAD_STATUS',url+' '+item.status);
          if(item.final!==url)critical('SITEMAP_REDIRECT',url+' -> '+item.final);
          if(/(?:noindex|none)/i.test([item.xRobots,...item.robots].join(',')))critical('NOINDEX_SITEMAP',url);
          if(!item.canonical)critical('CANONICAL_MISSING',url);
          else if(item.canonical!==url)critical('CANONICAL_MISMATCH',url+' -> '+item.canonical);
          if(!item.title)critical('TITLE_MISSING',url);
          if(item.h1count!==1)warning('H1_COUNT',url+' '+item.h1count);
          if(!item.description)warning('DESCRIPTION_MISSING',url);
          if(item.wordCount<150)warning('THIN_CONTENT',url+' '+item.wordCount);
          if(item.title && item.title.length>65)warning('LONG_TITLE',url+' '+item.title.length);
          if(!/^ru\b/i.test(item.lang))warning('LANGUAGE_NOT_RU',url+' '+item.lang);
          for(const itemLd of metadata.ldjson){
            try{JSON.parse(itemLd);}catch{warning('INVALID_JSON_LD',url);}
          }
          for(const [key,field,mapx] of [['title',item.title,titles],['description',item.description,descriptions],['body',norm(metadata.body).slice(0,1800),contents]]){
            if(!field)continue;
            const val=key==='body'?sha(field):field;
            if(!mapx.has(val))mapx.set(val,[]);
            mapx.get(val).push(url);
          }
          for(const link of metadata.links){
            if(!sameHost(link,base))continue;
            const dest=stripHash(link);
            if(!isPageLink(dest))continue;
            item.internalLinkCount++;
            inbound.set(dest,(inbound.get(dest)||0)+1);
            if(!map.has(dest))outgoing.add(dest);
          }
        }catch(e){item.error=norm(e.message).slice(0,240);critical('PAGE_LOAD_FAILED',url+' '+item.error);}
      }
      for(const url of map.keys()) if(url!==base+'/'&&!(inbound.get(url)>0))warning('SITEMAP_NO_INBOUND_LINKS',url);
      for(const [type,collection] of [['DUPLICATE_TITLE',titles],['DUPLICATE_DESCRIPTION',descriptions],['DUPLICATE_CONTENT',contents]]){
        for(const group of collection.values())if(group.length>1)warning(type,group);
      }
      for(const url of [...outgoing].slice(0,40)){
        const response=await fetch(url);
        if(response.status>=400||response.status===0)critical('BROKEN_INTERNAL_LINK',url+' '+response.status);
      }
      out.summary={pagesInSitemap:map.size,checked:out.pages.length,healthy:out.pages.filter(p=>p.status===200&&!p.error).length,
        rootRobots:robots.status,sitemapStatus:sitemap.status,externalLinkedPagesTested:Math.min(40,outgoing.size),
        critical:out.critical.length,warnings:out.warnings.length};
      await page.close();
      console.log('SITE',base,JSON.stringify(out.summary));
      for(const x of out.critical)console.log('CRITICAL',x.code,JSON.stringify(x.detail));
      for(const x of out.warnings)console.log('WARNING',x.code,JSON.stringify(x.detail));
    }
  }finally{await browser.close();await api.dispose();}
  await fs.writeFile('oleg-indexability.json',JSON.stringify(result,null,2));
  console.log('RESULT_JSON_WRITTEN');
  if(result.sites.some(s=>s.critical.length))process.exitCode=2;
}
main().catch(e=>{console.error('AUDIT_FAILED',e);process.exitCode=1;});
