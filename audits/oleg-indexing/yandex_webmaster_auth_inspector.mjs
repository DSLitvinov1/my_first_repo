import {chromium} from 'playwright';
import os from 'node:os';
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const HOSTS=['potrebpravo.ru','semya-yurist.ru'];
const SECTIONS={sitemap:'indexing/sitemap/',reindex:'indexing/reindex/',searchable:'indexing/searchable/'};
const PROFILE=path.join(os.homedir(),'.oleg-seo-playwright-profile');

export function webmasterUrl(host,section){
 if(!HOSTS.includes(host)||!Object.hasOwn(SECTIONS,section))throw Error('Not an approved property/section');
 return 'https://webmaster.yandex.ru/site/https:'+host+':443/'+SECTIONS[section];
}
export function matchesProperty(url,host,section){
 try{
  const u=new URL(url);
  return u.protocol==='https:'&&u.hostname==='webmaster.yandex.ru'&&
   u.pathname.replace(/\/+$/,'/')===new URL(webmasterUrl(host,section)).pathname;
 }catch{return false}
}
export function statusRows(rows,host){
 if(!HOSTS.includes(host))throw Error('Wrong host');
 const short=String(host).toLowerCase();
 return rows.map(x=>String(x||'').replace(/\s+/g,' ').trim().slice(0,500))
  .filter(x=>x&&(
     x.toLowerCase().includes(short)||/в очереди|ошибк|готово|обработ|отправлен|удален|исключен|отклонен|(^|\s)ok($|\s)|redirect/i.test(x)
  )).slice(0,250);
}
async function inspectPage(page,host,section){
 const url=webmasterUrl(host,section);
 const result={site:host,section,target:url,status:'unconfirmed'};
 await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
 if(!matchesProperty(page.url(),host,section)){
  result.status='property-or-login-not-available';
  result.final=new URL(page.url()).origin+new URL(page.url()).pathname;
  return result;
 }
 const body=await page.locator('body').innerText({timeout:15000});
 if(!body.includes(host)||/подтвердите права|нет доступа|нет прав|доступ запрещён/i.test(body)){
  result.status='ownership-not-confirmed';return result;
 }
 result.status='read-only-inspected';
 result.title=await page.title();
 result.headings=(await page.locator('h1,h2').allTextContents()).map(x=>x.replace(/\s+/g,' ').trim()).filter(Boolean).slice(0,12);
 const rows=await page.locator('tr').allTextContents();
 result.rows=statusRows(rows,host);
 // Only limited structured status excerpts from the selected property; no full browser storage or cookies.
 result.statusText=(body.match(/(?:В очереди|Ошибка|Обработано|Не проиндексирован|Страниц в поиске|Исключен[аоы]?|OK)/gi)||[]).slice(0,150);
 result.urlRowCount=result.rows.filter(x=>x.includes(host)).length;
 return result;
}
async function main(){
 const login=process.argv.includes('--login'),inspect=process.argv.includes('--inspect');
 if(login===inspect)throw Error('Choose exactly one of --login or --inspect');
 await fs.mkdir(PROFILE,{recursive:true,mode:0o700});
 const context=await chromium.launchPersistentContext(PROFILE,{
  headless:false,ignoreHTTPSErrors:false,viewport:{width:1400,height:950},
  args:['--no-first-run']
 });
 try{
  if(login){
   const page=await context.newPage();
   await page.goto('https://webmaster.yandex.ru/sites/',{waitUntil:'domcontentloaded',timeout:30000});
   const readline=await import('node:readline/promises');
   const rl=readline.createInterface({input:process.stdin,output:process.stdout});
   try{await rl.question('Войдите в Яндекс Вебмастер в окне Playwright; нажмите Enter в терминале после входа. ');}
   finally{rl.close()}
   console.log('Авторизация сохранена локально, не в GitHub.');
  }else{
   const output={date:new Date().toISOString(),scope:'authenticated local read-only Webmaster status',sites:[]};
   const page=await context.newPage();
   for(const host of HOSTS){
    const result={site:host,sections:[]};
    output.sites.push(result);
    for(const section of Object.keys(SECTIONS)){
     try{result.sections.push(await inspectPage(page,host,section));}
     catch(e){result.sections.push({section,status:'inspection-error',error:String(e.message).slice(0,250)})}
    }
   }
   await page.close();
   const destination=path.resolve('oleg-yandex-webmaster-auth-report.json');
   await fs.writeFile(destination,JSON.stringify(output,null,2),{mode:0o600});
   console.log('Read-only Webmaster report saved:',destination);
   for(const site of output.sites){
    console.log(site.site,site.sections.map(s=>({section:s.section,status:s.status,urlRows:s.urlRowCount})));
   }
   if(output.sites.some(s=>s.sections.some(x=>x.status!=='read-only-inspected')))process.exitCode=2;
  }
 }finally{await context.close()}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 main().catch(e=>{console.error('YANDEX_AUTH_INSPECT_FAILED:',String(e.message));process.exitCode=1});
}
