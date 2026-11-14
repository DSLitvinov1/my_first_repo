// Owner-initiated Playwright operator for the two Oleg sites.
// Does not read Chrome's private profile or export auth tokens. Uses a dedicated
// persistent Playwright profile that the owner must log into interactively.
// Nothing is submitted unless --apply is explicit.
import { chromium } from 'playwright';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import readline from 'node:readline/promises';

export const SITES = Object.freeze([
  { host: 'potrebpravo.ru', sitemap: 'https://potrebpravo.ru/sitemap.xml', count: 23 },
  { host: 'semya-yurist.ru', sitemap: 'https://semya-yurist.ru/sitemap.xml', count: 18 },
]);
export const webmasterPath = host => 'https://webmaster.yandex.ru/site/https:' + host + ':443/indexing/sitemap/';
export const googlePath = host =>
  'https://search.google.com/search-console/sitemaps?resource_id=' +
  encodeURIComponent('https://' + host + '/');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const norm = x => String(x ?? '').toLowerCase().replace(/\s+/g, ' ').trim();

export function isPropertyUrl(actualUrl, host, service) {
  try {
    const u = new URL(actualUrl);
    if (service === 'yandex')
      return u.hostname === 'webmaster.yandex.ru' &&
        u.pathname.includes('/site/https:' + host + ':443/') &&
        u.pathname.includes('/indexing/sitemap');
    if (service === 'google')
      return u.hostname === 'search.google.com' &&
        u.pathname.startsWith('/search-console/sitemaps') &&
        ['https://' + host + '/', 'sc-domain:' + host].includes(u.searchParams.get('resource_id'));
  } catch {}
  return false;
}

export async function inspectSitemap(page, site) {
  const got = await page.request.get(site.sitemap, {failOnStatusCode:false,timeout:20000});
  const body = await got.text();
  const locs = [...body.matchAll(/<loc(?:\s[^>]*)?>(.*?)<\/loc>/gsi)].map(x=>x[1].trim());
  const exact = locs.filter(s=>s.startsWith('https://' + site.host + '/'));
  if (!got.ok() || exact.length !== site.count || exact.length !== locs.length ||
      new Set(locs).size !== locs.length) {
    throw new Error('Live sitemap changed: '+site.host+' HTTP '+got.status()+' URLs '+locs.length+' expected '+site.count);
  }
  return { status:got.status(),urls:locs.length };
}

const errors = [
  /нет прав/i, /доступ запрещён/i, /нет доступа/i, /you don't have permission/i,
  /property not found/i, /подтвердите права/i
];
const accepted = /(^|[\s\n])(успешно|добавлен|отправлен|accepted|success|submitted|sitemap\.xml)([\s\n]|$)/i;

async function detectForm(page, service) {
  const candidates = service === 'yandex' ?
    [
      'input[placeholder*="sitemap" i]',
      'input[aria-label*="sitemap" i]',
      'input[type="url"]'
    ] :
    [
      'input[placeholder*="sitemap" i]',
      'input[aria-label*="sitemap" i]',
      'input[placeholder*="файл" i]'
    ];
  for (const selector of candidates) {
    const locator = page.locator(selector).filter({ visible: true });
    if (await locator.count() === 1) return locator;
  }
  // Refuse ambiguous inputs instead of entering anything into a search or admin form.
  throw new Error('Cannot identify one unique sitemap URL input');
}

async function detectButton(page, service) {
  const words = service === 'yandex' ? ['Добавить'] : ['Отправить', 'Submit'];
  for (const word of words) {
    const loc = page.getByRole('button',{name:word,exact:true});
    if(await loc.count()===1&&await loc.isVisible())return loc;
  }
  throw new Error('Cannot identify an unambiguous sitemap submission button');
}

export async function submitOne(page, site, service, {apply=false, strictUrl=true}={}) {
  if (strictUrl && !isPropertyUrl(page.url(),site.host,service))
    throw new Error('Wrong property URL. Refuse actions: '+page.url());
  const text = (await page.locator('body').innerText()).slice(0,24000);
  if (!text.includes(site.host)) throw new Error('Cannot verify selected website '+site.host);
  if (errors.some(rx=>rx.test(text))) throw new Error('Property access not confirmed for '+site.host);
  const tableText = norm(await page.locator('table').allTextContents().then(xs=>xs.join('\n')));
  if (tableText.includes(site.sitemap.toLowerCase()) ||
      tableText.includes('/sitemap.xml') && tableText.includes(site.host.toLowerCase())) {
    return {status:'already-listed',site:site.host,service};
  }
  const field = await detectForm(page,service);
  const button = await detectButton(page,service);
  if (!apply) return {status:'ready-no-submit',site:site.host,service};
  const value = service === 'yandex' ? site.sitemap : 'sitemap.xml';
  await field.fill(value);
  await button.click();
  await sleep(1500);
  const now = (await page.locator('body').innerText()).slice(0,24000);
  if (errors.some(rx=>rx.test(now)))
    return {status:'rejected',site:site.host,service,reason:'permission or property error'};
  if (!accepted.test(now))
    return {status:'unconfirmed',site:site.host,service,reason:'submit click occurred but acceptance not visible'};
  return {status:'submitted-ui-confirmed',site:site.host,service};
}

async function main() {
  const apply=process.argv.includes('--apply');
  const login=process.argv.includes('--login');
  const dir=path.join(os.homedir(), '.oleg-seo-playwright-profile');
  await fs.mkdir(dir,{recursive:true,mode:0o700});
  const context=await chromium.launchPersistentContext(dir,{
    headless:false,ignoreHTTPSErrors:false,viewport:{width:1440,height:980},
    args:['--no-first-run']
  });
  const report={time:new Date().toISOString(),mode:apply?'apply':'dry-run',results:[]};
  if(login){
    for(const url of ['https://webmaster.yandex.ru/sites/','https://search.google.com/search-console']){
      const tab=await context.newPage();
      await tab.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
    }
    const rl=readline.createInterface({input:process.stdin,output:process.stdout});
    try{await rl.question('Войдите в Яндекс и Google в открытых окнах, затем нажмите Enter здесь. ');}
    finally{rl.close();await context.close();}
    console.log('Локальная авторизация сохранена только в отдельном профиле на этом компьютере.');
    return;
  }
  try {
    for (const site of SITES) {
      const page=await context.newPage();
      try {
        const sitemap=await inspectSitemap(page,site);
        report.results.push({site:site.host,phase:'public-sitemap',...sitemap});
        for (const service of ['yandex','google']) {
          const url = service==='yandex'?webmasterPath(site.host):googlePath(site.host);
          await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
          if (!isPropertyUrl(page.url(),site.host,service)) {
            report.results.push({site:site.host,service,status:'login-or-property-missing',url:page.url()});
            continue;
          }
          try {
            report.results.push(await submitOne(page,site,service,{apply}));
          }catch(error){
            report.results.push({site:site.host,service,status:'not-submitted',reason:error.message});
          }
        }
      } catch(error) {
        report.results.push({site:site.host,status:'not-submitted',reason:error.message});
      } finally {await page.close();}
    }
  } finally {
    const reportPath=path.resolve('oleg-playwright-operator-report.json');
    await fs.writeFile(reportPath,JSON.stringify(report,null,2));
    await context.close();
    console.log('Local report: '+reportPath);
    for(const row of report.results)console.log(row);
    if (report.results.some(x=>x.status==='unconfirmed'||x.status==='rejected'))process.exitCode=2;
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(e=>{console.error('Operator failed:',e.message);process.exitCode=1;});
}
