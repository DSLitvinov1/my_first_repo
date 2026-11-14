import { test } from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {isPropertyUrl,submitOne,SITES} from './sitemap_operator.mjs';

test('Exact Search Console and Webmaster property URL binding',()=>{
  assert.equal(isPropertyUrl(
    'https://webmaster.yandex.ru/site/https:potrebpravo.ru:443/indexing/sitemap/',
    'potrebpravo.ru','yandex'),true);
  assert.equal(isPropertyUrl(
    'https://webmaster.yandex.ru/site/https:unrelated.ru:443/indexing/sitemap/',
    'potrebpravo.ru','yandex'),false);
  assert.equal(isPropertyUrl(
    'https://search.google.com/search-console/sitemaps?resource_id=https%3A%2F%2Fsemya-yurist.ru%2F',
    'semya-yurist.ru','google'),true);
  assert.equal(isPropertyUrl(
    'https://evil.test/search-console/sitemaps?resource_id=https%3A%2F%2Fsemya-yurist.ru%2F',
    'semya-yurist.ru','google'),false);
});

test('Playwright sitemap operator: dry-run, apply, idempotency and guards',async t=>{
  const browser=await chromium.launch({headless:true});
  t.after(async()=>browser.close());
  const page=await browser.newPage();
  t.after(async()=>page.close());
  const site=SITES[0];

  await page.setContent('<main><h1>potrebpravo.ru</h1><input placeholder="URL файла Sitemap"/><button id="add">Добавить</button><table><tbody id="rows"></tbody></table><span id="status"></span></main><script>window.sent=0;document.getElementById("add").addEventListener("click",()=>{window.sent++;document.getElementById("rows").innerHTML="<tr><td>https://potrebpravo.ru/sitemap.xml</td><td>Добавлено</td></tr>";document.getElementById("status").textContent="Успешно добавлено";});</script>');
  const before=await submitOne(page,site,'yandex',{apply:false,strictUrl:false});
  assert.equal(before.status,'ready-no-submit');
  assert.equal(await page.evaluate(()=>window.sent),0);
  const submitted=await submitOne(page,site,'yandex',{apply:true,strictUrl:false});
  assert.equal(submitted.status,'submitted-ui-confirmed');
  assert.equal(await page.evaluate(()=>window.sent),1);
  const repeated=await submitOne(page,site,'yandex',{apply:true,strictUrl:false});
  assert.equal(repeated.status,'already-listed');
  assert.equal(await page.evaluate(()=>window.sent),1);
  await assert.rejects(
    submitOne(page,site,'yandex',{apply:true,strictUrl:true}),
    /Wrong property URL/
  );

  await page.setContent('<h1>potrebpravo.ru</h1><p>Доступ запрещён</p><input type="url"><button>Добавить</button>');
  await assert.rejects(submitOne(page,site,'yandex',{apply:true,strictUrl:false}),/Property access/);

  await page.setContent('<h1>unrelated.ru</h1><input type="url"><button>Добавить</button>');
  await assert.rejects(submitOne(page,site,'yandex',{apply:true,strictUrl:false}),/selected website/);

  await page.setContent('<h1>potrebpravo.ru</h1><input type="text"><button>Добавить</button>');
  await assert.rejects(submitOne(page,site,'yandex',{apply:true,strictUrl:false}),/unique sitemap URL input/);

  await page.setContent('<h1>potrebpravo.ru</h1><input placeholder="Sitemap URL"><button>Submit</button><p>Nothing changed</p>');
  const failed = await submitOne(page,site,'google',{apply:true,strictUrl:false});
  assert.equal(failed.status,'unconfirmed');

  await page.setContent('<h1>potrebpravo.ru</h1><input placeholder="Sitemap URL"><button id="add">Submit</button><table><tbody id="rows"></tbody></table><script>window.sent=0;document.getElementById("add").addEventListener("click",()=>{window.sent++;document.getElementById("rows").innerHTML="<tr><td>sitemap.xml</td><td>Submitted</td></tr>";});</script>');
  const google=await submitOne(page,site,'google',{apply:true,strictUrl:false});
  assert.equal(google.status,'submitted-ui-confirmed');
  assert.equal(await page.evaluate(()=>window.sent),1);
});
