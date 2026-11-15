'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {parseRobots,permitted,locs,sitemapEntries}=require('./yandex_webmaster_preflight.cjs');
test('Yandex robot rule priority beats generic star rules',()=>{
 const rules=parseRobots('User-agent: *\nDisallow: /private/\nDisallow: /secret/\nAllow: /secret/public/\nSitemap: https://potrebpravo.ru/sitemap.xml\nUser-agent: Yandex\nDisallow: /tmp/\nAllow: /tmp/ok/\n');
 assert.equal(rules.sitemaps[0],'https://potrebpravo.ru/sitemap.xml');
 assert.equal(permitted(rules,'/tmp/x.html').allowed,false);
 assert.equal(permitted(rules,'/tmp/ok/post.html').allowed,true);
 assert.equal(permitted(rules,'/secret/no.html').allowed,true);
 assert.equal(permitted(rules,'/').allowed,true);
});
test('Fallback to generic robots rules where no Yandex group exists',()=>{
 const rules=parseRobots('User-agent: *\nDisallow: /private/\nAllow: /private/public/\n');
 assert.equal(permitted(rules,'/private/file').allowed,false);
 assert.equal(permitted(rules,'/private/public/file').allowed,true);
 assert.equal(permitted(rules,'/public').allowed,true);
});
test('Parse sitemap with URLs, lastmod and escaped query',()=>{
 const x='<?xml version="1.0"?><urlset><url><loc>https://potrebpravo.ru/</loc><lastmod>2026-11-14</lastmod></url><url><loc>https://potrebpravo.ru/practice/?a=1&amp;b=2</loc></url></urlset>';
 assert.deepEqual(locs(x),['https://potrebpravo.ru/','https://potrebpravo.ru/practice/?a=1&b=2']);
 assert.deepEqual(sitemapEntries(x),[
  {url:'https://potrebpravo.ru/',lastmod:'2026-11-14'},
  {url:'https://potrebpravo.ru/practice/?a=1&b=2',lastmod:null}
 ]);
});
test('Robots no rule and empty Sitemap are not accidental block',()=>{
 const rules=parseRobots('');
 assert.equal(permitted(rules,'/').allowed,true);
 assert.equal(locs('').length,0);
});
