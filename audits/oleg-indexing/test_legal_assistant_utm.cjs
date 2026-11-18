
'use strict';
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const code=fs.readFileSync(path.join(__dirname,'legal-assistant-v4-utm.js'),'utf8');
const start=code.indexOf('  const isFamily =');
const end=code.indexOf('  const topics =',start);
assert.ok(start>0&&end>start);
function result(host,query){return vm.runInNewContext(code.slice(start,end)+'\nformUrl',{location:{hostname:host,search:query},URL,URLSearchParams});}
test('consumer assistant iframe URL carries campaign',()=>{
 const url=new URL(result('potrebpravo.ru','?utm_source=yandex&utm_medium=organic'));
 assert.equal(url.pathname,'/crm_form_fhi3n/');assert.equal(url.searchParams.get('utm_source'),'yandex');
 assert.equal(url.searchParams.get('utm_medium'),'organic');
});
test('family assistant iframe URL retains correct form',()=>{
 const url=new URL(result('semya-yurist.ru','?utm_source=google&utm_campaign=moscow'));
 assert.equal(url.pathname,'/crm_form_ep5fd/');assert.equal(url.searchParams.get('utm_campaign'),'moscow');
});
test('assistant iframe never leaks arbitrary PII or tokens',()=>{
 const u=new URL(result('potrebpravo.ru','?utm_source=yandex&phone=123456&email=joe%40example.com&session_id=xxx'));
 assert.equal(u.searchParams.get('utm_source'),'yandex');
 for(const k of ['phone','email','session_id']) assert.equal(u.searchParams.has(k),false);
});
test('unsafe marketing field and too-long value omitted',()=>{
 const u=new URL(result('potrebpravo.ru','?utm_source=joe%40example.com&utm_term='+'x'.repeat(181)));
 assert.equal(u.searchParams.has('utm_source'),false);assert.equal(u.searchParams.has('utm_term'),false);
});
test('no UTM leaves existing form URL unchanged',()=>{
 assert.equal(result('semya-yurist.ru',''),'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/');
});