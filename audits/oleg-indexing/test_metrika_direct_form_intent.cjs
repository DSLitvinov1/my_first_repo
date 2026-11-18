'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const script = fs.readFileSync(path.join(__dirname, 'oleg-metrika-goals-v1.js'), 'utf8');
function run({host='potrebpravo.ru', href, consent=true, pageQuery=''}={}) {
  const calls=[]; const listeners={};
  const byHost={'potrebpravo.ru':'crm_form_fhi3n','semya-yurist.ru':'crm_form_ep5fd'};
  const win={__olegAnalyticsStarted:true,ym:(...a)=>calls.push(a),setTimeout:f=>f()};
  const document={addEventListener:(event,fn)=>{listeners[event]=fn;}};
  const ctx={window:win,document,URL,URLSearchParams,location:{hostname:host,href:'https://'+host+'/'+pageQuery,search:pageQuery},
    localStorage:{getItem:()=>JSON.stringify({value:consent?'yes':'no'})},Date,
    setTimeout:f=>f()};
  vm.runInNewContext(script,ctx,{timeout:1000});
  const a={href:href, getAttribute:(k)=>k==='href'?href:null};
  const target={closest:(s)=>s==='a[href]'?a:null};
  if (listeners.click) listeners.click({target});
  return {calls,byHost,formHref:a.href};
}
test('consumer own Bitrix form link produces intent goal with correct counter',()=>{
  const x=run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'});
  assert.deepEqual(x.calls,[[114249897,'reachGoal','oleg_crm_form_open']]);
});
test('family own Bitrix form link produces same goal in separate family counter',()=>{
  const x=run({host:'semya-yurist.ru',href:'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/?utm_source=test'});
  assert.deepEqual(x.calls,[[114251443,'reachGoal','oleg_crm_form_open']]);
});
test('wrong legal site form never counts as a valid lead intent',()=>{
  assert.equal(run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/'}).calls.length,0);
  assert.equal(run({host:'semya-yurist.ru',href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'}).calls.length,0);
});
test('malicious host and lookalike paths do not count',()=>{
  for(const href of ['https://b24-s2dosa.bitrix24site.ru.evil.example/crm_form_fhi3n/',
    'http://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',
    'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/more',
    'javascript:alert(1)']) {
    assert.equal(run({href}).calls.length,0,href);
  }
});
test('consent refusal prevents goal emission',()=>{
  assert.equal(run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',consent:false}).calls.length,0);
});
test('phone contact still tracked with same consent restrictions',()=>{
  assert.deepEqual(run({href:'tel:+79172052125'}).calls,[[114249897,'reachGoal','oleg_phone_click']]);
});
test('no synthetic lead-success conversion is emitted from user clicks',()=>{
  const x=run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'});
  assert.ok(x.calls.every(c=>c[2]!=='oleg_lead_success'&&c[2]!=='oleg_lead_submit_attempt'));
});
test('script is safe on an unrelated hostname',()=>{
  assert.equal(run({host:'example.com',href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'}).calls.length,0);
});
test('direct CRM form link carries only allowlisted campaign values to Bitrix24',()=>{
  const x=run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',pageQuery:'?utm_source=yandex&utm_medium=organic&utm_campaign=moscow%20family&utm_term=%D0%B2%D0%BE%D0%B7%D0%B2%D1%80%D0%B0%D1%82&email=secret%40example.org&token=bad'});
  const u=new URL(x.formHref);
  assert.equal(u.hostname,'b24-s2dosa.bitrix24site.ru');
  assert.equal(u.searchParams.get('utm_source'),'yandex');
  assert.equal(u.searchParams.get('utm_medium'),'organic');
  assert.equal(u.searchParams.get('utm_campaign'),'moscow family');
  assert.equal(u.searchParams.get('utm_term'),'возврат');
  assert.equal(u.searchParams.has('email'),false);
  assert.equal(u.searchParams.has('token'),false);
});
test('invalid marketing values are not forwarded to CRM',()=>{
  const x=run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',pageQuery:'?utm_source=a%40secret&'+'utm_campaign='+'a'.repeat(181)});
  const u=new URL(x.formHref);
  assert.equal(u.searchParams.has('utm_source'),false);
  assert.equal(u.searchParams.has('utm_campaign'),false);
});
test('external and lookalike links never receive UTM values',()=>{
  for(const href of ['https://b24-s2dosa.bitrix24site.ru.evil.example/crm_form_fhi3n/',
     'https://b24-s2dosa.bitrix24site.ru/crm_form_wrong/',
     'https://example.com/']) {
    const x=run({href,pageQuery:'?utm_source=yandex'});
    assert.equal(x.formHref,href);
  }
});
test('passing UTMs works even when analytics consent is refused; still emits no goal',()=>{
  const x=run({href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/',pageQuery:'?utm_source=yandex',consent:false});
  assert.equal(x.calls.length,0);
  assert.equal(new URL(x.formHref).searchParams.get('utm_source'),'yandex');
});
test('family-law direct URL preserves its own form path and campaign',()=>{
  const x=run({host:'semya-yurist.ru',href:'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/',pageQuery:'?utm_source=google&utm_medium=organic'});
  const u=new URL(x.formHref);
  assert.equal(u.pathname,'/crm_form_ep5fd/');
  assert.equal(u.searchParams.get('utm_source'),'google');
  assert.deepEqual(x.calls,[[114251443,'reachGoal','oleg_crm_form_open']]);
});
