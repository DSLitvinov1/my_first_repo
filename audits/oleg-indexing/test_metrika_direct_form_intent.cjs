'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const script = fs.readFileSync(path.join(__dirname, 'oleg-metrika-goals-v1.js'), 'utf8');
function run({host='potrebpravo.ru', href, consent=true}={}) {
  const calls=[]; const listeners={};
  const byHost={'potrebpravo.ru':'crm_form_fhi3n','semya-yurist.ru':'crm_form_ep5fd'};
  const win={__olegAnalyticsStarted:true,ym:(...a)=>calls.push(a),setTimeout:f=>f()};
  const document={addEventListener:(event,fn)=>{listeners[event]=fn;}};
  const ctx={window:win,document,URL,location:{hostname:host,href:'https://'+host+'/'},
    localStorage:{getItem:()=>JSON.stringify({value:consent?'yes':'no'})},Date,
    setTimeout:f=>f()};
  vm.runInNewContext(script,ctx,{timeout:1000});
  const a={href:href, getAttribute:(k)=>k==='href'?href:null};
  const target={closest:(s)=>s==='a[href]'?a:null};
  if (listeners.click) listeners.click({target});
  return {calls,byHost};
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