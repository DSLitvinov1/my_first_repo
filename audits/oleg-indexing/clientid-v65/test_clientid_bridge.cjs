'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const src = fs.readFileSync(path.join(__dirname, '..', 'live-rebased/potrebpravo.ru/public_html/assets/oleg-clientid-bridge-v1.js'), 'utf8');
const original = fs.readFileSync(path.join(__dirname, '..', 'live-rebased/semya-yurist.ru/public_html/assets/oleg-clientid-bridge-v1.js'), 'utf8');
assert.equal(src, original, 'site bridge source must be identical across sites');

function boot(host, consent, options={}) {
 const listeners={}; let callback=null, calls=0, metricCounter=null;
 const store=new Map();
 if(consent!==undefined) store.set('oleg.analytics.choice.v2', JSON.stringify({value:consent,at:options.consentAt??Date.now()}));
 if(options.oldConsent) store.set('oleg.analytics.choice.v1', JSON.stringify({value:'yes',at:Date.now()}));
 const schedule=[];
 const environment={
  location:{hostname:host,href:'https://'+host+'/',search:'',origin:'https://'+host},
  localStorage:{getItem:k=>store.has(k)?store.get(k):null},
  document:{addEventListener:(type,fn,capture)=>{(listeners[type]??=[]).push({fn,capture})}},
  window:{__olegAnalyticsStarted:options.started!==false,
    ym:(counter,command,cb)=>{calls++;metricCounter=counter;assert.equal(command,'getClientID');callback=cb}},
  setTimeout:(fn)=>schedule.push(fn),URL,Date,JSON,Object,RegExp,
 };
 vm.createContext(environment);vm.runInContext(src,environment);
 const b=environment.window.__olegClientIdBridgeV1;
 return {
  b,store,listeners,schedule,
  get calls(){return calls},get counter(){return metricCounter},
  callback:v=>callback?.(v),
  link:href=>b?b.augment(href):null,
  click:(anchor=true)=>{const node=anchor?{href:'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'}:null;
   const event={target:{closest:query=>query==='a[href]'?node:null}};
   for(const x of listeners.click||[])x.fn(event);return node?.href;
  },
  accept:()=>{store.set('oleg.analytics.choice.v2',JSON.stringify({value:'yes',at:Date.now()}));for(const x of listeners.click||[])x.fn({target:{closest:s=>s.includes('[data-allow]')?{}:null}});while(schedule.length)schedule.shift()()},
  deny:()=>{store.set('oleg.analytics.choice.v2',JSON.stringify({value:'no',at:Date.now()}));for(const x of listeners.click||[])x.fn({target:{closest:s=>s.includes('[data-deny]')?{}:null}})},
 };
}
const own='https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/';
const other='https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/';
const id='1700654321987654321';
function check(){
 let x=boot('potrebpravo.ru','yes');
 assert.equal(x.calls,1);assert.equal(x.counter,114249897);
 assert.equal(new URL(x.link(own)).searchParams.has('metrica_client_id'),false,'no ID before async callback');
 x.callback(id);
 assert.equal(new URL(x.link(own)).searchParams.get('metrica_client_id'),id);
 assert.equal(x.link(other),other,'no cross-form ID leakage');
 assert.equal(x.link('https://www.example.com/'), 'https://www.example.com/','no external leakage');
 assert.equal(x.link('http://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/'),'http://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/','must be HTTPS');
 assert.equal(x.link('https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n.evil/'),'https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n.evil/','exact path only');
 assert.equal(x.link('https://evil.test:443/crm_form_fhi3n/'),'https://evil.test:443/crm_form_fhi3n/');
 assert.equal(x.link('https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/?metrica_client_id=12345678'),own+'?metrica_client_id='+id,'replace forged ID');
 assert.equal(x.click().includes('metrica_client_id='+id),true,'direct-link click interception');
 x.deny();
 assert.equal(new URL(x.link(own)).searchParams.has('metrica_client_id'),false,'revocation removes field');
 x.callback(id);
 assert.equal(new URL(x.link(own)).searchParams.has('metrica_client_id'),false,'late callback after revocation ignored');
 let y=boot('semya-yurist.ru','yes');
 assert.equal(y.counter,114251443);y.callback(id);
 assert.equal(new URL(y.link(other)).searchParams.get('metrica_client_id'),id);
 assert.equal(y.link(own),own,'no consumer leakage from family');
 for(const state of ['no',undefined]) {
  let z=boot('potrebpravo.ru',state,{oldConsent:true});
  assert.equal(z.calls,0,'new consent required even if old v1 saved');
  assert.equal(new URL(z.link(own)).searchParams.has('metrica_client_id'),false);
 }
 let z=boot('potrebpravo.ru','yes',{started:false});
 assert.equal(z.calls,0,'must not request without actually loaded analytics');
 let l=boot('potrebpravo.ru','yes',{consentAt:Date.now()-367*86400000});
 assert.equal(l.calls,0,'old consent expires');
 let i=boot('potrebpravo.ru','yes');i.callback('javascript:alert(1)');
 assert.equal(new URL(i.link(own)).searchParams.has('metrica_client_id'),false,'reject untrusted IDs');
 let a=boot('potrebpravo.ru','no',{started:true});assert.equal(a.calls,0);a.accept();assert.equal(a.calls,1);a.callback(id);
 assert.equal(new URL(a.link(own)).searchParams.get('metrica_client_id'),id,'new opt-in activates');
 let u=boot('evil.test','yes');assert.equal(u.b,undefined,'unknown host blocked');
 console.log('CLIENTID_BRIDGE_UNIT_PASS: 24 assertions / two domains / consent / async / forgery / isolation');
}
check();