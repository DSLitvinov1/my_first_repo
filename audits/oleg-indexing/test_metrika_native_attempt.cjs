'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'oleg-metrika-goals-v1.js'),'utf8');
function mount(hostname, granted) {
  const handlers={};const emitted=[];let consent=granted;
  let time=10000;
  const doc={addEventListener:(event,fn)=>{handlers[event]=fn}};
  const win={__olegAnalyticsStarted:true,ym:(...args)=>emitted.push(args)};
  const context={
    window:win,document:doc,location:{hostname},
    localStorage:{getItem:()=>JSON.stringify({value:consent?'yes':'no'})},
    Date:{now:()=>time}
  };
  vm.runInNewContext(source,context,{timeout:500});
  return {handlers,emitted,win,setConsent:x=>{consent=x},tick:()=>{time+=2500}};
}
test('native submit attempt requires consent and correct form ID',()=>{
 const client=mount('potrebpravo.ru',false);
 const form={tagName:'FORM',id:'lead-form'};
 client.handlers.submit({target:form});
 assert.equal(client.emitted.length,0);
 client.setConsent(true);
 client.handlers.submit({target:form});
 assert.equal(client.emitted.length,1);
 assert.deepEqual(client.emitted[0],[114249897,'reachGoal','oleg_lead_submit_attempt']);
});
test('reject unrelated forms, cross-origin iframe and clicks as submissions',()=>{
 const c=mount('potrebpravo.ru',true);
 for(const target of [{tagName:'FORM',id:'other'}, {tagName:'IFRAME',id:'lead-form'},
                      {tagName:'BUTTON',id:'lead-form'},null,undefined])
  c.handlers.submit({target});
 assert.equal(c.emitted.length,0);
});
test('duplicate event binding does not double count and short repeated submits are suppressed',()=>{
 const c=mount('semya-yurist.ru',true);const evt={target:{tagName:'FORM',id:'lead-form'}};
 c.handlers.submit(evt);c.handlers.submit(evt);
 assert.equal(c.emitted.length,1);
 assert.deepEqual(c.emitted[0],[114251443,'reachGoal','oleg_lead_submit_attempt']);
 c.tick();c.handlers.submit(evt);
 assert.equal(c.emitted.length,2);
});
test('rejected consent, unknown domain and uninitialized tracker emit nothing',()=>{
 const c=mount('potrebpravo.ru',true);
 c.setConsent(false);
 c.handlers.submit({target:{tagName:'FORM',id:'lead-form'}});
 assert.equal(c.emitted.length,0);
 const other=mount('untrusted.ru',true);
 assert.equal(other.handlers.submit,undefined);
 const off=mount('semya-yurist.ru',true);
 off.win.__olegAnalyticsStarted=false;
 off.handlers.submit({target:{tagName:'FORM',id:'lead-form'}});
 assert.equal(off.emitted.length,0);
});
test('never send PII or CRM ID via Metrika; attempt is not success',()=>{
 const c=mount('semya-yurist.ru',true);
 c.handlers.submit({target:{tagName:'FORM',id:'lead-form',name:'Private Citizen',phone:'+7-999',value:'divorce'}});
 assert.deepEqual(c.emitted[0],[114251443,'reachGoal','oleg_lead_submit_attempt']);
 assert.equal(JSON.stringify(c.emitted).includes('crm_lead_accepted'),false);
 assert.equal(JSON.stringify(c.emitted).includes('Private Citizen'),false);
});
