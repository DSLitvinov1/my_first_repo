'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { COUNTERS, GOAL, verifiedAck, createTracker } = require('./lead-confirmation-guard');
function example(hostname='potrebpravo.ru', requestId='safe-req-100') {
  return { httpOk: true, hostname, requestId, body: { request_id: requestId, source_host:hostname, crm: { provider:'bitrix24',status:'confirmed',readback_confirmed:true,owner_confirmed:true,source_confirmed:true,utm_confirmed:true,dedupe_confirmed:true,notification_confirmed:true,entity_type:'deal',entity_id:9981 }, message:'Accepted' }};
}
test('both verified hosts map to correct counter', () => {
  assert.equal(COUNTERS['potrebpravo.ru'],114249897);
  assert.equal(COUNTERS['semya-yurist.ru'],114251443);
  assert.equal(GOAL,'crm_lead_accepted');
  assert.equal(verifiedAck(example()).crmId,'9981');
  assert.equal(verifiedAck(example('semya-yurist.ru')).hostname,'semya-yurist.ru');
});
test('HTTP 200 without actual CRM readback is not verified', () => {
  assert.equal(verifiedAck({httpOk:true,hostname:'potrebpravo.ru',requestId:'r',body:{message:'Success'}}),null);
  for (const changes of [{status:'queued'},{readback_confirmed:false},{entity_id:null},{provider:'unknown'},{entity_type:'contact'}]) {
    const source=example(); Object.assign(source.body.crm,changes);
    assert.equal(verifiedAck(source),null);
  }
});
test('fail-closed on bad HTTP status, wrong domain, wrong request identifier', () => {
  const cases=[
    {...example(),httpOk:false},
    {...example(),hostname:'other.ru'},
    {...example(),requestId:'mismatch'},
    {...example(),body:[1,2]},
    {...example(),body:null},
    {...example(),requestId:'name@example.org'},
  ];
  for(const val of cases) assert.equal(verifiedAck(val),null);
});
test('reject unsafe CRM ids and malformed types', () => {
  for(const id of [0,-1,'0','-3','1;alert(1)','001','999999999999999999999',{},null]){
    const val=example();val.body.crm.entity_id=id;
    assert.equal(verifiedAck(val),null,'invalid '+String(id));
  }
  const valid=example(); valid.body.crm.entity_type='lead';valid.body.crm.entity_id='4';
  assert.equal(verifiedAck(valid).crmId,'4');
});
test('explicit consent and ready counter are mandatory', () => {
  const ack=verifiedAck(example()); const actions=[];
  let consent=false,ready=true;
  const tracker=createTracker({consentGranted:()=>consent,metrikaReady:()=>ready,sendMetrika:(...a)=>actions.push(a)});
  assert.equal(tracker.record(ack),false);
  consent=true;ready=false;assert.equal(tracker.record(ack),false);
  assert.equal(actions.length,0);
  ready=true;assert.equal(tracker.record(ack),true);
  assert.deepEqual(actions,[[114249897,'crm_lead_accepted']]);
});
test('duplicate conversion is ignored, different CRM record can be counted', () => {
  const calls=[];
  const tracker=createTracker({consentGranted:()=>true,metrikaReady:()=>true,sendMetrika:(...args)=>calls.push(args)});
  const ack=verifiedAck(example());
  assert.equal(tracker.record(ack),true);
  assert.equal(tracker.record(ack),false);
  assert.equal(calls.length,1);
  const second=example();second.body.crm.entity_id=9982;
  assert.equal(tracker.record(verifiedAck(second)),true);
  assert.equal(calls.length,2);
});
test('no sending of name phone ID or other PII in Metrika call', () => {
  const calls=[];
  const tracker=createTracker({consentGranted:()=>true,metrikaReady:()=>true,sendMetrika:(...args)=>calls.push(args)});
  assert.ok(tracker.record(verifiedAck(example())));
  assert.deepEqual(calls,[ [114249897, 'crm_lead_accepted'] ]);
  assert.ok(!JSON.stringify(calls).includes('9981'));
});
test('emit failures do not lock a conversion as sent', () => {
  let fail=true;const calls=[];
  const tracker=createTracker({consentGranted:()=>true,metrikaReady:()=>true,sendMetrika:(...args)=>{if(fail)throw new Error('offline'); calls.push(args)}});
  const ack=verifiedAck(example());
  assert.throws(()=>tracker.record(ack),/offline/);
  fail=false;assert.equal(tracker.record(ack),true);
  assert.equal(calls.length,1);
});
test('invalid tracker dependencies rejected and invalid acknowledgement never tracked', () => {
  assert.throws(()=>createTracker({}),TypeError);
  let count=0;
  const tracker=createTracker({consentGranted:()=>true,metrikaReady:()=>true,sendMetrika:()=>count++});
  assert.equal(tracker.record(null),false);
  assert.equal(tracker.record({hostname:'potrebpravo.ru',requestId:'x',crmType:'lead',crmId:'!'}),false);
  assert.equal(count,0);
});
test('synthetic acknowledgement object cannot trigger analytics', () => {
  const sends=[];const tracker=createTracker({consentGranted:()=>true,metrikaReady:()=>true,sendMetrika:(...args)=>sends.push(args)});
  assert.equal(tracker.record({requestId:'fake',hostname:'potrebpravo.ru',crmType:'deal',crmId:'99'}),false);
  assert.equal(sends.length,0);
});

test('a positive HTTP and CRM ID do NOT count without independently proven owner/source/UTM/dedupe/notification', () => {
  const flags=['owner_confirmed','source_confirmed','utm_confirmed','dedupe_confirmed','notification_confirmed'];
  for (const flag of flags) {
    const payload=example();delete payload.body.crm[flag];
    assert.equal(verifiedAck(payload),null,'missing '+flag);
    payload.body.crm[flag]='true';
    assert.equal(verifiedAck(payload),null,'string flag '+flag);
    payload.body.crm[flag]=false;
    assert.equal(verifiedAck(payload),null,'false '+flag);
  }
});
