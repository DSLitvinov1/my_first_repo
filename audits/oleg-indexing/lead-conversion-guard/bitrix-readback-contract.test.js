'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {verifyAndBuildReceipt} = require('./bitrix-readback-contract');

function fixture(host='potrebpravo.ru') {
 const sourceId = host==='potrebpravo.ru'?'CONSUMER_APPROVED_SOURCE':'FAMILY_APPROVED_SOURCE';
 const submission={sourceHost:host, requestId:'test-crm-20261116-01',
   utm:{source:'yandex',medium:'organic',campaign:'',content:'',term:''}};
 const created={entityType:'deal',id:987};
 const record={id:'987',assignedById:'42',sourceId,sourceHost:host,
   requestId:submission.requestId,utm:{...submission.utm}};
 const opts={submission,created,expectedOwnerId:'42',
   sourceIdByHost:{'potrebpravo.ru':'CONSUMER_APPROVED_SOURCE','semya-yurist.ru':'FAMILY_APPROVED_SOURCE'},
   readEntity:async()=>record,
   lookupDuplicates:async()=>({count:1,entityId:'987'}),
   readNotification:async()=>({delivered:true,entityId:'987'})};
 return {opts,record};
}
test('verified readback + owner + source + UTM + unique CRM record + notification: each site',async()=>{
 for(const host of ['potrebpravo.ru','semya-yurist.ru']){
  const {opts}=fixture(host);
  const result=await verifyAndBuildReceipt(opts);
  assert.equal(result.request_id,opts.submission.requestId);
  assert.equal(result.source_host,host);
  assert.equal(result.crm.entity_id,'987');
  for(const field of ['readback_confirmed','owner_confirmed','source_confirmed',
                     'utm_confirmed','dedupe_confirmed','notification_confirmed'])
    assert.equal(result.crm[field],true);
  assert.equal(JSON.stringify(result).includes('yandex'),false);
  assert.equal(JSON.stringify(result).includes('42'),false);
  assert.ok(Object.isFrozen(result));
 }
});
test('Bitrix create HTTP response without actual readback never confirms',async()=>{
 const {opts}=fixture();
 opts.readEntity=async()=>null;
 assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('wrong owner or missing owner id are rejected',async()=>{
 const {opts,record}=fixture();
 record.assignedById='43';assert.equal(await verifyAndBuildReceipt(opts),null);
 record.assignedById='42';opts.expectedOwnerId=null;
 assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('different source or host: no cross-site attribution',async()=>{
 const {opts,record}=fixture();
 record.sourceId='FAMILY_APPROVED_SOURCE';assert.equal(await verifyAndBuildReceipt(opts),null);
 record.sourceId='CONSUMER_APPROVED_SOURCE';
 record.sourceHost='semya-yurist.ru';assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('both UTM value and missing-value mismatches are rejected',async()=>{
 const {opts,record}=fixture();
 record.utm.source='google';assert.equal(await verifyAndBuildReceipt(opts),null);
 record.utm.source='yandex';
 delete record.utm.medium;assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('zero, more than one, and wrong CRM ID cannot satisfy dedupe',async()=>{
 const {opts}=fixture();
 for(const bad of [{count:0,entityId:987},{count:2,entityId:987},
                    {count:1,entityId:999},{count:'1',entityId:987},null]){
  opts.lookupDuplicates=async()=>bad;
  assert.equal(await verifyAndBuildReceipt(opts),null);
 }
});
test('delivery notification must be verified independently',async()=>{
 const {opts}=fixture();
 for(const outcome of [null,{delivered:false,entityId:987},
  {delivered:true,entityId:42},{delivered:'yes',entityId:987}]){
   opts.readNotification=async()=>outcome;
   assert.equal(await verifyAndBuildReceipt(opts),null);
 }
});
test('reject invalid request ids, unsupported domains and CRM entity types',async()=>{
 const {opts}=fixture();
 for(const req of ['<script>','client@example.com','',null]){
  opts.submission.requestId=req;
  assert.equal(await verifyAndBuildReceipt(opts),null);
 }
 opts.submission.requestId='safe-crm-id';
 opts.submission.sourceHost='other.ru';
 assert.equal(await verifyAndBuildReceipt(opts),null);
 opts.submission.sourceHost='potrebpravo.ru';
 opts.created.entityType='contact';
 assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('no callbacks = fail closed; readback outage or revoked authorization = unknown',async()=>{
 const {opts}=fixture();
 opts.readEntity=undefined;
 assert.equal(await verifyAndBuildReceipt(opts),null);
 opts.readEntity=async()=>{throw Error('permission denied with secret value');};
 assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('CRM response ID must match independently fetched record ID',async()=>{
 const {opts,record}=fixture();
 record.id='988';
 assert.equal(await verifyAndBuildReceipt(opts),null);
});
test('no credential, name, phone or request UTM data in acknowledgement',async()=>{
 const {opts}=fixture();
 opts.submission.name='Secret Person';opts.submission.phone='+79999999999';
 const receipt=await verifyAndBuildReceipt(opts),serialized=JSON.stringify(receipt);
 assert.ok(receipt);
 for(const forbidden of ['Secret Person','+79999999999','yandex','organic'])
  assert.equal(serialized.includes(forbidden),false);
});
