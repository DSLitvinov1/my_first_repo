'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {CONFIG,formUiVerified}=require('./bitrix_form_evidence.cjs');

const base='https://b24-s2dosa.bitrix24site.ru/';
const valid=(url)=>({
 http:200,final:url,
 body:{hasConsent:true,forms:[{
  hasSubmit:true,fields:[{type:'text'},{type:'tel'},{type:'checkbox'}]
 }]}
});
test('Oleg sites have distinct exact Bitrix form IDs, never cross-wire',()=>{
 assert.equal(CONFIG.length,2);
 assert.deepEqual(CONFIG.map(x=>x.site),['https://potrebpravo.ru/','https://semya-yurist.ru/']);
 assert.deepEqual(CONFIG.map(x=>x.form),['crm_form_fhi3n','crm_form_ep5fd']);
 for(const config of CONFIG){
  const correct=base+config.form+'/';
  const other=base+CONFIG.find(x=>x!==config).form+'/';
  assert.equal(formUiVerified(valid(correct),correct),true);
  assert.equal(formUiVerified(valid(other),correct),false);
 }
});
test('HTTP 200 is insufficient without actual form, required consent and phone',()=>{
 const url=base+'crm_form_fhi3n/';
 assert.equal(formUiVerified({http:200,final:url},url),false);
 assert.equal(formUiVerified({http:200,final:url,body:{forms:[],hasConsent:true}},url),false);
 assert.equal(formUiVerified({...valid(url),body:{...valid(url).body,hasConsent:false}},url),false);
 assert.equal(formUiVerified({...valid(url),body:{forms:[{hasSubmit:true,fields:[{type:'text'}]}],hasConsent:true}},url),false);
 assert.equal(formUiVerified({...valid(url),body:{forms:[{hasSubmit:false,fields:[{type:'tel'}]}],hasConsent:true}},url),false);
 assert.equal(formUiVerified({...valid(url),http:403},url),false);
});
