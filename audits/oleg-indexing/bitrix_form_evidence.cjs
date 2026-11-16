'use strict';
/** Oleg legal CRM UI diagnostic, never claims a saved Bitrix deal. */
const CONFIG=Object.freeze([
 Object.freeze({site:'https://potrebpravo.ru/',path:'/services/vozvrat-deneg.html',form:'crm_form_fhi3n'}),
 Object.freeze({site:'https://semya-yurist.ru/',path:'/services/razvod.html',form:'crm_form_ep5fd'})
]);
const captureHref=x=>{try{let u=new URL(x);return u.origin+u.pathname}catch{return String(x??'').replace(/\s+/g,' ').trim().slice(0,220)}};
const formUiVerified=(frameInfo,formUrl)=>
 frameInfo.http===200 &&
 frameInfo.final===captureHref(formUrl) &&
 Array.isArray(frameInfo.body?.forms) &&
 frameInfo.body.forms.some(f=>f.fields?.some(x=>x.type==='tel') && f.hasSubmit) &&
 frameInfo.body.hasConsent===true;
module.exports=Object.freeze({CONFIG,captureHref,formUiVerified});
