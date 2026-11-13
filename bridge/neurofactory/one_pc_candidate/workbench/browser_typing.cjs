"use strict";
/* Browser input-only keyboard. No passwords, card numbers or form submission.
   This module never submits, never extracts field values and never logs user text. */

const MAX_CHARS = 2000;
const MAX_BYTES = 8000;
const KEYS = new Set(["Tab","Escape","ArrowLeft","ArrowRight","ArrowUp","ArrowDown","Home","End","Backspace"]);
const SENSITIVE = /\b(password|passwd|passphrase|token|secret|otp|2fa|cvv|cvc|credit.?card|bank.?card|pin.?code|api.?key|one.?time.?code|sms.?code)\b|парол|пин.?код|код.?подтвержден|карта.?номер|номер.?карты|секретн|плат[её]жн.*карт|паспорт/iu;
const INPUT_TYPES = new Set(["text","search","email","tel","url","number"]);

function validateText(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_CHARS ||
      Buffer.byteLength(text,"utf8") > MAX_BYTES ||
      /[\u0000-\u0009\u000b-\u001f\u007f]/u.test(text)) {
    throw Error("BROWSER_TEXT_INVALID_OR_TOO_LONG");
  }
  return text;
}

function validateMode(mode) {
  if (mode !== "replace" && mode !== "append") throw Error("BROWSER_INPUT_MODE_REFUSED");
  return mode;
}

function validKey(key) {
  if (!KEYS.has(key)) throw Error("BROWSER_KEY_REFUSED");
  return key;
}

/* Runs only inside the ephemeral Chromium origin, not in the Work UI. */
async function inspectInputs(page) {
  return page.evaluate((max) => {
    // JSON-serializable and no field VALUES (CRM personal data must not leak).
    const blocks = document.querySelectorAll('input,textarea,[contenteditable="true"]');
    const output = [];
    for (const el of blocks) {
      const desc = describe(el);
      if (!desc) continue;
      const r=el.getBoundingClientRect();
      if (r.width<4 || r.height<4 || r.bottom<0 || r.right<0 ||
          r.top>=720 || r.left>=1100) continue;
      const x=Math.floor(Math.min(1099,Math.max(0,r.left+r.width/2)));
      const y=Math.floor(Math.min(719,Math.max(0,r.top+r.height/2)));
      if(document.elementFromPoint(x,y)!==el &&
         !el.contains(document.elementFromPoint(x,y))) continue;
      output.push({label:desc.label,kind:"field",editable:true,
                   multiline:desc.multiline,x,y});
      if(output.length>=max)break;
    }
    return output;

    function describe(el) {
      const tag=el.tagName.toLowerCase();
      if(el.closest('[inert],[hidden]') || el.disabled || el.readOnly ||
         el.getAttribute('aria-disabled')==='true')return null;
      const style=getComputedStyle(el);
      if(style.display==='none'||style.visibility!=='visible')return null;
      if(tag==='input' && !['text','search','email','tel','url'].includes(el.type))return null;
      if(tag!=='input' && tag!=='textarea' && el.getAttribute('contenteditable')!=='true')return null;
      const hint=[el.id,el.name,el.autocomplete,el.placeholder,
                  el.getAttribute('aria-label')].filter(Boolean).join(' ');
      const sensitive=/password|passwd|passphrase|secret|token|otp|2fa|cvv|cvc|card|pin.?code|api.?key|парол|пин.?код|код.?подтвержден|номер.?карты|паспорт/i;
      if(sensitive.test(hint))return null;
      const associated=el.id&&document.querySelector('label[for="'+CSS.escape(el.id)+'"]');
      const enclosed=el.closest('label');
      return {
        label:(el.getAttribute('aria-label')||associated?.textContent||
               enclosed?.textContent||el.placeholder||el.name||'Текстовое поле')
               .trim().replace(/\s+/g,' ').slice(0,70),
        multiline:tag!=='input'
      };
    }
  }, 25);
}

class KeyboardSession {
  constructor(page) {
    this.page = page;
    this.active = null;
  }
  invalidate() {
    const old=this.active;
    this.active=null;
    if(old)old.dispose().catch(()=>{});
  }

  async focus(x,y) {
    this.invalidate();
    const info=await this.page.evaluate(({x,y})=>{
      const target=document.elementFromPoint(x,y);
      if(!target)return null;
      const field=target.closest("input,textarea,[contenteditable]");
      if(!field || field !== document.elementFromPoint(x,y) &&
        !field.contains(document.elementFromPoint(x,y)))return null;
      // Prevent selecting non-editable, sensitive, hidden or password fields.
      const tag=field.tagName.toLowerCase();
      if(field.disabled || field.readOnly ||
         field.getAttribute('aria-disabled')==='true') return null;
      if(tag==='input' && !['text','search','email','tel','url'].includes(field.type))return null;
      if(tag!=='input' && tag!=='textarea' && field.getAttribute('contenteditable')!=='true')return null;
      const hint=[field.id,field.name,field.autocomplete,field.placeholder,
                  field.getAttribute('aria-label')].filter(Boolean).join(' ');
      if(/password|passwd|passphrase|secret|token|otp|2fa|cvv|cvc|card|pin.?code|api.?key|парол|пин.?код|код.?подтвержден|номер.?карты|паспорт/i.test(hint))return null;
      const style=getComputedStyle(field);
      if(style.visibility!=='visible'||style.display==='none'||
         field.closest('[inert],[hidden]'))return null;
      return {ok:true,tag};
    },{x,y});
    if(!info?.ok)throw Error("BROWSER_EDITABLE_FIELD_REQUIRED");
    await this.page.mouse.move(x,y,{steps:2});
    await this.page.mouse.click(x,y,{clickCount:1,delay:35});
    const handle=await this.page.evaluateHandle(()=>document.activeElement);
    const allowed=await this.page.evaluate(el=>{
      return !!el && (el.matches('input,textarea,[contenteditable="true"]')) &&
       !el.matches('[disabled],[readonly]') && (el.isContentEditable ||
       el.matches('input:not([type="password"]),textarea'));
    },handle);
    if(!allowed){await handle.dispose();throw Error("BROWSER_EDITOR_FOCUS_FAILED");}
    this.active=handle;
    return {focused:true,tag:info.tag};
  }

  async assertFocus() {
    if(!this.active)throw Error("BROWSER_EDITOR_NOT_SELECTED");
    const allowed=await this.page.evaluate(el=>{
      if(!el||!el.isConnected||document.activeElement!==el||el.disabled||el.readOnly)
        return false;
      return el.matches('textarea,input[type="text"],input[type="search"],input[type="email"],input[type="tel"],input[type="url"]') ||
        (el.getAttribute('contenteditable')==='true'&&el.isContentEditable);
    },this.active);
    if(!allowed){this.invalidate();throw Error("BROWSER_EDITOR_LOST_FOCUS");}
  }

  async type(text,mode="append") {
    validateText(text);
    validateMode(mode);
    await this.assertFocus();
    const allowed=await this.page.evaluate((el,text,mode)=>{
      const multiline=el.matches('textarea')||el.isContentEditable;
      const limit=el.maxLength>=0?el.maxLength:Infinity;
      const old=el.value ?? el.innerText ?? "";
      if(!multiline && /[\n\r]/.test(text))return false;
      return text.length + (mode==="append"?old.length:0) <= Math.min(limit,2000);
    },this.active,text,mode);
    if(!allowed)throw Error("BROWSER_EDITOR_LIMIT_OR_NEWLINE_REFUSED");
    if(mode==="replace"){
      await this.page.keyboard.down("Control");
      await this.page.keyboard.press("A");
      await this.page.keyboard.up("Control");
      await this.page.keyboard.press("Backspace");
    }
    await this.assertFocus();
    await this.page.keyboard.type(text,{delay:0});
    // Return sizes only, never echo a client's message.
    const state=await this.page.evaluate(el=>{
      const value=el.value ?? el.innerText ?? "";
      return {characters:value.length,tag:el.tagName.toLowerCase()};
    },this.active);
    return {typed:true,characters:state.characters,tag:state.tag};
  }

  async fill(x,y,text,mode="replace"){
    await this.focus(x,y);
    return this.type(text,mode);
  }

  async press(key){
    validKey(key);
    await this.assertFocus();
    await this.page.keyboard.press(key);
    if(key==="Tab"||key==="Escape")this.invalidate();
    return {pressed:key};
  }
}

module.exports={KeyboardSession,validateText,validateMode,validKey,inspectInputs};
