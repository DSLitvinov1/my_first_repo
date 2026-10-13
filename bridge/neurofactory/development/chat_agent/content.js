/* Exact-conversation ChatGPT handoff. Never reads previous conversation or credentials. */
function chatKey(url){
  const clean=String(url||"").split(/[?#]/)[0].replace(/\/+$/,"");
  return /^https:\/\/chatgpt\.com\/(?:g\/[^/]+\/)?c\/[A-Za-z0-9-]+$/.test(clean)?clean:"";
}
chrome.runtime.onMessage.addListener((req, _sender, respond)=>{
  // Readiness check does not focus the composer or send any message.
  if(req?.type==="NF_HEALTH_CHECK"){
    const exact=location.href.split("?")[0].split("#")[0];
    respond({ready:Boolean(chatKey(exact))&&chatKey(req.boundUrl)===chatKey(exact)});
    return;
  }
  if(req?.type!=="NF_SEND_APPROVED_PROMPT")return;
  const exact=location.href.split("?")[0].split("#")[0];
  if(!chatKey(exact) || chatKey(exact)!==chatKey(req.boundUrl)){
    respond({submitted:false,reason:"wrong conversation"});return;
  }
  const prompt=req.text;
  if(typeof prompt!=="string"||prompt.length<50||prompt.length>3900 ||
      !/^[a-f0-9]{24}$/.test(req.sequence||"")){
    respond({submitted:false,reason:"unapproved prompt envelope"});return;
  }
  const receipt="Подтверждение отправки агентом нейрозавода: "+req.sequence+".";
  if(!prompt.endsWith(receipt)){
    respond({submitted:false,reason:"missing expected delivery receipt"});return;
  }
  // Count existing receipts BEFORE clicking. A pre-existing turn with this
  // sequence is never accepted as proof that this attempt was delivered.
  const countVisibleReceipts=()=>Array.from(
    document.querySelectorAll('[data-message-author-role="user"]')||[]
  ).filter(element=>(element.textContent||"").includes(receipt)).length;
  async function waitForOwnVisibleTurn(previousCount){
    for(let attempt=0;attempt<12;attempt++){
      if(countVisibleReceipts()>previousCount)return true;
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    return false;
  }
  // ChatGPT uses several composer DOM variants. Restrict detection to its
  // known input roots, or a SINGLE visible editable control inside a form.
  function isEditable(element){
    if(!element)return false;
    return String(element.tagName||"").toLowerCase()==="textarea" ||
           element.isContentEditable===true ||
           element.getAttribute?.("contenteditable")==="true";
  }
  function isVisible(element){
    return !element.getClientRects || element.getClientRects().length>0;
  }
  function selectEditor(){
    for(const selector of ["#prompt-textarea","[data-testid='prompt-textarea']",
                           "[data-testid='composer-text-input']"]){
      const root=document.querySelector(selector);
      if(isEditable(root)&&isVisible(root))return root;
      const nested=root?.querySelector?.("[contenteditable='true'], textarea");
      if(isEditable(nested)&&isVisible(nested))return nested;
    }
    const fallbacks=Array.from(document.querySelectorAll(
      "form [contenteditable='true'], form textarea, [data-testid='composer'] [contenteditable='true']"
    )||[]).filter(element=>isEditable(element)&&isVisible(element));
    return fallbacks.length===1?fallbacks[0]:null;
  }
  const editor=selectEditor();
  if(!editor){
    respond({submitted:false,reason:"composer not found in current ChatGPT interface"});return;
  }
  const nativeInput=String(editor.tagName||"").toLowerCase()==="textarea";
  const editorText=()=>nativeInput?String(editor.value||""):
    String(editor.innerText||editor.textContent||"").replace(/\r\n/g,"\n");
  // Attachments are user drafts even when the text editor appears empty.
  // Reject before touching the composer; never send the user's files.
  function pendingAttachments(){
    const scope=editor.closest?.("form")||editor.closest?.('[data-testid="composer"]');
    const selector="img[src], [data-testid*='attachment'], [data-testid*='file-preview'], [data-testid*='upload-preview']";
    if(scope?.querySelector?.(selector))return true;
    return Boolean(document.querySelector(
      "form img[src], form [data-testid*='attachment'], form [data-testid*='file-preview'], "+
      "[data-testid='composer'] img[src], [data-testid='composer'] [data-testid*='attachment']"
    ));
  }
  if(pendingAttachments()){
    respond({submitted:false,reason:"composer contains pending attachments"});return;
  }
  if(editorText().trim()){
    respond({submitted:false,reason:"composer contains user text"});return;
  }
  // Never take over the composer when the user is currently focused on it.
  if(document.activeElement===editor ||
     (typeof editor.contains==="function" && editor.contains(document.activeElement))){
    respond({submitted:false,reason:"user is actively using composer"});return;
  }
  // Do not submit another prompt while ChatGPT is generating an answer.
  if(document.querySelector('button[data-testid="stop-button"]')||
     document.querySelector('button[aria-label="Stop generating"]')){
    respond({submitted:false,reason:"response currently generating"});return;
  }
  // Message listener stays open until React updates the input state.
  (async()=>{
    let interruptedByUser=false;
    const interrupt=event=>{if(event?.isTrusted!==false)interruptedByUser=true;};
    editor.addEventListener?.("beforeinput",interrupt,true);
    editor.addEventListener?.("paste",interrupt,true);
    editor.addEventListener?.("keydown",interrupt,true);
    try{
      editor.focus();
      if(nativeInput){
        const setter=Object.getOwnPropertyDescriptor(
          window.HTMLTextAreaElement?.prototype||{},"value")?.set;
        if(setter)setter.call(editor,prompt);
        else editor.value=prompt;
        editor.dispatchEvent(new InputEvent("input",{bubbles:true,inputType:"insertText",data:prompt}));
      }else{
        const selection=window.getSelection(),range=document.createRange();
        range.selectNodeContents(editor);range.collapse(false);
        selection.removeAllRanges();selection.addRange(range);
        if(!document.execCommand("insertText",false,prompt)){
          editor.textContent=prompt;
          editor.dispatchEvent(new InputEvent("input",
            {bubbles:true,inputType:"insertText",data:prompt}));
        }
      }
      await new Promise(resolve=>setTimeout(resolve,350));
      if(chatKey(location.href)!==chatKey(req.boundUrl)){
        respond({submitted:false,reason:"conversation changed before send"});return;
      }
      if(document.querySelector('button[data-testid="stop-button"]')||
         document.querySelector('button[aria-label="Stop generating"]')){
        respond({submitted:false,reason:"generation began before send"});return;
      }
      const composerText=editorText().trim();
      if(interruptedByUser || composerText!==prompt.trim()){
        respond({submitted:false,reason:"composer changed during send; do not auto-retry"});return;
      }
      const send=document.querySelector('button[data-testid="send-button"]')||
                 document.querySelector('button[aria-label="Send prompt"]');
      if(!send||send.disabled){
        respond({submitted:false,reason:"send button missing or disabled"});return;
      }
      // Capture baseline at the last possible instant before the irreversible click.
      const previousCount=countVisibleReceipts();
      if(pendingAttachments()){
        respond({submitted:false,reason:"composer contains pending attachments"});return;
      }
      if(interruptedByUser){
        respond({submitted:false,reason:"composer changed during send; do not auto-retry"});return;
      }
      send.click();
      const visible=await waitForOwnVisibleTurn(previousCount);
      respond({submitted:visible,observed_user_turn:visible,
        reason:visible?"new own user turn visible in bound chat":"clicked but own message not observed; do not auto-retry"});
    }catch(err){respond({submitted:false,reason:String(err).slice(0,110)});}
    finally{
      editor.removeEventListener?.("beforeinput",interrupt,true);
      editor.removeEventListener?.("paste",interrupt,true);
      editor.removeEventListener?.("keydown",interrupt,true);
    }
  })();
  return true;
});
