/* Exact-conversation ChatGPT handoff. Never reads previous conversation or credentials. */
chrome.runtime.onMessage.addListener((req, _sender, respond)=>{
  if(req?.type!=="NF_SEND_APPROVED_PROMPT")return;
  const exact=location.href.split("?")[0].split("#")[0];
  if(exact!==req.boundUrl || !/^https:\/\/chatgpt\.com\//.test(exact)){
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
  const editor=document.querySelector("#prompt-textarea[contenteditable='true']")||
               document.querySelector("[data-testid='prompt-textarea'][contenteditable='true']");
  if(!editor||editor.innerText.trim()||editor.textContent.trim()){
    respond({submitted:false,reason:"composer unavailable or occupied"});return;
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
      const selection=window.getSelection(),range=document.createRange();
      range.selectNodeContents(editor);range.collapse(false);
      selection.removeAllRanges();selection.addRange(range);
      if(!document.execCommand("insertText",false,prompt)){
        editor.textContent=prompt;
        editor.dispatchEvent(new InputEvent("input",
          {bubbles:true,inputType:"insertText",data:prompt}));
      }
      await new Promise(resolve=>setTimeout(resolve,350));
      if(location.href.split("?")[0].split("#")[0]!==req.boundUrl){
        respond({submitted:false,reason:"conversation changed before send"});return;
      }
      if(document.querySelector('button[data-testid="stop-button"]')||
         document.querySelector('button[aria-label="Stop generating"]')){
        respond({submitted:false,reason:"generation began before send"});return;
      }
      const composerText=(editor.innerText||editor.textContent||"").replace(/\r\n/g,"\n").trim();
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
