/* Run only on already paired exact ChatGPT conversation. Never read messages or credentials. */
chrome.runtime.onMessage.addListener((request, _sender, respond)=>{
  if(request?.type!=="NF_SEND_APPROVED_PROMPT")return;
  const exact=location.href.split("?")[0].split("#")[0];
  if(exact!==request.boundUrl || !/^https:\/\/chatgpt\.com\//.test(exact)){
    respond({submitted:false,reason:"wrong conversation"});return;
  }
  const content=request.text;
  if(typeof content!=="string" || content.length<50 || content.length>3900 ||
     !/^NF-DEV-[0-9]{2}\b/.test((content.match(/NF-DEV-[0-9]{2}/)||[])[0]||"NF-DEV-00")) {
    // ID is kept in envelope; prompt wording may omit literal id.
    if(typeof content!=="string" || content.length<50 || content.length>3900){
      respond({submitted:false,reason:"invalid prompt"});return;
    }
  }
  const editor=document.querySelector("#prompt-textarea[contenteditable='true']") ||
               document.querySelector("[data-testid='prompt-textarea'][contenteditable='true']");
  if(!editor || editor.innerText.trim() || editor.textContent.trim()){
    respond({submitted:false,reason:"composer already occupied or unavailable"});return;
  }
  const send=document.querySelector('button[data-testid="send-button"]') ||
             document.querySelector('button[aria-label="Send prompt"]');
  if(!send){
    respond({submitted:false,reason:"send control missing"});return;
  }
  try{
    editor.focus();
    const selection=window.getSelection();
    const range=document.createRange();
    range.selectNodeContents(editor);range.collapse(false);
    selection.removeAllRanges();selection.addRange(range);
    // Browser editing command fires the same input events as an interactive text insertion.
    if(!document.execCommand("insertText",false,content)) {
      editor.textContent=content;
      editor.dispatchEvent(new InputEvent("input",{bubbles:true,inputType:"insertText",data:content}));
    }
    if(!editor.innerText.includes(content.slice(0,40))){
      respond({submitted:false,reason:"text insertion not confirmed"});return;
    }
    if(send.disabled){
      respond({submitted:false,reason:"send control disabled"});return;
    }
    send.click();
    respond({submitted:true,reason:"send button clicked; server delivery unverified"});
  }catch(err){respond({submitted:false,reason:String(err).slice(0,100)});}
});
