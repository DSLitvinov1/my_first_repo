/* Offline Chrome-extension contract tests: no browser, no chat messages actually sent. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const crypto=require('node:crypto');
const {TextEncoder,TextDecoder}=require('node:util');

const source=fs.readFileSync(__dirname+'/background.js','utf8');
const contentScript=fs.readFileSync(__dirname+'/content.js','utf8');
const conversation='https://chatgpt.com/c/12345678-abcd-1234-abcd-123456789012';
const prompt='Разрабатывай только нейрозавод. Проверь сохранение реальных результатов, безопасность очереди, независимую проверку и отправку следующего задания в выбранный чат без повторов.';
const stable=JSON.stringify({id:'NF-DEV-02',prompt}).replace('"id":','"id": ').replace(',"prompt":',', "prompt": ');
const digest=crypto.createHash('sha256').update(stable).digest('hex');
const job={schema:1,task_id:'NF-DEV-02',sequence:digest.slice(0,24),
  state:'ready_for_chat_agent',delivery:'requires_bound_chat',created_from_roadmap:true,
  prompt,sha256:digest};
const state={};
const subscribers={};
const calls=[];
let badge='', remote=job, sendMode='observed', tabUrl=conversation;
const api={
  storage:{local:{
    async get(keys){return Object.fromEntries(keys.filter(k=>k in state).map(k=>[k,state[k]]));},
    async set(values){Object.assign(state,values)}
  }},
  alarms:{async create(){},onAlarm:{addListener(fn){subscribers.alarm=fn;}}},
  action:{async setBadgeText({text}){badge=text},
    onClicked:{addListener(fn){subscribers.clicked=fn}}},
  runtime:{onInstalled:{addListener(fn){subscribers.install=fn}},
    onStartup:{addListener(fn){subscribers.startup=fn}}},
  tabs:{async query(){return [{id:11,url:tabUrl}]},
    async sendMessage(id,msg){
      if(msg.type==='NF_HEALTH_CHECK'){
        if(sendMode==='missingReceiver')throw Error('Could not establish connection. Receiving end does not exist.');
        return {ready:true};
      }
      if(sendMode==='busy')return {submitted:false,reason:'user is actively using composer'};
      calls.push({id,msg});
      return sendMode==='unconfirmed'?{submitted:false,reason:'clicked but own message not observed; do not auto-retry'}:{submitted:true,observed_user_turn:true};
    }}
};
const context={
  chrome:api,crypto:crypto.webcrypto,TextEncoder,TextDecoder,Date,
  atob(text){return Buffer.from(text,'base64').toString('binary')},
  fetch:async()=>({ok:true,json:async()=>({content:Buffer.from(JSON.stringify(remote)).toString('base64')})})
};
vm.runInNewContext(source,context,{filename:'background.js'});
const tick=()=>new Promise(r=>setTimeout(r,20));
(async()=>{
  assert.equal(typeof subscribers.clicked,'function');
  await subscribers.clicked({url:'https://example.net/c/123'});
  assert.equal(calls.length,0,'wrong host must never send');
  await subscribers.clicked({url:conversation});
  assert.equal(calls.length,1,'first explicitly bound chat must send once');
  assert.equal(calls[0].id,11);
  assert.equal(calls[0].msg.text.startsWith(prompt),true);
  assert.equal(calls[0].msg.text.includes('Подтверждение отправки агентом нейрозавода: '+job.sequence+'.'),true);
  assert.equal(state.attempted[job.sequence].state,'observed');
  assert.equal(state.nfDiagnostic.code,'SEEN','diagnostics must distinguish observed message from click');
  await subscribers.install();
  assert.equal(badge,'ON','extension reload must preserve the visible bound-on state');
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,1,'alarm must not replay same prompt');
  await subscribers.clicked({url:conversation});
  assert.equal(state.enabled,false,'second toolbar click disables');
  delete state.attempted[job.sequence];state.lastAt=0;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,1,'disabled agent must remain silent');
  remote={...job,prompt:prompt+' опасное изменение без смены подписи'};
  await subscribers.clicked({url:conversation});
  assert.equal(calls.length,1,'tampered prompt must not send');
  remote=job;
  // New local test fixture: a definitely refused pre-send attempt must be retryable.
  state.attempted={};state.lastAt=0;sendMode='busy';
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(state.attempted[job.sequence],undefined,'pre-send busy state is not permanently locked');
  assert.equal(state.nfDiagnostic.code,'COMPOSER_BUSY','diagnostics must explain occupied user composer');
  sendMode='observed';state.lastAt=0;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(state.attempted[job.sequence].state,'observed','idle composer allows later delivery');
  state.attempted={};state.lastAt=0;sendMode='unconfirmed';
  const unconfirmedCalls=calls.length;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(state.attempted[job.sequence].state,'unconfirmed','uncertain send is reserved');
  assert.equal(state.nfDiagnostic.code,'UNCONFIRMED','diagnostics must show the no-retry state');
  assert.match(state.attempted[job.sequence].reason,/clicked but own message not observed/,
    'ambiguous send must record the reason without unlocking retry');
  state.lastAt=0;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,unconfirmedCalls+1,'uncertain send must never replay');
  // A tab opened before installing an extension has no receiving content script.
  state.attempted={};state.lastAt=0;sendMode='missingReceiver';
  const beforeNoListener=calls.length;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,beforeNoListener,'readiness failure must not attempt to send');
  assert.equal(state.attempted[job.sequence],undefined,'no-listener failure must not reserve task');
  assert.equal(state.nfDiagnostic.code,'CHAT_REFRESH_REQUIRED','explain F5 on the bound chat tab');
  sendMode='observed';state.lastAt=0;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(state.attempted[job.sequence].state,'observed','after F5 and listener ready, deliver once');
  // Recover only the original no-receiver error already stored by the older build.
  state.attempted={[job.sequence]:{state:'unconfirmed',error:'Error: Could not establish connection. Receiving end does not exist.',task:job.task_id}};
  state.lastAt=0;
  const beforeSafeRecovery=calls.length;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,beforeSafeRecovery+1,'old proven pre-send failure may safely retry');
  assert.equal(state.attempted[job.sequence].state,'observed','safe recovery must preserve proof');
  // An unknown transmission error must NOT be re-sent.
  state.attempted={[job.sequence]:{state:'unconfirmed',error:'Error: The message port closed before a response was received.',task:job.task_id}};
  state.lastAt=0;
  const beforeUnknownError=calls.length;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,beforeUnknownError,'unknown transmission outcome must remain blocked');
  let handlers=[];
  function probe(href,editor,options={}){
    handlers=[];
    let clickOccurred=false;
    const deliveredText=prompt+'\n\nПодтверждение отправки агентом нейрозавода: '+job.sequence+'.';
    const fakeDoc={
      activeElement:options.focused?editor:null,
      querySelectorAll(selector){
        if(selector!=='[data-message-author-role="user"]')return [];
        const visible=[];
        if(options.previousReceipt)visible.push({textContent:deliveredText});
        if(clickOccurred && options.visible!==false)visible.push({textContent:deliveredText});
        return visible;
      },
      querySelector(selector){
        if(options.attachments && selector.startsWith('form img[src]'))return {tagName:'IMG'};
        if(options.generating && selector.includes('stop-button'))return {disabled:false};
        if(options.noEditor && (selector.includes('prompt-textarea')||selector.includes('composer-text-input')))return null;
        if(options.altWrapper && selector.includes('#prompt-textarea'))return null;
        if(options.altWrapper && selector.includes('prompt-textarea'))return {querySelector(){return editor;}};
        if(selector.includes('prompt-textarea')||selector.includes('composer-text-input'))return editor;
        if(selector.includes('send-button'))return {disabled:false,click(){clickOccurred=true;calls.push({sent:true})}};
        return null
      },
      createRange(){return {selectNodeContents(){},collapse(){}}},
      execCommand(){
        editor.textContent=deliveredText+(options.appendUserText?' USER TYPED':'');
        editor.innerText=editor.textContent;
        return true;
      }
    };
    vm.runInNewContext(contentScript,{
      chrome:{runtime:{onMessage:{addListener(f){handlers.push(f)}}}},
      location:{href},document:fakeDoc,
      window:{getSelection(){return {removeAllRanges(){},addRange(){}}}},
      setTimeout:(fn)=>{setImmediate(fn);return 0},
      InputEvent:class{},
    },{filename:'content.js'});
    return new Promise(resolve=>handlers[0](
       {type:options.probeType||'NF_SEND_APPROVED_PROMPT',
        boundUrl:conversation,sequence:job.sequence,text:deliveredText},
       {},resolve));
  }
  const clean=()=>({tagName:'DIV',innerText:'',textContent:'',
    getAttribute(key){return key==='contenteditable'?'true':null},focus(){},
    dispatchEvent(){}});
  let answer=await probe('https://chatgpt.com/c/other',clean());
  // Existing tests below continue to ensure wrong-chat isolation.
  assert.equal(answer.submitted,false,'wrong conversation must be denied');
  answer=await probe(conversation,{innerText:'I am typing',textContent:'I am typing',focus(){}});
  assert.equal(answer.submitted,false,'occupied user input must not be overwritten');
  answer=await probe(conversation,clean(),{focused:true});
  assert.equal(answer.submitted,false,'focused composer must be left alone');
  answer=await probe(conversation,clean(),{generating:true});
  assert.equal(answer.submitted,false,'must not interrupt existing ChatGPT response');
  const beforeAttachments=calls.length;
  const attachmentDraft=await probe(conversation,clean(),{attachments:true});
  assert.equal(attachmentDraft.submitted,false,'unsent images must never be submitted by the agent');
  assert.equal(attachmentDraft.reason,'composer contains pending attachments','show safe diagnostic for draft files');
  assert.equal(calls.length,beforeAttachments,'no click when user screenshots are attached');
  const beforeInspect=calls.length;
  const checked=await probe(conversation,clean(),
    {probeType:'NF_INSPECT_DELIVERY',previousReceipt:true,visible:false});
  assert.equal(checked.ready,true,'read-only receipt check requires exact bound conversation');
  assert.equal(checked.found,true,'read-only check locates existing full receipt');
  assert.equal(calls.length,beforeInspect,'inspection must never click Send');
  const checkedAbsent=await probe(conversation,clean(),
    {probeType:'NF_INSPECT_DELIVERY',visible:false});
  assert.equal(checkedAbsent.found,false,'receipt check distinguishes missing marker');
  assert.equal(calls.length,beforeInspect,'missing receipt must not trigger new send');
  const checkedWrong=await probe('https://chatgpt.com/c/other',clean(),
    {probeType:'NF_INSPECT_DELIVERY',previousReceipt:true});
  assert.equal(checkedWrong.ready,false,'must not inspect wrong conversation');
  const noEditorCalls=calls.length;
  answer=await probe(conversation,clean(),{noEditor:true});
  assert.equal(answer.submitted,false,'missing composer must not initiate a send');
  assert.equal(answer.reason,'composer not found in current ChatGPT interface');
  assert.equal(calls.length,noEditorCalls,'no false send for missing editor');
  answer=await probe(conversation,clean(),{altWrapper:true});
  assert.equal(answer.submitted,true,'contenteditable nested in wrapper is supported');
  const textarea={tagName:'TEXTAREA',value:'',focus(){},dispatchEvent(){}};
  const beforeTextarea=calls.length;
  answer=await probe(conversation,textarea);
  assert.equal(answer.submitted,true,'safe empty textarea composer can be used');
  assert.equal(calls.length,beforeTextarea+1,'native textarea variant sends exactly once');
  const draftedTextarea={tagName:'TEXTAREA',value:'my unsent message',focus(){},dispatchEvent(){}};
  const beforeDraft=calls.length;
  answer=await probe(conversation,draftedTextarea);
  assert.equal(answer.submitted,false,'non-empty textarea draft must remain untouched');
  assert.equal(draftedTextarea.value,'my unsent message','never overwrite user textarea draft');
  assert.equal(calls.length,beforeDraft,'no send occurs while the user has a draft');
  const before=calls.length;
  answer=await probe(conversation,clean());
  assert.equal(answer.submitted,true,'visible own turn confirms the attempt');
  assert.equal(answer.observed_user_turn,true,'visible user message must have exact receipt');
  assert.equal(calls.length,before+1,'exactly one UI click');
  const noReceipt=await probe(conversation,clean(),{visible:false});
  assert.equal(noReceipt.submitted,false,'button click alone is not proof of visible delivery');
  assert.equal(noReceipt.observed_user_turn,false,'absence of own turn cannot be accepted');
  const oldReceiptOnly=await probe(conversation,clean(),{previousReceipt:true,visible:false});
  assert.equal(oldReceiptOnly.submitted,false,'prior matching turn is not new delivery proof');
  const withNewTurn=await probe(conversation,clean(),{previousReceipt:true,visible:true});
  assert.equal(withNewTurn.submitted,true,'new user turn should count even when older matching turn exists');
  const beforeTyping=calls.length;
  const interrupted=await probe(conversation,clean(),{appendUserText:true});
  assert.equal(interrupted.submitted,false,'changed composer cannot be sent');
  assert.equal(calls.length,beforeTyping,'never click send after user appended text');
  // A newly approved milestone has a different digest and must be fetched exactly once.
  state.attempted[job.sequence]={state:'observed',task:job.task_id,at:Date.now()};
  state.enabled=true;state.lastAt=0;sendMode='observed';
  const nextPrompt='Продолжи реальную разработку ядра нейрозавода с двумя независимыми агентами, проверкой кода и сохранением только подтверждённых изменений. Не затрагивай другие проекты.';
  const nextStable=JSON.stringify({id:'NF-DEV-03',prompt:nextPrompt}).replace('"id":','"id": ').replace(',"prompt":',', "prompt": ');
  const nextDigest=crypto.createHash('sha256').update(nextStable).digest('hex');
  remote={...job,task_id:'NF-DEV-03',prompt:nextPrompt,sha256:nextDigest,sequence:nextDigest.slice(0,24)};
  tabUrl=conversation+'/?utm_source=browser'; // same exact bound thread with harmless URL suffix
  const previousCount=calls.length;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,previousCount+1,'next verified milestone should be fetched automatically');
  assert.equal(calls.at(-1).msg.text.includes(nextDigest.slice(0,24)),true,'next sent prompt has new proof marker');
  assert.equal(state.attempted[remote.sequence].state,'observed','new milestone has independent receipt');
  state.lastAt=0;
  await subscribers.alarm({name:'nf-roadmap-poll'});await tick();
  assert.equal(calls.length,previousCount+1,'new milestone must not be sent twice');
  console.log('Browser handoff checks passed: read-only exact-chat receipt inspection, recorded uncertain reason, no replay, attachment and user draft protection, next task. Live sending remains unverified.');
})().catch(e=>{console.error(e);process.exitCode=1});
