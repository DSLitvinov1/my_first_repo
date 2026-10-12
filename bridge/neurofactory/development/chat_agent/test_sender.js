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
let badge='', remote=job;
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
  tabs:{async query(){return [{id:11,url:conversation}]},
    async sendMessage(id,msg){calls.push({id,msg});return {submitted:true}}}
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
  assert.equal(state.attempted[job.sequence].state,'submitted');
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
  let handlers=[];
  function probe(href,editor,options={}){
    handlers=[];
    const fakeDoc={
      activeElement:options.focused?editor:null,
      querySelector(selector){
        if(options.generating && selector.includes('stop-button'))return {disabled:false};
        if(selector.includes('prompt-textarea'))return editor;
        if(selector.includes('send-button'))return {disabled:false,click(){calls.push({sent:true})}};
        return null
      },
      createRange(){return {selectNodeContents(){},collapse(){}}},
      execCommand(){editor.textContent=prompt;editor.innerText=prompt;return true}
    };
    vm.runInNewContext(contentScript,{
      chrome:{runtime:{onMessage:{addListener(f){handlers.push(f)}}}},
      location:{href},document:fakeDoc,
      window:{getSelection(){return {removeAllRanges(){},addRange(){}}}},
      setTimeout,
      InputEvent:class{},
    },{filename:'content.js'});
    return new Promise(resolve=>handlers[0](
       {type:'NF_SEND_APPROVED_PROMPT',boundUrl:conversation,sequence:job.sequence,text:prompt},
       {},resolve));
  }
  const clean=()=>({innerText:'',textContent:'',focus(){}});
  let answer=await probe('https://chatgpt.com/c/other',clean());
  assert.equal(answer.submitted,false,'wrong conversation must be denied');
  answer=await probe(conversation,{innerText:'I am typing',textContent:'I am typing',focus(){}});
  assert.equal(answer.submitted,false,'occupied user input must not be overwritten');
  answer=await probe(conversation,clean(),{focused:true});
  assert.equal(answer.submitted,false,'focused composer must be left alone');
  answer=await probe(conversation,clean(),{generating:true});
  assert.equal(answer.submitted,false,'must not interrupt existing ChatGPT response');
  const before=calls.length;
  answer=await probe(conversation,clean());
  assert.equal(answer.submitted,true,'known composer can click send');
  assert.equal(calls.length,before+1,'exactly one UI click');
  console.log('12 browser handoff checks passed including visible receipt; actual ChatGPT send not tested');
})().catch(e=>{console.error(e);process.exitCode=1});
