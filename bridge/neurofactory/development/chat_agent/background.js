/* Neurofactory chat bridge: one explicitly bound conversation, one attempt per prompt. */
const OUTBOX="https://api.github.com/repos/DSLitvinov1/my_first_repo/contents/bridge/neurofactory/development/chat_outbox.json?ref=neurofactory-public-lab-20261012";
const CHAT=/^https:\/\/chatgpt\.com\/(?:g\/[^/]+\/)?c\/[A-Za-z0-9-]+\/?$/;
const MIN_GAP=5*60*1000;
const MAX_PROMPT=3900;
let pollInFlight=false;
async function singlePoll(){if(pollInFlight)return;pollInFlight=true;try{await poll();}finally{pollInFlight=false;}}
async function local() { return await chrome.storage.local.get(["chatUrl","enabled","attempted","lastAt"]); }
async function view(text) { await chrome.action.setBadgeText({text}); }
function decode(data) {
  const bin=atob(data.replace(/\s+/g,""));
  return new TextDecoder("utf-8").decode(Uint8Array.from(bin,c=>c.charCodeAt(0)));
}
async function verifyDigest(job){
  if(!/^[a-f0-9]{64}$/.test(job.sha256||""))return false;
  if(job.sequence!==job.sha256.slice(0,24))return false;
  const encoded=new TextEncoder().encode('{"id": '+JSON.stringify(job.task_id)+', "prompt": '+JSON.stringify(job.prompt)+'}');
  const digest=await crypto.subtle.digest('SHA-256',encoded);
  const actual=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,'0')).join('');
  return actual===job.sha256;
}
async function poll() {
  const cfg=await local();
  if (!cfg.enabled || !CHAT.test(cfg.chatUrl||"")) return;
  if (Date.now()-(cfg.lastAt||0)<MIN_GAP) return;
  const response=await fetch(OUTBOX,{credentials:"omit",cache:"no-store",headers:{"Accept":"application/vnd.github+json"}});
  if (!response.ok) throw new Error("Roadmap outbox unavailable");
  const remote=await response.json(), job=JSON.parse(decode(remote.content));
  if (job.schema!==1 || job.state!=="ready_for_chat_agent" ||
      job.delivery!=="requires_bound_chat" || job.created_from_roadmap!==true ||
      !/^NF-DEV-\d{2}$/.test(job.task_id||"") ||
      !/^[a-f0-9]{24}$/.test(job.sequence||"") ||
      typeof job.prompt!=="string" || job.prompt.length<50 || job.prompt.length>MAX_PROMPT ||
      !(await verifyDigest(job))) return;
  if (cfg.attempted?.[job.sequence]) return;
  // A visible per-milestone handoff receipt can later be matched to the actual chat turn.
  // Only this one-stage sender adds it; clicking Send alone is never accepted as proof.
  const visibleReceipt="\\n\\nПодтверждение отправки агентом нейрозавода: "+job.sequence+".";
  const outgoingText=job.prompt+visibleReceipt;
  if(outgoingText.length>MAX_PROMPT)return;
  const tabs=await chrome.tabs.query({});
  const matched=tabs.find(t=>t.url===cfg.chatUrl && t.id!==undefined);
  if (!matched) return;
  const attempt={...(cfg.attempted||{})};
  // Reserve the sequence BEFORE clicking Send; failures cannot silently duplicate user messages.
  attempt[job.sequence]={state:"attempted",task:job.task_id,at:Date.now()};
  await chrome.storage.local.set({attempted:attempt,lastAt:Date.now()});
  try {
    const reply=await chrome.tabs.sendMessage(matched.id,{type:"NF_SEND_APPROVED_PROMPT",boundUrl:cfg.chatUrl,
      sequence:job.sequence,text:outgoingText});
    attempt[job.sequence]={state:reply?.submitted?"submitted":"unconfirmed",task:job.task_id,at:Date.now()};
    await chrome.storage.local.set({attempted:attempt});
    await view(reply?.submitted?"OK":"?");
  }catch(err){
    attempt[job.sequence]={state:"unconfirmed",task:job.task_id,at:Date.now(),error:String(err).slice(0,120)};
    await chrome.storage.local.set({attempted:attempt});
    await view("?");
  }
}
chrome.runtime.onInstalled.addListener(async()=>{
  await chrome.alarms.create("nf-roadmap-poll",{periodInMinutes:3});
  await view("OFF");
});
chrome.alarms.onAlarm.addListener(a=>{if(a.name==="nf-roadmap-poll") singlePoll().catch(async()=>view("!"));});
chrome.action.onClicked.addListener(async tab=>{
  const url=(tab.url||"").split("?")[0].split("#")[0];
  if (!CHAT.test(url)) { await view("NO");return; }
  const cfg=await local();
  if (cfg.enabled && cfg.chatUrl===url) {
    await chrome.storage.local.set({enabled:false});await view("OFF");return;
  }
  // Explicit binding, initiated by the human on the exact conversation tab.
  await chrome.storage.local.set({chatUrl:url,enabled:true,attempted:cfg.chatUrl===url?(cfg.attempted||{}):{}});
  await view("ON");
  await chrome.alarms.create("nf-roadmap-poll",{periodInMinutes:3});
  await singlePoll().catch(async()=>view("!"));
});
chrome.runtime.onStartup.addListener(async()=>{await chrome.alarms.create("nf-roadmap-poll",{periodInMinutes:3});});
