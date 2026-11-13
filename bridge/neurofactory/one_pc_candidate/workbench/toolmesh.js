"use strict";
/* Work ONE v0.6: one local UI; no direct secrets/model instructions execute. */
const mesh = {
  project:null, status:null, planId:null, desktopSession:null,
  screenshot:null, record:null, pending:null, flow:null, busy:false,
};

function meshMessage(text, error=false) {
  $("mesh-record-result").textContent=text;
  if(error)notice(text,true);
}

async function meshRefresh() {
  try {
    const status=await api("/api/toolmesh/status");
    mesh.status=status;
    const google=status.google||{};
    const configured=status.services?.configured||{};
    $("mesh-qwen-status").textContent=status.qwen?.configured?
      "Qwen готов к предложению плана; ни одно действие модели не выполняется автоматически.":
      "Модель Qwen не подключена в этом экземпляре. Можно вводить проверенный сценарий вручную.";
    $("mesh-connectors-status").textContent=
      "Google: "+((google.connected_scopes||[]).join(", ")||"нет согласованных прав")+
      " · Bitrix24: "+(status.bitrix_connected?"подключён":"не подключён");
    $("mesh-google-connect").disabled=!google.configured;
    $("mesh-google-disconnect").disabled=!google.configured;
    $("mesh-bitrix-connect").disabled=false;
    $("mesh-plan").disabled=!state.project||!status.qwen?.configured;
    const desktop=status.desktop||{};
    $("mesh-desktop-status").textContent=desktop.configured?
      "Доступ только для приложений: "+(desktop.allowed_apps||[]).join(", "):
      "Управление Windows выключено. Запустите приложение в пользовательской сессии с явным списком разрешённых программ.";
    $("mesh-windows").disabled=!state.project||!desktop.configured;
    if(mesh.project!==state.project) {
      mesh.project=state.project;
      mesh.record=null;
      mesh.pending=null;
      mesh.flow=null;
      mesh.desktopSession=null;
      $("mesh-flow-start").disabled=true;
      $("mesh-flow-write").disabled=true;
      $("mesh-flow-result").textContent="Подготовь сценарий для выбранного проекта.";
      $("mesh-record-commit").disabled=true;
      $("mesh-screen").hidden=true;
      $("mesh-screen").removeAttribute("src");
      $("mesh-window-list").replaceChildren();
    }
  }catch(e){
    $("mesh-qwen-status").textContent="Статус недоступен: "+e.message;
  }
}

async function meshQwenPlan(){
  if(!state.project||mesh.busy)return;
  const goal=$("mesh-goal").value.trim();
  if(goal.length<15){notice("Опиши цель не менее чем в 15 символах.",true);return;}
  mesh.busy=true;
  $("mesh-qwen-status").textContent="Qwen готовит только черновик плана...";
  try {
    const result=await api("/api/qwen/propose","POST",{project_id:state.project,goal});
    mesh.planId=result.id;
    mesh.project=state.project;
    $("mesh-qwen-status").textContent="План в обработке: "+result.id.slice(0,8);
  }catch(e){
    $("mesh-qwen-status").textContent="Qwen: "+e.message;
    notice(e.message,true);
  }finally{mesh.busy=false;}
}
async function meshPollQwen(){
  if(!mesh.planId||mesh.project!==state.project)return;
  try{
    const qs=new URLSearchParams({project_id:state.project,id:mesh.planId});
    const result=await api("/api/qwen/plan?"+qs);
    if(result.state==="GENERATING")return;
    mesh.planId=null;
    if(result.state==="PROPOSED"&&result.script){
      $("one-instructions").value=result.script;
      $("one-instructions").dispatchEvent(new Event("input",{bubbles:true}));
      $("mesh-qwen-status").textContent=
        "Qwen предложил "+result.steps+" действий. Проверь план в соседнем разделе, затем подтверди отдельно.";
      $("one-instructions").scrollIntoView({behavior:"smooth",block:"center"});
    }else{
      $("mesh-qwen-status").textContent="План Qwen не получен: "+(result.error||result.state);
    }
  }catch(e){
    mesh.planId=null;
    $("mesh-qwen-status").textContent="План Qwen недоступен: "+e.message;
  }
}

async function meshWindows(){
  if(!state.project||mesh.busy)return;
  mesh.busy=true;
  try{
    const result=await api("/api/desktop/windows","POST",{project_id:state.project});
    const list=$("mesh-window-list");
    list.replaceChildren();
    for(const win of result.windows||[]){
      const opt=document.createElement("option");
      opt.value=JSON.stringify(win);
      opt.textContent=win.app+" · процесс "+win.pid;
      list.append(opt);
    }
    $("mesh-desktop-status").textContent=
      "Разрешённые окна: "+(result.windows||[]).length;
  }catch(e){$("mesh-desktop-status").textContent=e.message;}
  finally{mesh.busy=false;}
}
async function meshAttach(){
  if(!state.project||mesh.busy)return;
  const selected=$("mesh-window-list").value;
  if(!selected){notice("Сначала найди и выбери разрешённое окно.",true);return;}
  const win=JSON.parse(selected);
  if(!window.confirm("Подключиться к окну "+win.app+" (PID "+win.pid+")?\\n"+
     "Клики и ввод будут доступны только внутри этого приложения."))return;
  mesh.busy=true;
  try{
    const result=await api("/api/desktop/attach","POST",{
      project_id:state.project,app:win.app,pid:win.pid,handle:win.handle});
    mesh.desktopSession=result.session_id;
    $("mesh-desktop-status").textContent=
      "Подключено: "+result.app+". Нажми «Снимок», чтобы увидеть окно.";
    await meshDesktopAction("frame");
  }catch(e){$("mesh-desktop-status").textContent="Подключение отклонено: "+e.message;}
  finally{mesh.busy=false;}
}
async function meshDesktopAction(op, data={}){
  if(!state.project||!mesh.desktopSession)return;
  try{
    const result=await api("/api/desktop/action","POST",{
      project_id:state.project,session_id:mesh.desktopSession,op,...data});
    if(op==="frame"&&result.result?.image){
      const image=result.result.image;
      if(/^[A-Za-z0-9+/=]+$/.test(image)&&image.length<=850000){
        mesh.screenshot=result.result;
        $("mesh-screen").src="data:image/jpeg;base64,"+image;
        $("mesh-screen").hidden=false;
      }
    }
    $("mesh-desktop-status").textContent=
      op==="type"?"Текст напечатан в выбранном поле разрешённой программы.":
      op==="click"?"Нажатие выполнено в выбранном окне.":
      "Команда Windows выполнена: "+op;
  }catch(e){
    $("mesh-desktop-status").textContent="Windows: "+e.message;
    if(/UNKNOWN|SESSION|EXPIRED|WORKER_STOPPED/.test(e.message)){
      mesh.desktopSession=null;
    }
  }
}
async function meshDesktopClose(){
  if(!mesh.desktopSession||!state.project)return;
  try{
    await api("/api/desktop/close","POST",
      {project_id:state.project,session_id:mesh.desktopSession});
    $("mesh-desktop-status").textContent="Окно отключено.";
  }catch(e){$("mesh-desktop-status").textContent=e.message;}
  finally{
    mesh.desktopSession=null;mesh.screenshot=null;
    $("mesh-screen").hidden=true;$("mesh-click-mode").checked=false;
  }
}

async function meshConnectGoogle(){
  if(!mesh.status?.google?.configured)return;
  const scope=$("mesh-google-scope").value;
  if(!window.confirm("Подключить Google с разрешением: "+scope+"?\\n"+
    "Вы сами подтверждаете доступ на странице Google."))return;
  // Opening a blank tab synchronously avoids popup blockers.
  const tab=window.open("about:blank","_blank");
  if(tab)tab.opener=null;
  try{
    const result=await api("/api/connectors/google/start","POST",{scope});
    if(tab)tab.location.href=result.authorization_url;
    else{
      const link=document.createElement("a");
      link.textContent="Открыть страницу согласия Google";
      link.href=result.authorization_url;
      link.target="_blank";link.rel="noopener noreferrer";
      $("mesh-connectors-status").replaceChildren(link);
    }
  }catch(e){
    if(tab)tab.close();
    notice("Google: "+e.message,true);
  }
}
async function meshDisconnectGoogle(){
  const scope=$("mesh-google-scope").value;
  if(!window.confirm("Удалить локальные токены Google для "+scope+
      "? Доступ можно также отозвать в аккаунте Google."))return;
  try{
    await api("/api/connectors/google/disconnect","POST",{scope});
    await meshRefresh();
  }catch(e){notice(e.message,true);}
}
async function meshConnectBitrix(){
  const portal=$("mesh-bitrix-portal").value.trim().toLowerCase();
  const access_token=$("mesh-bitrix-token").value.trim();
  if(!portal||!access_token){notice("Укажи портал и отдельный OAuth-токен.",true);return;}
  if(!window.confirm("Подключить именно этот Bitrix24-портал: "+portal+"?\\n"+
    "Токен будет зашифрован для текущего пользователя Windows."))return;
  try{
    await api("/api/connectors/bitrix/connect","POST",{portal,access_token});
    $("mesh-bitrix-token").value="";
    await meshRefresh();
    notice("Портал подключён в локальном хранилище.");
  }catch(e){$("mesh-bitrix-token").value="";notice(e.message,true);}
}
async function meshDisconnectBitrix(){
  if(!window.confirm("Отключить Bitrix24 и удалить его локальный токен?"))return;
  try{
    await api("/api/connectors/bitrix/disconnect","POST",{});
    await meshRefresh();
  }catch(e){notice(e.message,true);}
}

function meshRecordFields(){
  const action=$("mesh-record-action").value;
  const title=$("mesh-record-title").value.trim();
  const list_id=$("mesh-record-list").value.trim();
  const responsible_id=Number($("mesh-record-responsible").value);
  const id=$("mesh-record-id").value.trim();
  const expected_title=$("mesh-record-old").value.trim();
  const notes=$("mesh-record-notes").value.trim();
  let fields;
  if(action==="google.tasks.create"){
    fields={list_id,title};if(notes)fields.notes=notes;
  }else if(action==="google.tasks.update"){
    fields={list_id,id,title,expected_title};
  }else if(action==="bitrix.tasks.create"){
    fields={title,responsible_id};if(notes)fields.description=notes;
  }else if(action==="bitrix.tasks.update"){
    fields={id,title,expected_title};
  }else{throw Error("Недопустимое действие");}
  return {action,fields};
}
async function meshRecordPrepare(){
  if(!state.project)return notice("Выбери проект",true);
  const {action,fields}=meshRecordFields();
  mesh.record=null;$("mesh-record-commit").disabled=true;
  try{
    const result=await api("/api/service/prepare","POST",
      {project_id:state.project,action,fields});
    mesh.record={project:state.project,action,fields,hash:JSON.stringify(fields),id:result.id};
    $("mesh-record-commit").disabled=false;
    meshMessage("План операции проверен:\n"+action+"\n"+JSON.stringify(fields,null,2)+
      "\nПодтверди сохранение отдельно. Разрешение действует 5 минут.");
  }catch(e){meshMessage("Запись отклонена: "+e.message,true);}
}
async function meshRecordCommit(){
  const saved=mesh.record;
  if(!saved||saved.project!==state.project)return;
  const current=meshRecordFields();
  if(current.action!==saved.action||JSON.stringify(current.fields)!==saved.hash){
    mesh.record=null;$("mesh-record-commit").disabled=true;
    return meshMessage("Поля изменились. Проверь операцию заново.",true);
  }
  const preview=saved.action+" · "+saved.fields.title;
  if(!window.confirm("Подтвердить запись во внешнем сервисе?\\n"+preview+
    "\\nПовтор при неопределённом результате будет заблокирован."))return;
  mesh.record=null;$("mesh-record-commit").disabled=true;
  try{
    const reply=await api("/api/service/commit","POST",{
      project_id:saved.project,id:saved.id,action:saved.action,fields:saved.fields});
    meshMessage("Состояние: "+reply.state+
      "\nID записи: "+(reply.record_id||"не подтверждён")+
      (reply.error?"\n"+reply.error:""));
  }catch(e){meshMessage("Состояние записи неизвестно: "+e.message,true);}
}

async function meshRead(){
  if(!state.project)return notice("Выбери проект",true);
  const resource=$("mesh-read-resource").value;
  let fields={};
  if(resource==="google.tasks.list")fields={list_id:$("mesh-record-list").value.trim()};
  if(resource.startsWith("bitrix."))fields={id:$("mesh-record-id").value.trim()};
  try{
    const result=await api("/api/service/read","POST",{
      project_id:state.project,resource,fields});
    meshMessage(JSON.stringify(result.data,null,2).slice(0,32000));
  }catch(e){meshMessage("Чтение не выполнено: "+e.message,true);}
}

async function meshPrivateCheck() {
  const target=$("mesh-personal-result");
  target.textContent="Проверка...";
  try {
    const report=await api("/api/private/readiness");
    const names={
      qwen:"Планировщик Qwen",
      browser:"Управление браузером",
      desktop:"Рабочий стол Windows",
      google_tasks:"Google Tasks",
      bitrix24:"Bitrix24"
    };
    const states={
      ready:"Готово к следующему тесту",
      needs_setup:"Требуется подключение",
      needs_live_test:"Нужна проверка реального аккаунта"
    };
    const lines=["Личный режим · без коммерческого выпуска",
      "Это проверка подключения, не проверка безопасности."];
    for(const step of report.checks||[]){
      lines.push((names[step.id]||step.id)+": "+(states[step.status]||step.status));
    }
    lines.push("Автоматическое изменение внешних данных без подтверждения отключено.");
    lines.push("Первое необходимое действие: "+(
      report.next?.[0]||"Провести сквозной тест на отдельном тестовом аккаунте"));
    target.textContent=lines.join("\n");
  }catch(error) {
    target.textContent="Проверка не выполнена: "+error.message;
  }
}

function meshFlowInputs(){
  const script=$("one-instructions").value;
  const {action,fields}=meshRecordFields();
  return {script,action,fields,signature:JSON.stringify({script,action,fields})};
}

function meshFlowMatches(){
  if(!mesh.flow||mesh.flow.project!==state.project)return false;
  return meshFlowInputs().signature===mesh.flow.signature;
}

async function meshFlowPrepare(){
  if(!state.project)return notice("Выбери проект",true);
  mesh.flow=null;
  $("mesh-flow-start").disabled=true;
  $("mesh-flow-write").disabled=true;
  $("mesh-flow-result").textContent="Проверяю безопасный план...";
  try{
    const x=meshFlowInputs();
    const result=await api("/api/private/flow/prepare","POST",{
      project_id:state.project,script:x.script,action:x.action,fields:x.fields});
    mesh.flow={id:result.id,project:state.project,...x,state:"PREPARED"};
    $("mesh-flow-start").disabled=false;
    $("mesh-flow-result").textContent="Подготовлено: "+result.browser_steps+
      " безопасных действий браузера.\nВнешняя запись: "+result.service_action+
      ".\nСначала разреши проверку сайта; создание записи потребует второго подтверждения.";
  }catch(e){
    $("mesh-flow-result").textContent="План отклонён: "+e.message;
  }
}

async function meshFlowStart(){
  const f=mesh.flow;
  if(!f||f.state!=="PREPARED")return;
  if(!meshFlowMatches()){
    $("mesh-flow-start").disabled=true;
    return notice("Сценарий или поля изменились. Подготовь цепочку заново.",true);
  }
  if(!window.confirm("Проверить страницу указанными безопасными действиями?\n"+
       "Этот этап ничего не записывает в Google или Битрикс24."))return;
  $("mesh-flow-start").disabled=true;
  try{
    const r=await api("/api/private/flow/start","POST",{
      project_id:f.project,id:f.id,script:f.script,action:f.action,fields:f.fields});
    f.state=r.state;
    $("mesh-flow-result").textContent="Проверяю сайт. Сохранение задачи заблокировано.";
  }catch(e){
    f.state="UNKNOWN_NO_RETRY";
    $("mesh-flow-result").textContent="Проверка не подтверждена: "+e.message;
  }
}

async function meshFlowPoll(){
  const f=mesh.flow;
  if(!f||f.state!=="READING"||f.project!==state.project)return;
  try{
    const params=new URLSearchParams({project_id:f.project,id:f.id});
    const r=await api("/api/private/flow/status?"+params);
    if(!mesh.flow||mesh.flow.id!==f.id)return;
    f.state=r.state;
    if(r.state==="AWAITING_WRITE"){
      $("mesh-flow-result").textContent=
        "Сайт проверен. Теперь можно отдельно подтвердить запись во внешнем сервисе.";
      $("mesh-flow-write").disabled=false;
    }else if(r.state!=="READING"){
      $("mesh-flow-result").textContent=
        "Проверка остановлена: "+r.state+". Запись не выполнялась автоматически.";
      $("mesh-flow-write").disabled=true;
    }
  }catch(e){
    f.state="UNKNOWN_NO_RETRY";
    $("mesh-flow-write").disabled=true;
    $("mesh-flow-result").textContent="Неизвестный результат проверки: "+e.message;
  }
}

async function meshFlowConfirm(){
  const f=mesh.flow;
  if(!f||f.state!=="AWAITING_WRITE")return;
  if(!meshFlowMatches()){
    $("mesh-flow-write").disabled=true;
    return notice("Сценарий или поля изменились. Подготовь цепочку заново.",true);
  }
  if(!window.confirm("Проверка сайта завершена. Подтвердить ОДНУ запись во внешнем сервисе?\n"+
    f.action+"\nПри неизвестном результате повторная отправка будет заблокирована."))return;
  f.state="WRITING";
  $("mesh-flow-write").disabled=true;
  $("mesh-flow-result").textContent="Запись отправляется один раз, затем проверяется.";
  try{
    const r=await api("/api/private/flow/confirm","POST",{
      project_id:f.project,id:f.id,script:f.script,action:f.action,fields:f.fields});
    f.state=r.state;
    $("mesh-flow-result").textContent=r.write_verified?
      "Запись создана/изменена и повторно проверена (VERIFIED).":
      "Неопределённый результат (UNKNOWN_NO_RETRY). Не отправляй повторно без ручной проверки.";
  }catch(e){
    f.state="UNKNOWN_NO_RETRY";
    $("mesh-flow-result").textContent=
      "Нет подтверждения результата. Автоматический повтор запрещён: "+e.message;
  }
}

function bindMesh(){
  $("mesh-personal-check").addEventListener("click",meshPrivateCheck);
  $("mesh-flow-prepare").addEventListener("click",meshFlowPrepare);
  $("mesh-flow-start").addEventListener("click",meshFlowStart);
  $("mesh-flow-write").addEventListener("click",meshFlowConfirm);
  $("mesh-plan").addEventListener("click",meshQwenPlan);
  $("mesh-windows").addEventListener("click",meshWindows);
  $("mesh-attach").addEventListener("click",meshAttach);
  $("mesh-frame").addEventListener("click",()=>meshDesktopAction("frame"));
  $("mesh-close").addEventListener("click",meshDesktopClose);
  $("mesh-type").addEventListener("click",()=>{
    const text=$("mesh-desktop-input").value;
    if(text)meshDesktopAction("type",{text});
  });
  $("mesh-screen").addEventListener("click",event=>{
    if(!$("mesh-click-mode").checked||!mesh.screenshot)return;
    const rect=$("mesh-screen").getBoundingClientRect();
    const img=mesh.screenshot;
    const x=Math.floor((event.clientX-rect.left)*img.width/rect.width+img.offset_x);
    const y=Math.floor((event.clientY-rect.top)*img.height/rect.height+img.offset_y);
    if(!window.confirm("Нажать мышью в выбранном окне Windows по точке "+
      x+", "+y+"?"))return;
    meshDesktopAction("click",{x,y});
  });
  $("mesh-google-connect").addEventListener("click",meshConnectGoogle);
  $("mesh-google-disconnect").addEventListener("click",meshDisconnectGoogle);
  $("mesh-bitrix-connect").addEventListener("click",meshConnectBitrix);
  $("mesh-bitrix-disconnect").addEventListener("click",meshDisconnectBitrix);
  $("mesh-record-prepare").addEventListener("click",meshRecordPrepare);
  $("mesh-record-commit").addEventListener("click",meshRecordCommit);
  $("mesh-read").addEventListener("click",meshRead);
  for(const id of ["mesh-record-action","mesh-record-title","mesh-record-list",
    "mesh-record-responsible","mesh-record-id","mesh-record-old","mesh-record-notes"]){
    $(id).addEventListener("input",()=>{
      mesh.record=null;$("mesh-record-commit").disabled=true;
    });
  }
}

bindMesh();
meshRefresh();
meshPrivateCheck();
setInterval(meshRefresh,15000);
setInterval(meshPollQwen,1500);
setInterval(meshFlowPoll,1300);
