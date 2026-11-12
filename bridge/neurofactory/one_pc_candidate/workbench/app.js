"use strict";
/* Neurofactory Work: client-side controls. No eval, dynamic HTML, or model execution. */
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="nf-token"]').content;
const state = { projects:[],project:null,tasks:[],selectedTask:null,files:[],
                file:null,sha:null,savedText:null,modelOk:false,poll:null };
let toastTimer=null;
const browserState={configured:false,session:null,project:null,active:false,busy:false,moveBusy:false,lastMove:0};

async function api(url,method="GET",body){
  const opt={method,cache:"no-store",credentials:"same-origin",headers:{}};
  if(method!=="GET"){
    opt.headers["Content-Type"]="application/json";
    opt.headers["X-NF-Work-Token"]=token;
    opt.body=JSON.stringify(body);
  }
  let reply;
  try{reply=await fetch(url,opt);}
  catch(_){throw new Error("Нет соединения с локальным Нейрозавод Work");}
  let value;
  try{value=await reply.json();}
  catch(_){throw new Error("Сервер вернул неожиданный ответ");}
  if(!reply.ok){throw new Error(value.error||"Операция не выполнена");}
  return value;
}
const el=(tag,cls,text)=>{
  const x=document.createElement(tag);
  if(cls)x.className=cls;
  if(text!==undefined)x.textContent=text;
  return x;
};
function notice(message,error=false){
  const t=$("toast");
  t.textContent=message;
  t.classList.toggle("error",error);
  t.classList.add("show");
  if(toastTimer)clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>t.classList.remove("show"),4300);
}
function formatDate(timestamp){
  return new Date(timestamp*1000).toLocaleString("ru-RU",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"});
}
function prettyState(s){
  return ({DRAFT:"Ожидает",GENERATING:"Генерация",REVIEW:"На проверке",
           UNKNOWN_NO_RETRY:"Неопределённо"})[s]||s;
}
function projectName(){
  return state.projects.find(x=>x.id===state.project)?.name||"Обзор";
}
function drawProjects(){
  const nav=$("project-list");nav.replaceChildren();
  for(const project of state.projects){
    const b=el("button","project-entry"+(state.project===project.id?" selected":""));
    b.type="button";
    const ico=el("span","project-symbol",project.kind==="web"?"⌘":project.kind==="python"?"Py":"◫");
    const txt=el("span","entry-name",project.name);
    b.append(ico,txt);
    b.addEventListener("click",()=>selectProject(project.id));
    nav.append(b);
  }
  if(!state.projects.length)nav.append(el("p","muted small","Создай первый проект"));
  $("projects-count").textContent=String(state.projects.length);
  $("stat-projects").textContent=String(state.projects.length);
}
function setTask(task){
  state.selectedTask=task?.id||null;
  $("selected-task-title").textContent=task?.title||"Пока нет задачи";
  $("selected-task-goal").textContent=task?.goal||"Создай задачу и выбери её, чтобы получить черновик Qwen.";
  $("draft-state").textContent=task?prettyState(task.state):"Нет черновика";
  $("draft-state").classList.toggle("ready",task?.state==="REVIEW");
  $("draft-output").textContent=task?.draft||
    (task?.state==="GENERATING"?"Qwen готовит ответ. Повторные запросы отключены.":
     task?.state==="UNKNOWN_NO_RETRY"?"Результат модели неопределённый. Автоматическая повторная генерация запрещена.":
      "Текст модели появится здесь. Он не будет автоматически сохраняться или выполняться.");
  $("generate").disabled=!task||task.state!=="DRAFT";
  $("copy-draft-editor").disabled=!task?.draft||!state.file;
  const btn=$("generate");
  btn.textContent=task?.state==="GENERATING"?"◌ Модель работает...":"✳ Подготовить черновик Qwen";
}
function drawTasks(){
  const list=$("tasks-list");list.replaceChildren();
  for(const task of state.tasks){
    const btn=el("button","task-item"+(state.selectedTask===task.id?" selected":""));
    btn.type="button";
    const ico=el("span","task-icon","✳");
    const main=el("span","task-main");
    main.append(el("strong",null,task.title),el("span","task-goal",task.goal));
    const stat=el("span","task-status"+(task.state==="REVIEW"?" review":task.state==="UNKNOWN_NO_RETRY"?" unknown":""),prettyState(task.state));
    btn.append(ico,main,stat);
    btn.addEventListener("click",()=>{
      state.selectedTask=task.id;
      drawTasks();
      setTask(task);
    });
    list.append(btn);
  }
  if(!state.tasks.length)
    list.append(el("div","empty",state.project?"Нажми «Задача», чтобы описать работу для Qwen.":"Сначала выбери проект."));
  const selected=state.tasks.find(x=>x.id===state.selectedTask)||state.tasks[0]||null;
  setTask(selected);
  $("stat-tasks").textContent=String(state.tasks.length);
}
function drawFiles(){
  const list=$("files-list");list.replaceChildren();
  for(const file of state.files){
    const btn=el("button","file-entry"+(state.file===file.path?" selected":""));
    btn.type="button";
    const name=el("span","file-name",file.path);
    btn.append(el("span","file-icon","▤"),name,el("span","file-bytes",file.size+" б"));
    btn.addEventListener("click",()=>openFile(file.path));
    list.append(btn);
  }
  if(!state.files.length)list.append(el("div","empty","Пока нет файлов"));
  $("project-path").textContent=state.project?
    "C:\\NeurofactoryProjects\\projects\\"+state.project:"Ещё не выбрана";
}
function changed(){return state.file!==null&&$("editor").value!==state.savedText;}
function updateEditor(){
  const active=state.file!==null;
  $("editor").disabled=!active;
  $("save-file").disabled=!active||!changed();
  $("undo-file").disabled=!active||!state.sha;
  $("editor-dirty").textContent=changed()?"● Не сохранено":"";
  $("editor-size").textContent=String($("editor").value.length)+" символов";
  $("editor-heading").textContent=state.file||"Редактор файла";
  $("editor-sha").textContent=!active?"Выбери файл, чтобы начать":state.sha?
     "Контрольная сумма: "+state.sha.slice(0,20)+"…":"Новый файл · ещё не записан";
  const task=state.tasks.find(x=>x.id===state.selectedTask);
  $("copy-draft-editor").disabled=!task?.draft||!active;
}
function discardOK(){
  return !changed()||window.confirm("Есть несохранённые правки. Отменить их?");
}
function clearEditor(){
  state.file=null;state.sha=null;state.savedText=null;
  $("editor").value="";updateEditor();
}
async function openFile(path){
  if(!discardOK())return;
  try{
    const obj=await api("/api/projects/"+state.project+"/file?path="+encodeURIComponent(path));
    state.file=obj.path;state.sha=obj.sha256;state.savedText=obj.text;
    $("editor").value=obj.text;
    updateEditor();drawFiles();
    $("editor-panel").scrollIntoView({behavior:"smooth",block:"nearest"});
  }catch(e){notice(e.message,true);}
}
async function refreshTasks(){
  if(!state.project)return;
  try{
    const obj=await api("/api/projects/"+state.project+"/tasks");
    state.tasks=obj.tasks;
    drawTasks();
  }catch(e){notice(e.message,true);}
}
async function refreshFiles(){
  if(!state.project)return;
  try{
    const obj=await api("/api/projects/"+state.project+"/files");
    state.files=obj.files;drawFiles();
  }catch(e){notice(e.message,true);}
}
async function selectProject(id){
  if(!discardOK())return;
  state.project=id;state.tasks=[];state.selectedTask=null;state.files=[];
  clearEditor();
  $("crumb-project").textContent=projectName();
  $("heading").textContent=projectName();
  $("description").textContent="Задачи, файлы и история проекта. Qwen готовит черновики, а сохранение файлов остаётся под твоим контролем.";
  $("new-task").disabled=false;$("new-file").disabled=false;
  $("agent-run").disabled=false;
  drawProjects();
  await Promise.all([refreshFiles(),refreshTasks(),browserStatus()]);
}
async function refreshActivity(){
  try{
    const events=(await api("/api/activity")).events;
    const list=$("activity-list");list.replaceChildren();
    for(const item of events.slice(0,12)){
      const c=el("div","activity-item");
      c.append(el("strong",null,({
        PROJECT_CREATED:"Проект создан",TASK_CREATED:"Задача добавлена",
        MODEL_ATTEMPT_RESERVED:"Qwen получила задачу",MODEL_DRAFT_READY:"Черновик Qwen готов",
        MODEL_RESULT_UNKNOWN:"Результат Qwen неопределённый",FILE_SAVED:"Файл сохранён"
      })[item.kind]||item.kind));
      let label="";
      try{const d=JSON.parse(item.detail);label=d.path||d.title||d.task?.slice(0,8)||"";}catch(_){}
      c.append(el("small",null,formatDate(item.created)+(label?" · "+label:"")));
      list.append(c);
    }
    if(!events.length)list.append(el("p","muted small","История появится после первого действия."));
  }catch(e){notice(e.message,true);}
}
async function refreshAll(){
  try{
    const [s,p]=await Promise.all([api("/api/status"),api("/api/projects")]);
    state.projects=p.projects;
    state.modelOk=!!s.qwen_available;
    $("model-label").textContent=s.qwen_available?"Qwen 3.5 · подключена":"Qwen · недоступна";
    $("model-dot").classList.toggle("good",!!s.qwen_available);
    drawProjects();
    const id=state.project&&state.projects.some(x=>x.id===state.project)?state.project:
              state.projects[0]?.id;
    if(id){state.project=null;await selectProject(id);}
    else{clearEditor();drawTasks();drawFiles();$("new-task").disabled=true;$("new-file").disabled=true;$("agent-run").disabled=true;}
    await refreshActivity();
  }catch(e){notice("Не удалось открыть Work: "+e.message,true);}
}
async function generate(){
  const task=state.tasks.find(x=>x.id===state.selectedTask);
  if(!task||task.state!=="DRAFT")return;
  if(!state.modelOk){notice("Qwen пока недоступна",true);return;}
  if(!window.confirm("Отправить задачу Qwen 3.5? Запрос одноразовый: при неопределённом результате автоматический повтор запрещён."))return;
  $("generate").disabled=true;
  try{
    await api("/api/tasks/"+task.id+"/generate","POST",{});
    notice("Qwen получила задачу. Результат появится в правой панели.");
    await Promise.all([refreshTasks(),refreshActivity()]);
  }catch(e){notice(e.message,true);await refreshTasks();}
}
function showDialog(id){
  $(id).showModal();
  const inp=$(id).querySelector("input");
  if(inp)inp.focus();
}
async function runSiteAudit(){
  if(!state.project){notice("Сначала выбери проект",true);return;}
  const urls=$("agent-urls").value.split(/[\\n,]+/).map(x=>x.trim()).filter(Boolean);
  if(urls.length<1||urls.length>4){notice("Укажи от 1 до 4 HTTPS-адресов",true);return;}
  const button=$("agent-run");
  button.disabled=true;
  $("agent-progress").textContent="Идёт проверка...";
  $("agent-results").textContent="Читаем только общедоступные страницы. Никакие формы не отправляются.";
  try{
    const report=await api("/api/agent/audits","POST",{project_id:state.project,urls});
    const lines=["Результат: "+report.state+" · "+report.id.slice(0,8)];
    for(const step of report.steps){
      lines.push("",step.target, "Статус: "+step.state);
      if(step.result){
        lines.push("Заголовок: "+(step.result.title||"не найден"));
        lines.push("Описание: "+(step.result.description||"отсутствует"));
        lines.push("Robots: "+(step.result.robots||step.result.x_robots_tag||"не найден"));
        lines.push("H1: "+step.result.h1.join(" | "));
        lines.push("Формы: "+step.result.form_count+"; ссылки: "+step.result.link_count);
        lines.push("Замечания: "+(step.result.warnings.join(", ")||"не обнаружено при базовой проверке"));
        for(const form of step.result.forms){
          lines.push("  Форма "+(form.id||"без имени")+": "+(form.hidden?"скрыта":"видима")+
            ", метод "+form.method+", полей "+form.fields.length);
        }
      }else{lines.push("Причина: "+(step.error||"неизвестна"));}
    }
    $("agent-results").textContent=lines.join("\n");
    await refreshActivity();
  }catch(e){
    $("agent-results").textContent="Проверка не выполнена: "+e.message;
    notice(e.message,true);
  }finally{
    $("agent-progress").textContent="";
    button.disabled=!state.project;
  }
}
function browserButtons(){
  const hasProject=!!state.project;
  const active=browserState.session&&browserState.project===state.project;
  $("browser-open").disabled=!hasProject||!browserState.configured||!!active||browserState.busy;
  $("browser-controls").hidden=!active;
  $("browser-screen").hidden=!active;
  $("browser-close").disabled=!active||browserState.busy;
  if(!active){
    $("browser-page-title").textContent="";
    $("browser-frame").removeAttribute("src");
    $("browser-cursor").hidden=true;
  }
}
async function browserStatus(){
  if(!state.project){
    browserState.session=null;browserState.project=null;browserButtons();
    $("browser-status").textContent="Выбери проект, чтобы открыть разрешённый сайт.";
    return;
  }
  try{
    const result=await api("/api/browser/status?project_id="+state.project);
    browserState.configured=!!result.configured;
    browserState.session=result.session?.id||null;
    browserState.project=state.project;
    const hosts=result.allowed_hosts||[];
    $("browser-status").textContent=result.configured?
      "Разрешённые сайты: "+hosts.join(", ")+". Клики управляют только веб-страницей.":
      "Браузер не настроен: для запуска необходим Chromium и явный список разрешённых сайтов.";
    browserButtons();
    if(browserState.session){
      try{
        const page=await browserAction("frame");
        showBrowserFrame(page);
      }catch(e){notice(e.message,true);}
    }
  }catch(e){browserState.configured=false;browserButtons();$("browser-status").textContent=e.message;}
}
function browserTargets(items){
  const root=$("browser-targets");
  root.replaceChildren();
  const targets=Array.isArray(items)?items:[];
  root.hidden=!targets.length;
  if(!targets.length)return;
  root.append(el("strong",null,"Видимые кнопки и ссылки"));
  for(const entry of targets.slice(0,35)){
    const button=el("button","button soft small",entry.label);
    button.type="button";
    button.disabled=!!entry.protected||browserState.busy;
    button.title=entry.protected?"Кнопка формы: действие заблокировано":entry.kind;
    button.addEventListener("click",()=>invokeBrowser("click",{x:entry.x,y:entry.y}));
    root.append(button);
  }
}
function showBrowserFrame(result){
  const image=result?.frame?.image;
  if(image&&/^[A-Za-z0-9+/=]+$/.test(image)&&image.length<=850000){
    $("browser-frame").src="data:image/jpeg;base64,"+image;
    $("browser-screen").hidden=false;
  }
  const info=result?.frame;
  if(info)$("browser-page-title").textContent=(info.title||"Без названия")+" · "+(info.url||"");
}
async function openBrowser(){
  if(!state.project||!browserState.configured||browserState.busy)return;
  const url=$("browser-address").value.trim();
  if(!url.startsWith("https://")){notice("Только HTTPS-адреса",true);return;}
  if(!window.confirm("Открыть этот сайт в изолированном браузере?\n"+url+
    "\nСессия не имеет доступа к файлам компьютера. Отправка форм запрещена."))return;
  browserState.busy=true;browserButtons();
  $("browser-status").textContent="Запуск изолированного браузера...";
  try{
    const reply=await api("/api/browser/open","POST",{project_id:state.project,url});
    browserState.session=reply.session_id;
    browserState.project=state.project;
    showBrowserFrame(reply);
    browserTargets([]);
    $("browser-status").textContent="Браузер открыт. Мышью можно наводить и нажимать разрешённые кнопки.";
    await refreshActivity();
  }catch(e){
    $("browser-status").textContent="Не удалось открыть браузер: "+e.message;
    notice(e.message,true);
  }finally{browserState.busy=false;browserButtons();}
}
async function browserAction(op,options={}){
  if(!browserState.session||state.project!==browserState.project)
    throw new Error("Нет активной сессии браузера.");
  return await api("/api/browser/action","POST",{
    project_id:state.project,session_id:browserState.session,op,...options
  });
}
async function invokeBrowser(op,options={}){
  if(!browserState.session||browserState.busy)return;
  browserState.busy=true;browserButtons();
  try{
    const reply=await browserAction(op,options);
    showBrowserFrame(reply);
    if(op==="inspect")browserTargets(reply.frame?.targets);
    else if(op!=="move")browserTargets([]);
    if(op!=="move")await refreshActivity();
  }catch(e){
    notice("Браузер: "+e.message,true);
    $("browser-status").textContent="Действие отклонено: "+e.message;
    if(/UNKNOWN|STOPPED|EXPIRED|SESSION/.test(e.message)){
      browserState.session=null;
    }
  }finally{browserState.busy=false;browserButtons();}
}
function browserCoordinates(event){
  const rect=$("browser-frame").getBoundingClientRect();
  if(!rect.width||!rect.height)return null;
  const x=Math.floor((event.clientX-rect.left)*1100/rect.width);
  const y=Math.floor((event.clientY-rect.top)*720/rect.height);
  if(x<0||y<0||x>=1100||y>=720)return null;
  $("browser-cursor").hidden=false;
  $("browser-cursor").style.left=(event.clientX-rect.left)+"px";
  $("browser-cursor").style.top=(event.clientY-rect.top)+"px";
  return {x,y};
}
function bindBrowser(){
  $("browser-open").addEventListener("click",openBrowser);
  $("browser-close").addEventListener("click",async()=>{
    if(!browserState.session||browserState.busy)return;
    browserState.busy=true;
    try{
      await api("/api/browser/close","POST",
        {project_id:state.project,session_id:browserState.session});
      browserState.session=null;
      browserTargets([]);
      $("browser-status").textContent="Сессия браузера закрыта. Куки не сохраняются.";
      await refreshActivity();
    }catch(e){notice(e.message,true);}
    finally{browserState.busy=false;browserButtons();}
  });
  for(const el of document.querySelectorAll("[data-browser-command]")){
    el.addEventListener("click",()=>{
      const op=el.dataset.browserCommand;
      if(op==="scroll_up")invokeBrowser("scroll",{delta:-560});
      else if(op==="scroll_down")invokeBrowser("scroll",{delta:560});
      else invokeBrowser(op);
    });
  }
  $("browser-frame").addEventListener("click",async event=>{
    const point=browserCoordinates(event);
    if(point)await invokeBrowser("click",point);
  });
  $("browser-frame").addEventListener("pointermove",async event=>{
    const point=browserCoordinates(event);
    const now=Date.now();
    if(!point||browserState.moveBusy||browserState.busy||now-browserState.lastMove<300
       ||!browserState.session)return;
    browserState.lastMove=now;
    browserState.moveBusy=true;
    try{await browserAction("move",point);}
    catch(e){if(/UNKNOWN|STOPPED|EXPIRED|SESSION/.test(e.message)){
      browserState.session=null;browserButtons();}}
    finally{browserState.moveBusy=false;}
  });
  $("browser-frame").addEventListener("pointerleave",()=>{$("browser-cursor").hidden=true;});
}
function bind(){
  bindBrowser();
  $("agent-run").addEventListener("click",runSiteAudit);
  for(const id of ["new-project-side","top-new-project"])
    $(id).addEventListener("click",()=>showDialog("project-dialog"));
  $("new-task").addEventListener("click",()=>{
    if(!state.project){notice("Сначала создай проект",true);return;}
    showDialog("task-dialog");
  });
  $("new-file").addEventListener("click",()=>{
    if(!state.project){notice("Сначала выбери проект",true);return;}
    showDialog("file-dialog");
  });
  for(const x of document.querySelectorAll("[data-close]"))
    x.addEventListener("click",()=>$(x.dataset.close).close());
  $("project-form").addEventListener("submit",async event=>{
    event.preventDefault();
    try{
      const p=await api("/api/projects","POST",{
        name:$("project-name").value,template:$("project-kind").value
      });
      $("project-dialog").close();
      $("project-form").reset();
      state.projects=(await api("/api/projects")).projects;
      state.project=null;await selectProject(p.id);
      await refreshActivity();
      notice("Проект создан в изолированной папке");
    }catch(e){notice(e.message,true);}
  });
  $("task-form").addEventListener("submit",async event=>{
    event.preventDefault();
    try{
      const p=await api("/api/projects/"+state.project+"/tasks","POST",{
        title:$("task-title").value,goal:$("task-goal").value
      });
      $("task-dialog").close();$("task-form").reset();
      state.selectedTask=p.id;
      await Promise.all([refreshTasks(),refreshActivity()]);
      notice("Задача сохранена. Можно запросить черновик Qwen.");
    }catch(e){notice(e.message,true);}
  });
  $("file-form").addEventListener("submit",event=>{
    event.preventDefault();
    if(!discardOK())return;
    state.file=$("file-name").value.trim();
    state.sha=null;state.savedText="";
    $("editor").value="";
    $("file-dialog").close();
    $("file-form").reset();
    updateEditor();$("save-file").disabled=false;
    $("editor").focus();
    notice("Новый файл открыт в редакторе. Он будет создан только после сохранения.");
  });
  $("editor").addEventListener("input",updateEditor);
  $("save-file").addEventListener("click",async()=>{
    if(!state.project||!state.file)return;
    if(!window.confirm("Сохранить эту версию файла внутри рабочего проекта?"))return;
    try{
      const p=await api("/api/projects/"+state.project+"/file","PUT",{
        path:state.file,text:$("editor").value,previous_sha:state.sha
      });
      state.sha=p.sha256;state.savedText=$("editor").value;
      updateEditor();await Promise.all([refreshFiles(),refreshActivity()]);
      notice("Файл сохранён с проверкой SHA-256");
    }catch(e){notice("Сохранение отклонено: "+e.message,true);}
  });
  $("undo-file").addEventListener("click",async()=>{
    if(!state.project||!state.file||!state.sha)return;
    if(!window.confirm("Вернуть предыдущую сохранённую версию файла?"))return;
    const path=state.file;
    try{
      await api("/api/projects/"+state.project+"/undo","POST",{
        path,sha256:state.sha
      });
      state.savedText=$("editor").value;await openFile(path);
      await refreshActivity();notice("Предыдущая версия восстановлена");
    }catch(e){notice(e.message,true);}
  });
  $("generate").addEventListener("click",generate);
  $("copy-draft-editor").addEventListener("click",()=>{
    const task=state.tasks.find(x=>x.id===state.selectedTask);
    if(!task?.draft||!state.file)return;
    if(!window.confirm("Перенести текст Qwen в редактор? Файл не будет сохранён автоматически."))return;
    $("editor").value=task.draft;updateEditor();
    $("editor-panel").scrollIntoView({behavior:"smooth",block:"nearest"});
    notice("Черновик вставлен в редактор. Для записи нажми «Сохранить правку».");
  });
  $("refresh").addEventListener("click",async()=>{
    await Promise.all([refreshTasks(),refreshFiles(),refreshActivity()]);
    notice("Данные обновлены");
  });
  $("all-projects").addEventListener("click",()=>{
    if(!discardOK())return;
    state.project=null;state.selectedTask=null;state.tasks=[];state.files=[];
    clearEditor();drawTasks();drawFiles();drawProjects();
    $("heading").textContent="Твоя мастерская ИИ";
    $("crumb-project").textContent="Обзор";
    $("description").textContent="Создавай проекты и управляй задачами в одном месте.";
    $("new-task").disabled=true;$("new-file").disabled=true;
    browserState.session=null;browserState.project=null;browserButtons();
  });
}
async function poll(){
  if(!state.project||!state.tasks.some(x=>x.state==="GENERATING"))return;
  await Promise.all([refreshTasks(),refreshActivity()]);
}
bind();refreshAll();
setInterval(poll,4500);
