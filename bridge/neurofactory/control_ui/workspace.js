"use strict";
/* Integration-only live draft workspace. All task execution remains disabled. */
(() => {
  const nav=document.getElementById("navigation");
  const main=document.getElementById("main-content");
  if(!nav||!main)return;
  const button=document.createElement("button");
  button.type="button";button.className="nav-link";button.dataset.route="workspace";
  const glyph=document.createElement("span");glyph.className="glyph";glyph.textContent="▣";
  const label=document.createElement("span");label.textContent="Локальная база";
  button.append(glyph,label);
  nav.append(button);
  let csrf=null;
  function el(tag,text,cls){
    const x=document.createElement(tag);
    if(cls)x.className=cls;
    if(text!==undefined)x.textContent=String(text);
    return x;
  }
  function append(parent,...children){parent.append(...children);return parent;}
  function box(title,description){
    const e=el("section",undefined,"card");
    const head=el("div",undefined,"card-head");
    append(head,el("h2",title));
    if(description)append(head,el("small",description));
    append(e,head);append(main,e);return e;
  }
  function field(form,title,type,max,placeholder){
    const wrapper=el("div",undefined,"field");
    const label=el("label",title);
    const input=el(type==="textarea"?"textarea":"input");
    if(type!=="textarea")input.type=type;
    input.maxLength=max;
    input.placeholder=placeholder;
    input.required=true;
    label.append(input);wrapper.append(label);form.append(wrapper);
    return input;
  }
  function status(message,error=false){
    const div=el("p",message,error?"tag":"muted-small");
    div.setAttribute("role","status");main.prepend(div);
  }
  async function request(path,body){
    if(!csrf){
      const response=await fetch("/api/bootstrap",{cache:"no-store"});
      if(!response.ok)throw Error("Локальная база не запущена");
      const data=await response.json();
      if(data.mode!=="LOCAL_DRAFT_ONLY"||data.live_execution_allowed!==false)throw Error("Неверный безопасный режим");
      csrf=data.csrf_token;
    }
    const options={cache:"no-store"};
    if(body!==undefined){
      options.method="POST";options.headers={
        "Content-Type":"application/json",
        "X-NF-Local-Token":csrf
      };
      options.body=JSON.stringify(body);
    }
    const response=await fetch(path,options);
    if(!response.ok)throw Error("Локальная операция отклонена ("+response.status+")");
    return response.json();
  }
  function row(parent,headline,detail){
    const r=el("div",undefined,"item-row");
    const meta=el("div",undefined,"left-meta");
    const words=el("div");
    append(words,el("div",headline,"item-title"),el("div",detail,"item-meta"));
    append(meta,words);append(r,meta);parent.append(r);
  }
  async function render(){
    main.replaceChildren();
    nav.querySelectorAll("button").forEach(b=>{
      b.classList.toggle("active",b===button);
      if(b===button)b.setAttribute("aria-current","page");
      else b.removeAttribute("aria-current");
    });
    const title=el("div",undefined,"headline");
    const inner=el("div");
    append(inner,el("p","НЕЙРОЗАВОД / ЛОКАЛЬНЫЕ ДАННЫЕ","eyebrow"),
          el("h1","Рабочая база проектов"),
          el("p","Настоящее сохранение SQLite на этом ПК. Запуск ИИ и запись файлов пока запрещены.","subhead"));
    title.append(inner);main.append(title);
    const warning=el("div",undefined,"warning-strip");
    append(warning,el("strong","Безопасный локальный режим: задания сохраняются, но НЕ отправляются в исполнительную очередь."));
    main.append(warning);
    try{
      const [projects,tasks,history,health,models,checks,core]=await Promise.all([
        request("/api/projects"),request("/api/tasks"),
        request("/api/history"),request("/api/status"),request("/api/models"),request("/api/model-checks"),
        request("/api/core/status").catch(()=>({configured:true,available:false,reported_state:"UNAVAILABLE"}))
      ]);
      const summary=box("Реальное состояние","Данные непосредственно из локального сервера");
      const metrics=el("div",undefined,"metric-grid");
      for(const [name,value] of [
        ["Проекты",health.projects],["Задания",health.tasks],
        ["SQLite",health.database_connected?"РАБОТАЕТ":"ОШИБКА"],
        ["Очередь ИИ","ЗАКРЫТА"]]){
        const metric=el("div",undefined,"metric");
        append(metric,el("small",name),el("strong",value));
        metrics.append(metric);
      }
      summary.append(metrics);
      const coreBox=box("CORE — только чтение","Локальная SQLite-очередь, не является независимой аттестацией и не разрешает выполнение");
      if(core.available && core.task){
        const labels={
          QUEUED:"В очереди",CLAIMED:"Выдано исполнителю",
          APPLYING:"Применяется (учебный режим)",
          CHECKPOINTED_TEST:"Учебная контрольная точка",
          HOST_CHECKPOINTED_TEST:"Учебный результат HOST",
          NEEDS_MANUAL_REVIEW:"Нужна ручная проверка"
        };
        row(coreBox,"CORE: "+(labels[core.reported_state]||"Неизвестное состояние"),
          core.task.task_id+" · проект "+core.task.project_id+
          " · "+core.task.model+" · попыток: "+core.task.attempts);
      }else if(core.available){
        row(coreBox,"CORE: очередь пуста","Подключено явное локальное состояние, заданий пока нет");
      }else if(core.configured){
        row(coreBox,"CORE: данные недоступны","Доступ или целостность локального состояния не подтверждены — работа заблокирована");
      }else{
        row(coreBox,"CORE не подключён","Только просмотр после явной настройки каталога состояния; новые задания остаются черновиками");
      }
      row(coreBox,"Полномочия","Чтение без исполнения. Проверка подписи HOST и независимая приёмка здесь НЕ производятся.");
      row(summary,"Ollama",models.ollama_reachable?"Доступен локальный интерфейс. Настоящая генерация не проверена.":"Локальный сервер модели недоступен");
      if(models.installed_qwen.length)row(summary,"Установленные Qwen",models.installed_qwen.join(", "));
      const probeBox=box("Проверка локальной Qwen","Только явный запрос к установленной модели; никаких операций с файлами или очередью");
      row(probeBox,"Происхождение модели","Ответ Ollama не доказывает подлинность весов Qwen. Подтверждение защищённого HOST не выдаётся.");
      const probe=el("button","Проверить реальный ответ локальной модели","outline-btn");
      probe.type="button";probe.disabled=!models.installed_qwen.length;
      probe.addEventListener("click",async()=>{
        probe.disabled=true;
        try{
          const result=await request("/api/model-probe",{model_preference:"auto"});
          status("Ollama ответил: "+result.reported_model+" · SHA-256: "+result.response_sha256.slice(0,16)+"… · "+result.response_excerpt);
          const all=await request("/api/model-checks");
          row(probeBox,"Проверок сохранено",String(all.checks.length)+" (показываются последние 20)");
        }catch(error){status(error.message||"Локальная модель недоступна",true);}
        finally{probe.disabled=false;}
      });
      probeBox.append(probe);
      for(const item of checks.checks.slice(0,5)){
        row(probeBox,item.reported_model,item.checked_utc+" · SHA-256: "+item.response_sha256.slice(0,16)+"… · происхождение не аттестовано");
      }

      const projectBox=box("Мои проекты","Постоянные записи");
      for(const p of projects.projects)row(projectBox,p.name,p.description||p.id);
      if(!projects.projects.length)row(projectBox,"Проектов нет","Создайте первый проект.");
      const form=el("form");form.className="form-card";
      const name=field(form,"Название нового проекта","text",80,"Например, Юридический сайт");
      const description=field(form,"Описание","textarea",400,"Цель проекта");
      const save=el("button","Создать проект","primary-btn");save.type="submit";form.append(save);
      form.addEventListener("submit",async event=>{
        event.preventDefault();save.disabled=true;
        try{await request("/api/projects",{name:name.value.trim(),description:description.value.trim()});await render();}
        catch(err){status(err.message,true);save.disabled=false;}
      });
      projectBox.append(form);
      const taskBox=box("Новые задания","Сохраняются как черновики без запуска");
      for(const t of tasks.tasks){
        row(taskBox,t.objective.slice(0,85),
          "Проект: "+t.project_id.slice(0,10)+" · "+t.model_preference+" · Ожидает разрешения");
        const prep=el("button","Подготовить запрос на допуск CORE","outline-btn");
        prep.type="button";
        prep.addEventListener("click",async()=>{
          prep.disabled=true;
          try{
            const requestData=await request("/api/tasks/"+t.id+"/admission-request");
            if(requestData.schema!=="nf.onepc.draft_admission_request.v1" ||
                requestData.owner_signed!==false ||
                requestData.queue_mutation_allowed!==false ||
                requestData.execution_allowed!==false ||
                requestData.draft_id!==t.id){
              throw Error("Недостоверный запрос на допуск");
            }
            status("Запрос подготовлен. ID: "+requestData.draft_id+
                   " · SHA-256: "+requestData.draft_sha256+
                   ". Задание остаётся черновиком. Только отдельный защищённый механизм владельца может подписать допуск.");
          }catch(err){
            status("Допуск не подготовлен: "+(err.message||"проверьте ограничения задания"),true);
          }finally{prep.disabled=false;}
        });
        taskBox.append(prep);
      }
      if(projects.projects.length){
        const taskForm=el("form");taskForm.className="form-card";
        const picker=el("select");picker.required=true;
        for(const p of projects.projects){
          const opt=el("option",p.name);
          opt.value=p.id;picker.append(opt);
        }
        const projectField=el("div",undefined,"field");
        append(projectField,el("label","Проект"),picker);taskForm.append(projectField);
        const objective=field(taskForm,"Задание для ИИ","textarea",1200,
          "Опишите, что нужно сделать; без автоматического выполнения");
        const modelField=el("div",undefined,"field");
        const modelChoice=el("select");
        for(const [value,label] of [
          ["auto","Автоматический выбор"],
          ["qwen3:0.6b","Qwen3 0.6B"],
          ["qwen2.5-coder:1.5b","Qwen Coder 1.5B"]]){
          const option=el("option",label);option.value=value;modelChoice.append(option);
        }
        append(modelField,el("label","Предпочитаемый ИИ"),modelChoice);
        taskForm.append(modelField);
        const taskButton=el("button","Сохранить задание","primary-btn");
        taskButton.type="submit";taskForm.append(taskButton);
        taskForm.addEventListener("submit",async event=>{
          event.preventDefault();taskButton.disabled=true;
          try{
            await request("/api/tasks",{project_id:picker.value,objective:objective.value,
                                        model_preference:modelChoice.value});
            await render();
          }catch(err){status(err.message,true);taskButton.disabled=false;}
        });
        taskBox.append(taskForm);
      }else{
        row(taskBox,"Сначала создайте проект","Задания без проекта отклоняются сервером.");
      }
      const historyBox=box("История изменений","Реальная история локальной базы");
      for(const h of history.history.slice(0,20))row(historyBox,h.event,h.event_utc+" · "+h.record_id.slice(0,12));
      if(!history.history.length)row(historyBox,"История пустая","События появятся после создания проектов.");
      const backupBox=box("Резервные копии","Создаёт согласованную копию SQLite; данные не отправляются в облако");
      const backup=el("button","Создать резервную копию","outline-btn");
      backup.type="button";backup.addEventListener("click",async()=>{
        backup.disabled=true;
        try{const result=await request("/api/backup",{});status("Резервная копия сохранена: "+result.filename);}
        catch(err){status(err.message,true);}finally{backup.disabled=false;}
      });
      backupBox.append(backup);
    }catch(error){status(error.message||"Локальный сервер недоступен",true);}
  }
  button.addEventListener("click",render);
})();
