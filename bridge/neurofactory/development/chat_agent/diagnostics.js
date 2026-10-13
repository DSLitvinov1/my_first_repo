/* Local read-only status. Never expose a chat URL, token or entered message. */
const labels={
 BOUND:"Беседа выбрана",NOT_BOUND:"Беседа ещё не привязана",DISABLED:"Агент выключен",
 WRONG_PAGE:"Открыта не беседа ChatGPT",COOLDOWN:"Ожидание следующей проверки",
 FETCHING:"Получение задания из GitHub",FETCH_ERROR:"Ошибка получения задания из GitHub",
 REJECTED_OUTBOX:"Полученное задание не прошло проверку",
 ALREADY_ATTEMPTED:"Это задание уже обрабатывалось",
 BOUND_TAB_NOT_FOUND:"Не найдена вкладка ранее выбранной беседы. Проверь её адрес",
 CHAT_REFRESH_REQUIRED:"Открой выбранный чат и обнови вкладку клавишей F5",
 SAFE_RETRY_READY:"Безопасное восстановление после отсутствия обработчика вкладки",
 PROMPT_TOO_LONG:"Сообщение слишком длинное",AWAITING_CHAT:"Передача сообщения в выбранный чат",
 COMPOSER_NOT_FOUND:"Расширение не находит поле ввода ChatGPT — проверь версию агента",
 PENDING_ATTACHMENTS:"В поле ввода прикреплены файлы или изображения — агент не будет отправлять их",
 COMPOSER_BUSY:"Поле ввода содержит пользовательский текст, занято или ChatGPT отвечает",
 SEEN:"Новое сообщение замечено в чате",
 UNCONFIRMED:"Подтверждения отправки нет",BRIDGE_ERROR:"Ошибка связи со вкладкой"
};
const statuses={observed:"Появилось в беседе",unconfirmed:"Не подтверждено: автоповтор запрещён",
 attempted:"Попытка начата: повтор запрещён",submitted:"Нажата отправка: требуется подтверждение"};
async function refresh(){
 const data=await chrome.storage.local.get(["chatUrl","enabled","nfDiagnostic","attempted"]);
 document.getElementById("bound").textContent=data.enabled&&data.chatUrl?
 "Включена, выбрана одна беседа":data.chatUrl?"Отключена":"Не настроена";
 const diagnostic=data.nfDiagnostic||{};
 document.getElementById("status").textContent=labels[diagnostic.code]||"Ожидание первой проверки";
 document.getElementById("detail").textContent=diagnostic.detail||"—";
 document.getElementById("time").textContent=diagnostic.at?
 new Date(diagnostic.at).toLocaleString("ru-RU"):"—";
 const attempts=Object.values(data.attempted||{});
 const previous=attempts.length?attempts[attempts.length-1]:null;
 document.getElementById("attempt").textContent=previous?
 statuses[previous.state]||"Предыдущая попытка": "Попыток пока нет";
 document.getElementById("attemptReason").textContent=previous?
 (previous.reason||previous.error||"Старая версия не сохранила причину попытки"):"—";
}
function conversationKey(url){
 const clean=String(url||"").split(/[?#]/)[0].replace(/\\/+$/,"");
 return /^https:\\/\\/chatgpt\\.com\\/(?:g\\/[^/]+\\/)?c\\/[A-Za-z0-9-]+$/.test(clean)?clean:"";
}
async function inspectCurrentReceipt(){
 const result=document.getElementById("receiptCheck");
 result.textContent="Проверка без отправки…";
 const data=await chrome.storage.local.get(["chatUrl","enabled","attempted"]);
 const records=Object.entries(data.attempted||{}).filter(([key,value])=>
   /^[a-f0-9]{24}$/.test(key)&&value&&typeof value==="object");
 const last=records.sort((a,b)=>(b[1].at||0)-(a[1].at||0))[0];
 if(!last){result.textContent="Попыток для проверки не обнаружено";return;}
 const expected=conversationKey(data.chatUrl);
 if(!data.enabled||!expected){result.textContent="Сначала привяжи и включи выбранную беседу";return;}
 const tabs=await chrome.tabs.query({});
 const tab=tabs.find(t=>conversationKey(t.url)===expected&&t.id!==undefined);
 if(!tab){result.textContent="Выбранная беседа сейчас не открыта";return;}
 try{
   const reply=await chrome.tabs.sendMessage(tab.id,
      {type:"NF_INSPECT_DELIVERY",boundUrl:data.chatUrl,sequence:last[0]});
   if(!reply?.ready){result.textContent="Не удалось проверить эту беседу";return;}
   result.textContent=reply.found?
      "Контрольная фраза найдена в этой беседе ("+reply.matchCount+"). Требуется проверка происхождения":
      "Контрольная фраза не найдена в этой беседе. Повторная отправка по-прежнему запрещена";
 }catch(error){
   result.textContent="Связь с вкладкой не установлена. Обнови беседу клавишей F5";
 }
}
document.getElementById("inspect").addEventListener("click",()=>inspectCurrentReceipt().catch(()=>{
 document.getElementById("receiptCheck").textContent="Проверка недоступна, повтор не выполнялся";
}));
document.getElementById("refresh").addEventListener("click",()=>refresh().catch(()=>{
 document.getElementById("status").textContent="Ошибка чтения локального состояния";
}));
refresh().catch(()=>{document.getElementById("status").textContent="Диагностика недоступна";});
