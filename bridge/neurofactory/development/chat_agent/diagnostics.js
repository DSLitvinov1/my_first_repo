/* Local read-only status. Never expose a chat URL, token or entered message. */
const labels={
 BOUND:"Беседа выбрана",NOT_BOUND:"Беседа ещё не привязана",DISABLED:"Агент выключен",
 WRONG_PAGE:"Открыта не беседа ChatGPT",COOLDOWN:"Ожидание следующей проверки",
 FETCHING:"Получение задания из GitHub",FETCH_ERROR:"Ошибка получения задания из GitHub",
 REJECTED_OUTBOX:"Полученное задание не прошло проверку",
 ALREADY_ATTEMPTED:"Это задание уже обрабатывалось",
 BOUND_TAB_NOT_FOUND:"Вкладка выбранной беседы не найдена",
 PROMPT_TOO_LONG:"Сообщение слишком длинное",AWAITING_CHAT:"Передача сообщения в выбранный чат",
 COMPOSER_BUSY:"Поле ввода занято или ChatGPT отвечает",SEEN:"Новое сообщение замечено в чате",
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
}
document.getElementById("refresh").addEventListener("click",()=>refresh().catch(()=>{
 document.getElementById("status").textContent="Ошибка чтения локального состояния";
}));
refresh().catch(()=>{document.getElementById("status").textContent="Диагностика недоступна";});
