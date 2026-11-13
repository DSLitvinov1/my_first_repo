"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const {KeyboardSession,validateText,validateMode,validKey,inspectInputs}
  =require("./browser_typing.cjs");
const puppeteer=require("puppeteer-core");

test("keyboard text and key validation rejects unsafe commands",()=>{
  for(const t of ["", "a".repeat(2001), "\u0000", "hello\tworld",
                   "\u001b[31m"]){
    assert.throws(()=>validateText(t),/BROWSER_TEXT_INVALID/);
  }
  assert.equal(validateText("Задача: проверить карточку клиента"),"Задача: проверить карточку клиента");
  for(const m of ["auto","submit", "", 42])assert.throws(()=>validateMode(m));
  assert.equal(validKey("Tab"),"Tab");
  for(const k of ["Enter","Control+Enter","Control+A","Meta+V","F5","Delete","Escape+Enter"]){
    assert.throws(()=>validKey(k),/BROWSER_KEY_REFUSED/);
  }
});

test("real Chromium owner keyboard: title, description, safe field constraints",{skip:!process.env.NF_TEST_CHROMIUM},
  async()=>{
    const browser=await puppeteer.launch({
      executablePath:process.env.NF_TEST_CHROMIUM,headless:true,
      args:["--disable-dev-shm-usage"],
    });
    try{
      const page=await browser.newPage();
      await page.setViewport({width:1100,height:720});
      await page.setContent('<!doctype html><html><body>'+
        '<form id="task" style="padding:22px;">'+
          '<label for="title">Название задачи</label><input type="text" id="title" name="title" maxlength="80" placeholder="Название" style="width:410px;height:38px;display:block">'+
          '<label for="description">Описание задачи</label><textarea id="description" name="description" style="width:500px;height:160px;display:block"></textarea>'+
          '<label>Пароль<input id="password" name="password" type="password" style="width:500px;height:36px;display:block"></label>'+
          '<label>Номер карты<input name="card_number" id="card" style="width:500px;height:36px;display:block"></label>'+
          '<button id="send" type="submit">Создать задачу</button></form>'+
          '<div contenteditable="true" role="textbox" aria-label="Примечание" id="note" style="min-height:40px;border:1px solid black"></div>'+
          '<script>window.sent=0;document.querySelector("#task").addEventListener("submit",e=>{e.preventDefault();window.sent++;})</script>'+
          '</body></html>');
      const k=new KeyboardSession(page);
      const xyp=async id=>page.$eval(id,x=>{const r=x.getBoundingClientRect();return {
        x:Math.floor(r.x+r.width/2),y:Math.floor(r.y+r.height/2)};
      });
      const listed=await inspectInputs(page);
      assert(listed.some(x=>x.label==="Название задачи"));
      assert(listed.some(x=>x.label==="Описание задачи"));
      assert(!listed.some(x=>x.label.includes("Парол")));
      assert(!listed.some(x=>x.label.toLowerCase().includes("карт")));
      const title=await xyp("#title");
      assert.equal((await k.focus(title.x,title.y)).focused,true);
      const result=await k.type("Позвонить клиенту по договору","replace");
      assert.equal(result.typed,true);
      assert(!JSON.stringify(result).includes("Позвонить"));
      assert.equal(await page.$eval("#title",e=>e.value),"Позвонить клиенту по договору");
      await k.type(" — срочно","append");
      assert.equal(await page.$eval("#title",e=>e.value),"Позвонить клиенту по договору — срочно");
      await assert.rejects(()=>k.type("строка\nдва","replace"),/NEWLINE_REFUSED/);
      await assert.rejects(()=>k.type("X".repeat(81),"replace"),/LIMIT_OR_NEWLINE/);
      const description=await xyp("#description");
      await k.fill(description.x,description.y,
                   "Проверить карточку клиента.\nСоздать напоминание.", "replace");
      assert.equal(await page.$eval("#description",e=>e.value),
                   "Проверить карточку клиента.\nСоздать напоминание.");
      await k.press("Tab");
      await assert.rejects(()=>k.type("нет","append"),/NOT_SELECTED/);
      const note=await xyp("#note");
      await k.fill(note.x,note.y,"Внутренняя заметка к задаче","replace");
      assert.equal(await page.$eval("#note",e=>e.textContent),
                   "Внутренняя заметка к задаче");
      for(const selector of ["#password","#card"]){
        const xy=await xyp(selector);
        await assert.rejects(()=>k.focus(xy.x,xy.y),/EDITABLE_FIELD_REQUIRED/);
      }
      assert.equal(await page.evaluate(()=>window.sent),0);
    }finally{await browser.close();}
  }
);
