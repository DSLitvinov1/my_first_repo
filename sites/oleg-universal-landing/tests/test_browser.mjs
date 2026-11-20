import { spawn } from "node:child_process";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "..");
const chromium = process.env.CHROME_BIN || "/usr/bin/chromium";
const profile = mkdtempSync(path.join(os.tmpdir(), "oleg-landing-browser-"));
const appPort = 18145, debugPort = 18146;
let php, chrome, ws;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitUrl(url, tries = 50) {
    for (let i = 0; i < tries; i++) {
        try { const r = await fetch(url); if (r.ok) return r.json(); } catch {}
        await sleep(100);
    }
    throw new Error("Browser server did not start: "+url);
}
try {
    assert(existsSync(chromium), "Chrome binary missing");
    php = spawn("php", ["-S", "127.0.0.1:"+appPort, "-t", root], {stdio:"ignore"});
    chrome = spawn(chromium, [
        "--headless","--no-sandbox","--disable-gpu","--disable-dev-shm-usage",
        "--remote-allow-origins=*","--remote-debugging-port="+debugPort,
        "--user-data-dir="+profile,"about:blank"
    ], {stdio:"ignore"});
    await waitUrl("http://127.0.0.1:"+debugPort+"/json/version");
    const created = await fetch("http://127.0.0.1:"+debugPort+"/json/new?about:blank", {method:"PUT"}).then(r=>r.json());
    ws = new WebSocket(created.webSocketDebuggerUrl);
    await new Promise((resolve,reject) => { ws.onopen=resolve; ws.onerror=reject; });
    let serial = 0;
    const pending = new Map();
    ws.onmessage = ev => {
        const packet=JSON.parse(ev.data);
        if (!packet.id || !pending.has(packet.id)) return;
        const {resolve,reject}=pending.get(packet.id); pending.delete(packet.id);
        if(packet.error)reject(new Error(packet.error.message)); else resolve(packet.result);
    };
    async function call(method,params={}) {
        const id=++serial;
        return new Promise((resolve,reject)=>{
            pending.set(id,{resolve,reject}); ws.send(JSON.stringify({id,method,params}));
        });
    }
    async function evaluate(expression) {
        const result=await call("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true});
        if(result.exceptionDetails)throw new Error("Browser JS exception: "+JSON.stringify(result.exceptionDetails));
        return result.result.value;
    }
    await call("Page.enable");
    await call("Runtime.enable");
    for (const [width,height] of [[1440,900],[390,844]]) {
        await call("Emulation.setDeviceMetricsOverride",{width,height,deviceScaleFactor:1,mobile:width<700});
        const topic=encodeURIComponent("Наследство");
        await call("Page.navigate",{url:"http://127.0.0.1:"+appPort+"/?topic="+topic+"&utm_source=yandex&utm_medium=cpc"});
        await sleep(1000);
        const state=await evaluate("({width:innerWidth,scroll:document.documentElement.scrollWidth,topic:document.querySelector('#topic').value,headings:document.querySelectorAll('h1').length,services:document.querySelectorAll('[data-topic]').length,form:!!document.querySelector('#lead-form'),cookieVisible:!document.querySelector('#cookie-banner').hidden})");
        assert(state.scroll <= state.width+1, "horizontal scrolling "+JSON.stringify(state));
        assert(state.topic==="Наследство" && state.headings===1 && state.services===14 && state.form);
        if (!state.cookieVisible) await evaluate("document.querySelector('#cookie-settings').click()");
        assert(await evaluate("!document.querySelector('#cookie-banner').hidden"));
        await evaluate("document.querySelector('#cookie-deny').click()");
        assert(await evaluate("document.querySelector('#cookie-banner').hidden"));
        assert(!(await evaluate("!!window.ym")), "analytics loaded after reject");
        await evaluate("document.querySelector('[data-topic=\"Судебный спор\"]').click()");
        assert((await evaluate("document.querySelector('#topic').value"))==="Судебный спор");
        await evaluate("document.querySelector('[data-topic=\"Арбитражные споры по договору подряда\"]').click()");
        assert((await evaluate("document.querySelector('#topic').value"))==="Арбитражные споры по договору подряда");
        await evaluate("document.querySelector('#lead-submit').click()");
        assert((await evaluate("document.querySelector('#lead-status').textContent")).includes("Укажите тему"));
        await evaluate("document.querySelector('#client-name').value='Тестовый контакт';document.querySelector('#client-phone').value='+7 (999) 000-00-00';document.querySelector('#lead-consent').checked=true;document.querySelector('#lead-submit').click()");
        await sleep(900);
        const message=await evaluate("document.querySelector('#lead-status').textContent");
        assert(message.includes("Не удалось подтвердить"), "false CRM success: "+message);
        console.log("PASS browser", width, "no overflow, form validation, no fake CRM, consent, ads topic");
    }
} finally {
    try {ws?.close();} catch {}
    try {chrome?.kill("SIGTERM");} catch {}
    try {php?.kill("SIGTERM");} catch {}
    await sleep(150);
    rmSync(profile,{recursive:true,force:true});
}
