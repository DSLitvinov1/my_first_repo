"use strict";
/* NEIROZAVOD Work ONE browser pilot: explicit, single-tab, owner-driven.
 * No persistent Chrome profile; no raw shell/desktop mouse; no form submits.
 * Network egress is limited to one public HTTPS origin with a DNS-pinned
 * Chromium resolver. Production requires OS-level network sandbox as well.
 */
const readline = require("node:readline");
const puppeteer = require("puppeteer-core");

const WIDTH = 1100, HEIGHT = 720;
let browser = null, page = null, origin = null;
let currentIp = null;
let chain = Promise.resolve();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function safeOrigin(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && u.port === "" ? u.origin : null;
  } catch (_) { return null; }
}
function present() {
  if (!page || !origin) throw Error("BROWSER_SESSION_NOT_OPEN");
}
async function frame(includeImage = true) {
  present();
  const url = page.url();
  const sameOrigin = safeOrigin(url) === origin;
  if (!sameOrigin) throw Error("BROWSER_ORIGIN_CHANGED");
  const result = {
    url: url.slice(0, 500),
    title: (await page.title()).slice(0, 180),
    width: WIDTH, height: HEIGHT,
  };
  if (includeImage) {
    const image = await page.screenshot({
      type: "jpeg", quality: 55, encoding: "base64", animations: "disabled",
    });
    if (image.length > 850000) throw Error("BROWSER_FRAME_TOO_LARGE");
    result.image = image;
  }
  return result;
}
async function shutdown() {
  const old = browser;
  browser = null; page = null; origin = null; currentIp = null;
  if (old) await old.close();
}
function constrainPoint(data) {
  const x = Number(data.x), y = Number(data.y);
  if (!Number.isInteger(x) || !Number.isInteger(y) ||
      x < 0 || x >= WIDTH || y < 0 || y >= HEIGHT) {
    throw Error("BROWSER_COORDINATES_REFUSED");
  }
  return {x, y};
}
async function guardClick(x,y) {
  const check = await page.evaluate(({x,y,origin}) => {
    const el = document.elementFromPoint(x,y);
    if (!el) return "NO_ELEMENT";
    const target = el.closest("a,button,[role=button],input,select,textarea");
    if (!target) return "NO_INTERACTIVE_TARGET";
    if (target.closest("form") || target.matches("input,select,textarea") ||
        target.getAttribute("type") === "submit" ||
        target.hasAttribute("form") ||
        target.getAttribute("contenteditable") === "true" ||
        target.getAttribute("aria-disabled") === "true" ||
        target.hasAttribute("disabled")) return "FORM_OR_INPUT_REFUSED";
    const text = (target.innerText || target.textContent ||
                  target.getAttribute("aria-label") || "").trim().toLowerCase().slice(0,100);
    if (/^(удалить|отправить|оплатить|купить|подписаться|delete|send|pay|purchase|checkout|submit|заказать|сохранить)/i.test(text)) {
      return "HIGH_IMPACT_ACTION_REFUSED";
    }
    if (target.tagName.toLowerCase() === "a") {
      const href = target.getAttribute("href") || "";
      let url;
      try { url = new URL(href, location.href); } catch (_) { return "INVALID_LINK"; }
      if (url.origin !== origin || url.protocol !== "https:")
        return "LINK_ORIGIN_REFUSED";
    } else if (target.tagName.toLowerCase() === "button") {
      if (target.type !== "button") return "SUBMIT_BUTTON_REFUSED";
    }
    return null;
  }, {x,y,origin});
  if (check) throw Error("BROWSER_CLICK_DENIED_" + check);
}
async function open(input) {
  if (browser) throw Error("CLOSE_CURRENT_BROWSER_FIRST");
  const u = new URL(input.url);
  if (!input.executablePath || !input.ip || u.protocol !== "https:" ||
      u.port || u.username || u.password ||
      !/^[a-z0-9.-]+$/i.test(u.hostname) ||
      !/^[0-9.]+$/.test(input.ip)) throw Error("BROWSER_UNSAFE_OPEN");
  origin = u.origin;
  currentIp = input.ip;
  // Fixed DNS mapping avoids a second DNS lookup between validation and use.
  browser = await puppeteer.launch({
    executablePath: input.executablePath,
    headless: true,
    defaultViewport: {width: WIDTH, height: HEIGHT, deviceScaleFactor: 1},
    args: [
      "--disable-dev-shm-usage", "--disable-background-networking",
      "--disable-extensions", "--no-first-run", "--disable-sync",
      "--host-resolver-rules=MAP " + u.hostname + " " + input.ip + ", MAP * ~NOTFOUND",
    ],
  });
  page = await browser.newPage();
  page.setDefaultNavigationTimeout(12000);
  page.setDefaultTimeout(6500);
  await page.setBypassServiceWorker(true);
  await page.evaluateOnNewDocument(() => {
    // Defense in depth, in addition to request-blocking and click guard.
    window.addEventListener("submit", event => {
      event.preventDefault();
      event.stopImmediatePropagation();
    }, true);
    window.open = () => null;
  });
  await page.setRequestInterception(true);
  page.on("request", request => {
    let permitted = false;
    try {
      const requrl = new URL(request.url());
      permitted = requrl.origin === origin &&
                  requrl.protocol === "https:" &&
                  ["GET","HEAD"].includes(request.method());
      if (request.resourceType() === "websocket") permitted = false;
    } catch (_) { permitted = false; }
    (permitted ? request.continue() : request.abort("blockedbyclient")).catch(()=>{});
  });
  page.on("dialog", dialog => dialog.dismiss().catch(()=>{}));
  page.on("popup", popup => popup.close().catch(()=>{}));
  const cdp = await page.createCDPSession();
  await cdp.send("Network.enable");
  await cdp.send("Network.setBlockedURLs", {
    urls: ["http://*", "ws://*", "wss://*", "file://*"],
  });
  try {
    await page.goto(input.url, {waitUntil:"domcontentloaded", timeout:12000});
    await sleep(400);
    return await frame();
  } catch (e) {
    await shutdown();
    throw e;
  }
}
async function command(data) {
  const operation = data.op;
  if (operation === "open") return await open(data);
  if (operation === "close") {
    await shutdown();
    return {closed:true};
  }
  present();
  if (operation === "frame") return await frame();
  if (operation === "inspect") {
    const targets = await page.evaluate(() => {
      const answer = [];
      for (const el of document.querySelectorAll("a,button,[role=button]")) {
        const rect = el.getBoundingClientRect();
        if (rect.width < 2 || rect.height < 2 || rect.bottom <= 0 ||
            rect.right <= 0 || rect.top >= 720 || rect.left >= 1100)
          continue;
        const style = getComputedStyle(el);
        if (style.visibility !== "visible" || style.display === "none" ||
            Number(style.opacity) === 0) continue;
        let label = (el.innerText || el.textContent ||
                     el.getAttribute("aria-label") || "").trim().replace(/\\s+/g, " ");
        if (!label) continue;
        const x = Math.floor(Math.max(0,Math.min(1099,rect.left+rect.width/2)));
        const y = Math.floor(Math.max(0,Math.min(719,rect.top+rect.height/2)));
        const item = {label:label.slice(0,65),kind:el.tagName.toLowerCase(),x,y};
        if (el.closest("form"))item.protected=true;
        answer.push(item);
        if (answer.length >= 35) break;
      }
      return answer;
    });
    return {...await frame(false), targets};
  }
  if (operation === "move") {
    const {x,y} = constrainPoint(data);
    await page.mouse.move(x,y,{steps:2});
    return await frame(false);
  }
  if (operation === "click") {
    const {x,y} = constrainPoint(data);
    await guardClick(x,y);
    await page.mouse.move(x,y,{steps:3});
    await page.mouse.click(x,y,{clickCount:1,delay:60});
    await sleep(300);
    return await frame();
  }
  if (operation === "scroll") {
    const amount=Number(data.delta);
    if (!Number.isInteger(amount) || Math.abs(amount)>1200 || amount===0)
      throw Error("BROWSER_SCROLL_REFUSED");
    await page.mouse.wheel({deltaY: amount});
    await sleep(240);
    return await frame();
  }
  if (operation === "back") {
    await page.goBack({waitUntil:"domcontentloaded",timeout:10000});
    await sleep(180);
    return await frame();
  }
  throw Error("BROWSER_ACTION_NOT_SUPPORTED");
}
const rl = readline.createInterface({input:process.stdin,crlfDelay:Infinity});
rl.on("line", line => {
  chain = chain.then(async () => {
    let msg;
    try { msg=JSON.parse(line); } catch (_) {msg={id:0,op:"invalid"};}
    try {
      const result=await command(msg);
      process.stdout.write(JSON.stringify({id:msg.id,ok:true,result})+"\n");
    } catch (err) {
      process.stdout.write(JSON.stringify({
        id:msg.id,ok:false,error:String(err.message || "BROWSER_OPERATION_FAILED").slice(0,180),
      })+"\n");
      if (msg.op==="open") await shutdown().catch(()=>{});
    }
  }).catch(()=>{});
});
rl.on("close",()=>{ shutdown().finally(()=>process.exit(0)); });
process.on("SIGTERM",()=>{shutdown().finally(()=>process.exit(0));});
