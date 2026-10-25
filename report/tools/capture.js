// Captures real UI evidence for one level: solved status, lessons-learned note,
// the replayed prompt/answer transcript, and the flag-accepted state.
// Config: .work/capture_cfg.json  { level, prefix, flag, prompts: [...] }
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'img');
const WORK = path.join(__dirname, '..', '..', '.work');
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9333;
const cfg = JSON.parse(fs.readFileSync(path.join(WORK, 'capture_cfg.json'), 'utf8'));
const TARGET = `http://127.0.0.1:8800/level/${cfg.level}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
fs.mkdirSync(OUT, { recursive: true });

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--hide-scrollbars',
    '--no-first-run',
    '--no-default-browser-check',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${path.join(WORK, 'chrome')}`,
    '--window-size=1400,1100',
    TARGET,
  ],
  { stdio: 'ignore' }
);

let ws;
let seq = 0;
const pending = new Map();

function send(method, params = {}) {
  const id = ++seq;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error('timeout: ' + method));
      }
    }, 90000);
  });
}

async function connect() {
  for (let i = 0; i < 90; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === 'page' && t.url.includes('127.0.0.1:8800'));
      if (page && page.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(500);
  }
  throw new Error('could not find page target');
}

async function evaluate(expression) {
  const res = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (res.exceptionDetails) throw new Error('eval error: ' + JSON.stringify(res.exceptionDetails.text));
  return res.result.value;
}

async function shot(name) {
  const res = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  fs.writeFileSync(path.join(OUT, name), Buffer.from(res.data, 'base64'));
  console.log('saved ' + name);
}

async function viewport(w, h) {
  await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
  await sleep(700);
}

const TRANSCRIPT = `(() => { const t = document.getElementById('lines_container'); return t ? t.innerText : ''; })()`;

async function waitFor(expr, timeout = 45000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeout) {
    try {
      if (await evaluate(expr)) return true;
    } catch {}
    await sleep(400);
  }
  return false;
}

// The page appends a `waiting-caret` glyph while the agent is still working and
// exposes an `isProcessing` flag, so "text stopped changing" alone is not enough
// (the caret plateaus during the model's thinking gap). Wait for the turn to end,
// then for the transcript to settle.
const IDLE_DONE = `(()=>{ let busy=false; try { busy = (typeof isProcessing!=='undefined') && isProcessing; } catch(e){}
  if (busy) return false;
  if (document.querySelector('.waiting-caret')) return false;
  return true; })()`;

async function waitStable(idle = 1500, timeout = 120000) {
  const t0 = Date.now();
  let last = '';
  let lastChange = Date.now();
  while (Date.now() - t0 < timeout) {
    let done = false;
    try { done = await evaluate(IDLE_DONE); } catch {}
    const t = await evaluate(TRANSCRIPT);
    if (t !== last) {
      last = t;
      lastChange = Date.now();
    } else if (done && Date.now() - lastChange > idle) return t;
    await sleep(300);
  }
  return last;
}

const EXPAND = `html,body,#mother_container,#lines_container{height:auto!important;max-height:none!important;overflow:visible!important;}`;

(async () => {
  try {
    ws = new WebSocket(await connect());
    await new Promise((res, rej) => {
      ws.onopen = res;
      ws.onerror = rej;
    });
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        const { resolve, reject } = pending.get(m.id);
        pending.delete(m.id);
        if (m.error) reject(new Error(JSON.stringify(m.error)));
        else resolve(m.result);
      }
    };
    await send('Page.enable');
    await send('Runtime.enable');

    await waitFor(`!!document.querySelector('.start_button')`, 30000);
    await evaluate(`(()=>{const b=document.querySelector('.start_button'); if(b) b.click(); return 1})()`);
    const ready = await waitFor(
      `(()=>{const t=document.getElementById('lines_container'); return !!(t && (t.innerText.includes('READY FOR INQUIRY')||document.getElementById('user-input').disabled===false))})()`,
      45000
    );
    console.log('ready=' + ready);
    await sleep(3000);
    await evaluate(`(()=>{
      try { if (typeof skipWalkMe==='function') skipWalkMe(); } catch(e){}
      try { if (typeof closeWalkMe==='function') closeWalkMe(); } catch(e){}
      document.querySelectorAll('[class*=walk],[id*=walk]').forEach(e=>{ if(e&&e.style){e.style.display='none';e.classList.remove('show');} });
      const s=document.createElement('style'); s.textContent=${JSON.stringify(EXPAND)}; document.head.appendChild(s);
      return 1; })()`);
    await sleep(600);

    await viewport(1400, 1200);
    const popup = await evaluate(`(()=>{const p=document.getElementById('takeaways-popup');return !!(p&&p.classList.contains('show'))})()`);
    if (popup) {
      await shot(cfg.prefix + '_lessons.png');
      await evaluate(`document.getElementById('takeaways-popup').classList.remove('show')`);
      await sleep(400);
    }
    await shot(cfg.prefix + '_solved.png');

    await viewport(1400, 3200);
    const log = [];
    for (const p of cfg.prompts) {
      // A prompt may be { template, extract } so the next message can embed values
      // (e.g. order ids) returned by the previous tool call.
      let text = p;
      if (p && typeof p === 'object' && p.template) {
        const di = typeof p.from === 'number' ? p.from : log.length - 1;
        const src = (log[di] && log[di].answer) || '';
        const ids = p.extract ? [...src.matchAll(new RegExp(p.extract, 'g'))].map((m) => m[1] || m[0]) : [];
        text = p.template.replace(/\{\{(\d+)\}\}/g, (_, n) => ids[Number(n) - 1] || '');
        if (/\{\{\d+\}\}/.test(text)) throw new Error('dynamic prompt unresolved: ' + p.template);
        console.log('  (dynamic) ' + text.slice(0, 110));
      }
      const before = await evaluate(TRANSCRIPT);
      await evaluate(`(()=>{const i=document.getElementById('user-input'); i.disabled=false; i.value=${JSON.stringify(text)}; sendMessage(); return 1;})()`);
      const after = await waitStable();
      // The delta starts with the page's echo of the user's own prompt ('> ...').
      let delta = after.slice(before.length).trim();
      if (delta.startsWith('> ')) delta = delta.replace(/^>[^\n]*\n?/, '').trim();
      log.push({ prompt: text, answer: delta });
      console.log('  > ' + String(delta).slice(0, 90));
    }
    fs.writeFileSync(path.join(WORK, cfg.prefix + '_prompts.json'), JSON.stringify(log, null, 2));
    // Full rendered conversation, so the report can quote every prompt and answer verbatim.
    fs.writeFileSync(path.join(WORK, cfg.prefix + '_transcript.txt'), await evaluate(TRANSCRIPT));
    await shot(cfg.prefix + '_interaction.png');

    if (cfg.flag) {
      await evaluate(`(()=>{
        const b=document.getElementById('flag-btn'); if(b){b.disabled=false;}
        const i=document.getElementById('flag-input'); if(i){i.value=${JSON.stringify(cfg.flag)};}
        submitFlag(); return 1; })()`);
      const done = await waitFor(`document.getElementById('lines_container').innerText.includes('MISSION ACCOMPLISHED')`, 30000);
      console.log('mission accomplished=' + done);
      await sleep(1800);
      await evaluate(`(()=>{const p=document.getElementById('takeaways-popup'); if(p) p.classList.remove('show'); return 1})()`);
      await sleep(400);
      await shot(cfg.prefix + '_flag.png');
    }
    console.log('status: ' + (await evaluate(`(async()=>{const r=await fetch('/level/${cfg.level}/status');return await r.text()})()`)));
  } catch (e) {
    console.error('FAILED: ' + e.message);
    process.exitCode = 1;
  } finally {
    try { chrome.kill(); } catch {}
    await sleep(500);
    process.exit();
  }
})();
