// Renders report/report.html to PDF with headless Chrome over the DevTools
// Protocol (same approach as the screenshot capture; no npm dependencies).
// usage: node report/tools/render_pdf.js
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = Number(process.env.PDF_PORT || 9334);
// Optional args: <input.html> <output.pdf>
const REPORT = path.resolve(process.argv[2] || path.join(__dirname, '..', 'report.html'));
const PDF = path.resolve(process.argv[3] || path.join(__dirname, '..', 'ARKX_AI_Agent_Security_CTF_Solution_Report.pdf'));
const PROFILE = path.join(__dirname, '..', '..', '.work', 'chrome-pdf-' + PORT);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fileUrl = 'file:///' + REPORT.replace(/\\/g, '/');

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--allow-file-access-from-files',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${PROFILE}`,
    'about:blank',
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
    }, 180000);
  });
}
async function evaluate(expression) {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  return r.result && r.result.value;
}
async function connect() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page && page.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(500);
  }
  throw new Error('no page target');
}

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
    await send('Page.navigate', { url: fileUrl });

    // Wait until every screenshot referenced by the document has decoded.
    let ok = false;
    for (let i = 0; i < 120; i++) {
      try {
        ok = await evaluate(
          `(()=>{ if(document.readyState!=='complete') return false; const im=[...document.images]; return im.length>0 && im.every(i=>i.complete && i.naturalWidth>0); })()`
        );
      } catch {}
      if (ok) break;
      await sleep(500);
    }
    const imgs = await evaluate(`[...document.images].length`);
    console.log('images loaded: ' + ok + ' (' + imgs + ' in document)');
    await sleep(1500);

    const res = await send('Page.printToPDF', {
      printBackground: true,
      preferCSSPageSize: true,
      displayHeaderFooter: false,
    });
    fs.writeFileSync(PDF, Buffer.from(res.data, 'base64'));
    const kb = (fs.statSync(PDF).size / 1024).toFixed(0);
    console.log('wrote ' + PDF + ' (' + kb + ' KB)');
  } catch (e) {
    console.error('FAILED: ' + e.message);
    process.exitCode = 1;
  } finally {
    try {
      chrome.kill();
    } catch {}
    await sleep(400);
    process.exit();
  }
})();
