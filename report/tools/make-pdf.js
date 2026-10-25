const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const html = path.resolve(__dirname, '..', 'arkx-level-7-report.html');
const pdf = path.resolve(__dirname, '..', 'arkx-level-7-report.pdf');
const chrome = 'C:/Program Files/Google/Chrome/Application/chrome.exe';

if (fs.existsSync(pdf)) fs.unlinkSync(pdf);

const res = spawnSync(
  chrome,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-pdf-header-footer',
    '--virtual-time-budget=20000',
    '--print-to-pdf=' + pdf,
    pathToFileURL(html).href,
  ],
  { encoding: 'utf8' }
);

const out = (res.stdout || '') + (res.stderr || '');
console.log(out.split('\n').filter((l) => /written|error/i.test(l)).join('\n') || '(no chrome output)');
console.log('html url: ' + pathToFileURL(html).href);
console.log('pdf exists: ' + fs.existsSync(pdf) + (fs.existsSync(pdf) ? ' size=' + fs.statSync(pdf).size : ''));
