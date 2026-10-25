const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const EXT = { '.png': 'image/png', '.html': 'text/html; charset=utf-8', '.json': 'application/json', '.pdf': 'application/pdf' };

http
  .createServer((req, res) => {
    const p = decodeURIComponent(req.url.split('?')[0]);
    const file = path.join(ROOT, p === '/' ? '/img/01_level_solved.png' : p);
    try {
      const buf = fs.readFileSync(file);
      res.writeHead(200, { 'Content-Type': EXT[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  })
  .listen(8801, '127.0.0.1', () => console.log('serving report/ on 8801'));
