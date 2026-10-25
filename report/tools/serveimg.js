// Tiny static server for report/img, used to eyeball the captured screenshots
// in the preview browser (file:// is not permitted there).
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'img');
const PORT = 8801;
const TYPES = { '.png': 'image/png', '.html': 'text/html; charset=utf-8', '.jpg': 'image/jpeg' };

http
  .createServer((req, res) => {
    const name = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'sheet.html';
    const file = path.join(ROOT, path.basename(name));
    fs.readFile(file, (err, buf) => {
      if (err) {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
      res.end(buf);
    });
  })
  .listen(PORT, '127.0.0.1', () => console.log('img server on ' + PORT));
