// Authenticated reverse proxy for ctf.arkx.ninja.
// Injects the captured session cookie so a local headless Chrome can render
// the authenticated challenge pages for screenshot capture.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = 8800;
const UPSTREAM = 'ctf.arkx.ninja';
const COOKIE_FILE = path.join(__dirname, '..', '..', '.work', 'cookie.txt');

function cookie() {
  try {
    return fs.readFileSync(COOKIE_FILE, 'utf8').trim();
  } catch {
    return '';
  }
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);

  // One-shot cookie capture endpoint (visited by the authenticated preview tab).
  if (u.pathname === '/__cookie') {
    fs.mkdirSync(path.dirname(COOKIE_FILE), { recursive: true });
    fs.writeFileSync(COOKIE_FILE, decodeURIComponent(u.searchParams.get('c') || ''));
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  const headers = { ...req.headers };
  delete headers['accept-encoding']; // ask upstream for identity encoding
  delete headers['content-length'];
  headers['host'] = UPSTREAM;
  headers['cookie'] = cookie();

  // The MCP resource server rejects requests carrying a browser Origin.
  // A real MCP client sends none, so strip it there and pin it elsewhere.
  if (u.pathname.endsWith('/mcp')) delete headers['origin'];
  else headers['origin'] = `https://${UPSTREAM}`;
  headers['referer'] = `https://${UPSTREAM}/level/7`;

  const upstream = https.request(
    { host: UPSTREAM, servername: UPSTREAM, path: u.pathname + u.search, method: req.method, headers },
    (up) => {
      const out = { ...up.headers };
      delete out['content-encoding'];
      delete out['content-length'];
      delete out['transfer-encoding'];
      // Keep the browser on the proxy origin after app redirects.
      if (out.location && out.location.startsWith(`https://${UPSTREAM}`)) {
        out.location = out.location.replace(`https://${UPSTREAM}`, `http://127.0.0.1:${PORT}`);
      }
      delete out['content-security-policy'];
      res.writeHead(up.statusCode, out);
      up.pipe(res);
    }
  );
  upstream.on('error', (e) => {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('proxy error: ' + e.message);
  });
  req.pipe(upstream);
});

server.listen(PORT, '127.0.0.1', () => console.log('proxy listening on ' + PORT));
