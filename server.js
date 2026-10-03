/**
 * ============================================================================
 * WOO PASS — Local WebApp & PWA Server (server.js)
 * Zero-dependency Node.js HTTP Server with full PWA & Service Worker support
 * ============================================================================
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf'
};

function getLocalIpAddresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        addresses.push(net.address);
      }
    }
  }
  return addresses;
}

const server = http.createServer((req, res) => {
  // Parse clean URL
  let parsedUrl = req.url.split('?')[0];

  // Route aliases
  if (parsedUrl === '/' || parsedUrl === '') {
    parsedUrl = '/index.html';
  } else if (parsedUrl === '/app' || parsedUrl === '/install') {
    parsedUrl = '/app.html';
  }

  // Safe file path resolution
  const safePath = path.normalize(parsedUrl).replace(/^(\.\.[\/\\])+/, '');
  let filePath = path.join(ROOT_DIR, safePath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Check if adding .html helps (e.g. /app -> /app.html)
      if (!path.extname(filePath)) {
        const htmlPath = filePath + '.html';
        if (fs.existsSync(htmlPath)) {
          filePath = htmlPath;
        } else {
          return send404(res);
        }
      } else {
        return send404(res);
      }
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    // Headers
    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Service-Worker-Allowed', '/');

    // Cache control
    if (ext === '.html' || filePath.endsWith('sw.js') || ext === '.json') {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => send404(res));
    stream.pipe(res);
  });
});

function send404(res) {
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>404 — Not Found | WooPass</title>
      <style>
        body { background:#0b0f19; color:#fff; font-family:sans-serif; text-align:center; padding:100px 20px; }
        a { color:#3b82f6; text-decoration:none; font-weight:bold; }
      </style>
    </head>
    <body>
      <h1>404 — File Not Found</h1>
      <p>The requested vault resource does not exist.</p>
      <p><a href="/index.html">Return to Vault</a> | <a href="/app.html">Install as App</a></p>
    </body>
    </html>
  `);
}

server.listen(PORT, () => {
  const localIps = getLocalIpAddresses();
  console.log('\n============================================================');
  console.log('🛡️  WOO PASS — Private Vault & PWA Server Running');
  console.log('============================================================');
  console.log(`\n Local Vault:       http://localhost:${PORT}`);
  console.log(` 📲 Install Page:    http://localhost:${PORT}/app.html`);
  if (localIps.length > 0) {
    console.log(`\n 📱 On Mobile / WiFi:`);
    localIps.forEach((ip) => {
      console.log(`    Vault:          http://${ip}:${PORT}`);
      console.log(`    Install Page:   http://${ip}:${PORT}/app.html`);
    });
  }
  console.log('============================================================\n');
});
