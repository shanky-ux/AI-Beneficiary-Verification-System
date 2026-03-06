/**
 * Simple static file server for the frontend.
 * Serves index.html on all routes (SPA).
 * Zero dependencies — pure Node.js built-ins.
 *
 * Start: node serve.js
 * Port:  3000
 */

'use strict';

const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT      = parseInt(process.env.FRONTEND_PORT || '3000', 10);
const DIST_DIR  = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
};

const server = http.createServer((req, res) => {
  // Always serve index.html for SPA routing
  let filePath = path.join(DIST_DIR, req.url === '/' ? 'index.html' : req.url);

  // Check file exists, otherwise fall back to index.html
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(DIST_DIR, 'index.html');
  }

  const ext      = path.extname(filePath).toLowerCase();
  const mimeType = MIME[ext] || 'text/plain';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': mimeType, 'Content-Length': data.length });
    res.end(data);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ SS Fraud Prevention Frontend running`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Open this URL in your browser\n`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT',  () => { console.log('\nShutting down...'); server.close(() => process.exit(0)); });
