#!/usr/bin/env node
/**
 * SS Fraud Prevention System — Master Launcher
 * Starts backend (port 4000) and frontend (port 3000) in parallel.
 * No npm install needed — uses only Node.js built-in modules.
 *
 * Usage:
 *   node start.js
 *
 * Then open: http://localhost:3000
 */

'use strict';

const { spawn }  = require('child_process');
const path       = require('path');
const fs         = require('fs');

const ROOT      = __dirname;
const BACKEND   = path.join(ROOT, 'backend', 'server.js');
const FRONTEND  = path.join(ROOT, 'frontend', 'serve.js');
const ENV_FILE  = path.join(ROOT, 'backend', '.env');

// Load .env into process.env for child processes
function loadEnv() {
  if (!fs.existsSync(ENV_FILE)) return;
  const lines = fs.readFileSync(ENV_FILE, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (!process.env[key]) process.env[key] = val; // don't override existing env
  }
}

loadEnv();

const ENV = { ...process.env };

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  SS Fraud Prevention System — Launcher  ');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

function spawnProcess(label, script, env) {
  const proc = spawn(process.execPath, [script], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const prefix = `[${label}]`;
  const color  = label === 'BACKEND' ? '\x1b[36m' : '\x1b[35m'; // cyan / magenta
  const reset  = '\x1b[0m';

  proc.stdout.on('data', d => {
    d.toString().split('\n').filter(Boolean).forEach(line =>
      console.log(`${color}${prefix}${reset} ${line}`)
    );
  });
  proc.stderr.on('data', d => {
    d.toString().split('\n').filter(Boolean).forEach(line =>
      console.error(`${color}${prefix}${reset} \x1b[31m${line}\x1b[0m`)
    );
  });
  proc.on('exit', (code) => {
    console.log(`\n${prefix} Process exited with code ${code}`);
    process.exit(code || 0);
  });

  return proc;
}

const backend  = spawnProcess('BACKEND',  BACKEND,  ENV);
const frontend = spawnProcess('FRONTEND', FRONTEND, ENV);

// Give backend 1 second to seed, then announce URLs
setTimeout(() => {
  console.log('\n\x1b[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
  console.log('\x1b[32m  🟢 Both services are running!\x1b[0m');
  console.log('\x1b[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m');
  console.log('\n  \x1b[1m🌐 Website:\x1b[0m  \x1b[4mhttp://localhost:3000\x1b[0m');
  console.log('  \x1b[1m🔌 API:\x1b[0m      \x1b[4mhttp://localhost:4000/health\x1b[0m');
  console.log('\n  \x1b[33m👤 Admin:\x1b[0m    admin@ssfps.gov.in / Admin@123456');
  console.log('  \x1b[33m👤 Operator:\x1b[0m operator@ssfps.gov.in / Operator@123');
  console.log('\n  Press Ctrl+C to stop both servers\n');
}, 1500);

// Graceful shutdown
const shutdown = () => {
  console.log('\n\nShutting down...');
  backend.kill('SIGTERM');
  frontend.kill('SIGTERM');
  setTimeout(() => process.exit(0), 500);
};

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
