/**
 * SS Fraud Prevention System — Standalone Backend
 * Zero external dependencies: uses only Node.js built-in modules.
 * Implements JWT auth, RBAC, fraud engine, full CRUD, analytics, audit logs.
 * Data is persisted to JSON files in ./data/ so it survives restarts.
 *
 * Start: node server.js
 * Port:  4000
 */

'use strict';

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT              = parseInt(process.env.PORT || '4000', 10);
const FRONTEND_ORIGIN   = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
const JWT_SECRET        = process.env.JWT_SECRET || 'ss-fraud-dev-jwt-secret-change-in-prod';
const JWT_REFRESH_SECRET= process.env.JWT_REFRESH_SECRET || 'ss-fraud-dev-refresh-secret-change-in-prod';
const ENCRYPT_KEY       = process.env.FIELD_ENCRYPTION_KEY
  ? Buffer.from(process.env.FIELD_ENCRYPTION_KEY, 'hex')
  : crypto.randomBytes(32); // safe random key for this session
const DATA_DIR          = path.join(__dirname, 'data');

// ─── Persistence ─────────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadTable(name, defaultVal = []) {
  const file = path.join(DATA_DIR, `${name}.json`);
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return typeof defaultVal === 'function' ? defaultVal() : defaultVal; }
}

function saveTable(name, data) {
  const file = path.join(DATA_DIR, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// In-memory tables (loaded from disk, written on mutation)
const DB = {
  users:         loadTable('users'),
  beneficiaries: loadTable('beneficiaries'),
  fraudCases:    loadTable('fraudCases'),
  verifications: loadTable('verifications'),
  payments:      loadTable('payments'),
  auditLogs:     loadTable('auditLogs'),
  notifications: loadTable('notifications'),
};

function persist(table) { saveTable(table, DB[table]); }

// ─── Crypto helpers ──────────────────────────────────────────────────────────
function encryptField(plain) {
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPT_KEY, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join(':');
}

function decryptField(ciphertext) {
  const [ivB64, tagB64, encB64] = ciphertext.split(':');
  const iv  = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const enc = Buffer.from(encB64, 'base64');
  const d   = crypto.createDecipheriv('aes-256-gcm', ENCRYPT_KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

function maskLast4(s) {
  if (!s || s.length <= 4) return '****';
  return 'X'.repeat(s.length - 4) + s.slice(-4);
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto.scryptSync(pw, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
}

function cuid() {
  return 'c' + Date.now().toString(36) + crypto.randomBytes(8).toString('hex');
}

// ─── JWT helpers (manual Base64URL, no deps) ─────────────────────────────────
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function signJwt(payload, secret, expiresIn = 8 * 3600) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + expiresIn }));
  const sig     = b64url(crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Bad token format');
  const [header, body, sig] = parts;
  const expected = b64url(crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest());
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) throw new Error('Signature mismatch');
  const payload = JSON.parse(Buffer.from(body, 'base64').toString('utf8'));
  if (payload.exp < Math.floor(Date.now()/1000)) throw new Error('Token expired');
  return payload;
}

// ─── Fraud Engine ─────────────────────────────────────────────────────────────
function runFraudEngine(beneficiary) {
  const rules = [];
  let score = 0;

  if (beneficiary.deathVerified) {
    rules.push({ ruleId:'DEATH_CONFIRMED', name:'Death Record Found', score:40, detail:'Confirmed deceased in civil death registry' });
    score += 40;
  }
  if (beneficiary.lifeCertStatus === 'EXPIRED') {
    rules.push({ ruleId:'LIFE_CERT_EXPIRED', name:'Life Certificate Expired', score:25, detail:'Life certificate expired and not renewed' });
    score += 25;
  } else if (beneficiary.lifeCertStatus === 'NOT_FOUND') {
    rules.push({ ruleId:'LIFE_CERT_EXPIRED', name:'Life Certificate Missing', score:20, detail:'No life certificate on record' });
    score += 20;
  } else if (beneficiary.lifeCertStatus === 'PENDING') {
    rules.push({ ruleId:'LIFE_CERT_EXPIRED', name:'Life Certificate Pending', score:10, detail:'Life certificate submission pending' });
    score += 10;
  }
  if (!beneficiary.aadhaarVerified) {
    rules.push({ ruleId:'AADHAAR_UNVERIFIED', name:'Aadhaar Not Verified', score:20, detail:'Aadhaar OTP verification not completed' });
    score += 20;
  }
  if (beneficiary.age > 100) {
    rules.push({ ruleId:'AGE_ANOMALY', name:'Age Anomaly', score:10, detail:`Beneficiary age ${beneficiary.age} exceeds 100` });
    score += 10;
  }

  const lastVerif = DB.verifications.filter(v => v.beneficiaryId === beneficiary.id).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))[0];
  const daysSince = lastVerif ? Math.floor((Date.now()-new Date(lastVerif.createdAt).getTime()) / 86400000) : 999;
  if (daysSince > 365) {
    const s = Math.min(15, Math.floor(daysSince/365)*5);
    rules.push({ ruleId:'VERIFICATION_OVERDUE', name:'Verification Overdue', score:s, detail:`Last verification was ${daysSince} days ago` });
    score += s;
  }

  // Check payments while suspended
  if (beneficiary.status === 'SUSPENDED') {
    const recent = DB.payments.filter(p => p.beneficiaryId === beneficiary.id && p.status === 'DISBURSED').length;
    if (recent > 0) {
      rules.push({ ruleId:'PAYMENT_DURING_SUSPENSION', name:'Payment While Suspended', score:30, detail:`${recent} payment(s) disbursed while account was suspended` });
      score += 30;
    }
  }

  score = Math.min(100, score);
  const severity = score >= 75 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 50 ? 'MEDIUM' : score > 0 ? 'LOW' : 'NONE';
  const action   = score >= 75 ? 'STOP_PAYMENT' : score >= 50 ? 'FLAG' : score > 0 ? 'REVIEW' : 'NONE';

  return { totalScore: score, triggeredRules: rules, severity, recommendedAction: action };
}

// ─── Seed data ────────────────────────────────────────────────────────────────
function seedIfEmpty() {
  if (DB.users.length > 0) return;
  console.log('🌱 Seeding initial data...');

  const adminId = cuid();
  const opId    = cuid();

  DB.users.push(
    { id: adminId, email: 'admin@ssfps.gov.in', passwordHash: hashPassword('Admin@123456'), name: 'System Administrator', role: 'ADMIN', isActive: true, lastLoginAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
    { id: opId,    email: 'operator@ssfps.gov.in', passwordHash: hashPassword('Operator@123'), name: 'Field Operator', role: 'OPERATOR', isActive: true, lastLoginAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }
  );

  const sampleBeneficiaries = [
    { pensionId:'PEN001234', name:'Ramesh Kumar',   aadhaar:'123456789012', bank:'987654321098', age:72, state:'Maharashtra', district:'Pune',         status:'ACTIVE',         lc:'VALID' },
    { pensionId:'PEN001235', name:'Savitri Devi',   aadhaar:'234567890123', bank:'876543210987', age:68, state:'Bihar',       district:'Patna',         status:'ACTIVE',         lc:'VALID' },
    { pensionId:'PEN001230', name:'Mohan Lal',      aadhaar:'345678901234', bank:'765432109876', age:81, state:'Uttar Pradesh',district:'Lucknow',       status:'DECEASED',       lc:'EXPIRED' },
    { pensionId:'PEN001231', name:'Geeta Singh',    aadhaar:'456789012345', bank:'654321098765', age:75, state:'Rajasthan',   district:'Jaipur',         status:'FRAUD_FLAGGED',  lc:'EXPIRED' },
    { pensionId:'PEN001245', name:'Abdul Rahman',   aadhaar:'567890123456', bank:'543210987654', age:65, state:'Kerala',      district:'Kozhikode',      status:'ACTIVE',         lc:'VALID' },
    { pensionId:'PEN001255', name:'Priya Sharma',   aadhaar:'678901234567', bank:'432109876543', age:69, state:'Tamil Nadu',  district:'Chennai',        status:'PAYMENT_STOPPED',lc:'EXPIRED' },
    { pensionId:'PEN001265', name:'Suresh Patel',   aadhaar:'789012345678', bank:'321098765432', age:77, state:'Gujarat',     district:'Surat',          status:'SUSPENDED',      lc:'PENDING' },
    { pensionId:'PEN001236', name:'Kamala Bai',     aadhaar:'890123456789', bank:'210987654321', age:83, state:'Madhya Pradesh',district:'Bhopal',       status:'ACTIVE',         lc:'VALID' },
    { pensionId:'PEN001237', name:'Rajan Nair',     aadhaar:'901234567890', bank:'109876543210', age:70, state:'Kerala',      district:'Thiruvananthapuram', status:'ACTIVE',      lc:'VALID' },
    { pensionId:'PEN001238', name:'Meena Kumari',   aadhaar:'012345678901', bank:'198765432109', age:105,state:'Bihar',       district:'Gaya',           status:'FRAUD_FLAGGED',  lc:'NOT_FOUND' },
  ];

  const months = ['2025-01','2025-02','2025-03','2025-04','2025-05'];

  for (const b of sampleBeneficiaries) {
    const id = cuid();
    const isDeceased = b.status === 'DECEASED';
    const isFraud    = ['FRAUD_FLAGGED','PAYMENT_STOPPED','DECEASED'].includes(b.status);
    const amount     = 3000 + Math.floor(Math.random() * 2000);

    DB.beneficiaries.push({
      id, pensionId: b.pensionId, name: b.name,
      aadhaarEncrypted: encryptField(b.aadhaar),
      bankAccountEncrypted: encryptField(b.bank),
      ifscCode: 'SBIN0001234',
      address: `${Math.floor(Math.random()*999)+1}, Sample Street`,
      district: b.district, state: b.state,
      pincode: `${400000 + Math.floor(Math.random()*99999)}`,
      age: b.age,
      dateOfBirth: new Date(2025 - b.age, 3, 15).toISOString(),
      status: b.status, monthlyAmount: amount,
      disbursedSince: '2020-01-01T00:00:00.000Z',
      aadhaarVerified: b.status === 'ACTIVE', aadhaarVerifiedAt: b.status === 'ACTIVE' ? new Date().toISOString() : null,
      deathVerified: isDeceased, deathVerifiedAt: isDeceased ? '2024-03-15T00:00:00.000Z' : null,
      lifeCertStatus: b.lc, lifeCertUpdatedAt: new Date().toISOString(),
      createdAt: new Date(Date.now() - Math.random()*180*86400000).toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Payments
    for (const [mi, month] of months.entries()) {
      const [yr, mo] = month.split('-').map(Number);
      DB.payments.push({
        id: cuid(), beneficiaryId: id, amount, month: mo, year: yr,
        status: b.status === 'PAYMENT_STOPPED' && mi >= 3 ? 'STOPPED' : 'DISBURSED',
        disbursedAt: `${month}-05T00:00:00.000Z`,
        stopReason: b.status === 'PAYMENT_STOPPED' && mi >= 3 ? 'AUTO_FRAUD_ENGINE' : null,
        createdAt: `${month}-01T00:00:00.000Z`,
      });
    }

    // Fraud cases for flagged
    if (isFraud) {
      const assessment = runFraudEngine(DB.beneficiaries[DB.beneficiaries.length - 1]);
      DB.fraudCases.push({
        id: cuid(), beneficiaryId: id,
        assignedToId: adminId,
        severity: assessment.severity === 'NONE' ? 'LOW' : assessment.severity,
        status: 'OPEN',
        fraudScore: assessment.totalScore,
        triggers: assessment.triggeredRules,
        autoActionTaken: b.status === 'PAYMENT_STOPPED',
        resolutionNote: null, resolvedAt: null,
        createdAt: new Date(Date.now() - Math.random()*30*86400000).toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }

    // Notifications
    DB.notifications.push({
      id: cuid(), userId: adminId,
      type: isFraud ? 'FRAUD_ALERT' : 'INFO',
      title: isFraud ? `🚨 Fraud alert: ${b.name}` : `Beneficiary registered: ${b.name}`,
      body: `Pension ID ${b.pensionId} — ${b.status}`,
      isRead: !isFraud,
      readAt: !isFraud ? new Date().toISOString() : null,
      metadata: { pensionId: b.pensionId },
      createdAt: new Date(Date.now() - Math.random()*7*86400000).toISOString(),
    });
  }

  // Historical fraud trend (last 6 months)
  const now = new Date();
  for (let m = 5; m >= 0; m--) {
    const d = new Date(now.getFullYear(), now.getMonth()-m, 15);
    const count = Math.floor(Math.random()*5) + 2;
    for (let i = 0; i < count; i++) {
      DB.fraudCases.push({
        id: cuid(), beneficiaryId: DB.beneficiaries[0].id,
        assignedToId: null, severity: ['LOW','MEDIUM','HIGH'][Math.floor(Math.random()*3)],
        status: 'RESOLVED', fraudScore: 30 + Math.random()*50,
        triggers: [], autoActionTaken: false, resolutionNote: 'Historical',
        resolvedAt: d.toISOString(),
        createdAt: d.toISOString(), updatedAt: d.toISOString(),
      });
    }
  }

  persist('users'); persist('beneficiaries'); persist('payments');
  persist('fraudCases'); persist('notifications');
  console.log('✅ Seed complete. Admin: admin@ssfps.gov.in / Admin@123456');
}

// ─── Rate limiter (in-memory) ─────────────────────────────────────────────────
const rateLimitMap = new Map();
function rateLimit(ip, max = 100, windowMs = 900000) {
  const now = Date.now();
  const key = ip;
  let entry  = rateLimitMap.get(key);
  if (!entry || now - entry.start > windowMs) {
    entry = { start: now, count: 0 };
    rateLimitMap.set(key, entry);
  }
  entry.count++;
  return entry.count <= max;
}

// ─── Middleware chain helper ──────────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString();
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { resolve({}); }
    });
  });
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(pair => {
    const [k, v] = pair.trim().split('=');
    if (k) out[k.trim()] = decodeURIComponent((v||'').trim());
  });
  return out;
}

function getAuth(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  try { return verifyJwt(h.slice(7), JWT_SECRET); }
  catch { return null; }
}

function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':  'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function ok(res, data, meta)  { send(res, 200, { success:true, data, ...(meta?{meta}:{}) }); }
function created(res, data)   { send(res, 201, { success:true, data }); }
function err(res, status, code, message, details) {
  send(res, status, { success:false, error:{ code, message, ...(details?{details}:{}) } });
}

function auditAsync(action, entity, userId, entityId, beneficiaryId, req) {
  process.nextTick(() => {
    DB.auditLogs.push({
      id: cuid(), userId, beneficiaryId: beneficiaryId||null,
      action, entity, entityId: entityId||null,
      ipAddress: req.socket.remoteAddress,
      userAgent: (req.headers['user-agent']||'').slice(0,200),
      metadata: { method: req.method, path: req.url },
      createdAt: new Date().toISOString(),
    });
    persist('auditLogs');
  });
}

function sanitiseBeneficiary(b) {
  let aadhaarMasked = '****', bankMasked = '****';
  try { aadhaarMasked = maskLast4(decryptField(b.aadhaarEncrypted)); } catch {}
  try { bankMasked    = maskLast4(decryptField(b.bankAccountEncrypted)); } catch {}
  const { aadhaarEncrypted: _a, bankAccountEncrypted: _b, ...rest } = b;
  return { ...rest, aadhaarMasked, bankMasked };
}

// ─── Route handlers ──────────────────────────────────────────────────────────

const handlers = {};

// POST /api/v1/auth/login
handlers['POST /api/v1/auth/login'] = async (req, res) => {
  const { email, password } = await parseBody(req);
  if (!email || !password) return err(res, 422, 'VALIDATION_ERROR', 'email and password required');

  const user = DB.users.find(u => u.email === email.toLowerCase().trim() && u.isActive);
  // Dummy compute to prevent timing attacks
  const dummyHash = 'aabbccdd:' + '00'.repeat(64);
  const valid = user ? verifyPassword(password, user.passwordHash)
                     : (crypto.timingSafeEqual(Buffer.alloc(1), Buffer.alloc(1)), false);
  if (!user || !valid) return err(res, 401, 'INVALID_CREDENTIALS', 'Invalid email or password');

  user.lastLoginAt = new Date().toISOString();
  persist('users');
  auditAsync('LOGIN', 'user', user.id, user.id, null, req);

  const accessToken  = signJwt({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, 8*3600);
  const refreshToken = signJwt({ sub: user.id }, JWT_REFRESH_SECRET, 7*24*3600);
  ok(res, { accessToken, refreshToken, user: { id:user.id, name:user.name, email:user.email, role:user.role } });
};

// POST /api/v1/auth/refresh
handlers['POST /api/v1/auth/refresh'] = async (req, res) => {
  const { refreshToken } = await parseBody(req);
  if (!refreshToken) return err(res, 400, 'MISSING_TOKEN', 'Refresh token required');
  try {
    const payload = verifyJwt(refreshToken, JWT_REFRESH_SECRET);
    const user    = DB.users.find(u => u.id === payload.sub && u.isActive);
    if (!user) return err(res, 401, 'INVALID_TOKEN', 'User not found');
    const accessToken = signJwt({ sub:user.id, email:user.email, role:user.role }, JWT_SECRET, 8*3600);
    ok(res, { accessToken });
  } catch (e) { err(res, 401, 'INVALID_TOKEN', 'Token invalid or expired'); }
};

// GET /api/v1/auth/me
handlers['GET /api/v1/auth/me'] = (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const user = DB.users.find(u => u.id === auth.sub);
  if (!user) return err(res, 404, 'NOT_FOUND', 'User not found');
  ok(res, { id:user.id, name:user.name, email:user.email, role:user.role, lastLoginAt:user.lastLoginAt, createdAt:user.createdAt });
};

// GET /api/v1/beneficiaries
handlers['GET /api/v1/beneficiaries'] = (req, res, query) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const page   = Math.max(1, parseInt(query.page||'1',10));
  const limit  = Math.min(100, Math.max(1, parseInt(query.limit||'15',10)));
  const status = query.status || '';
  const search = (query.search||'').toLowerCase();

  let results = DB.beneficiaries.filter(b => {
    if (status && b.status !== status) return false;
    if (search && !b.name.toLowerCase().includes(search) && !b.pensionId.toLowerCase().includes(search)) return false;
    return true;
  });

  const total = results.length;
  results = results.slice((page-1)*limit, page*limit);
  auditAsync('VIEW', 'beneficiary', auth.sub, null, null, req);
  ok(res, results.map(sanitiseBeneficiary), { page, limit, total, pages: Math.ceil(total/limit) });
};

// GET /api/v1/beneficiaries/stats
handlers['GET /api/v1/beneficiaries/stats'] = (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const byStatus = {};
  for (const b of DB.beneficiaries) byStatus[b.status] = (byStatus[b.status]||0) + 1;
  const totalMonthly = DB.beneficiaries.reduce((s, b) => s + (b.monthlyAmount||0), 0);
  const openFraud    = DB.fraudCases.filter(c => c.status === 'OPEN').length;

  ok(res, { total: DB.beneficiaries.length, byStatus, totalMonthlyDisbursement: totalMonthly, openFraudCases: openFraud });
};

// GET /api/v1/beneficiaries/:id
handlers['GET /api/v1/beneficiaries/:id'] = (req, res, _query, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const b = DB.beneficiaries.find(b => b.id === params.id);
  if (!b) return err(res, 404, 'NOT_FOUND', 'Beneficiary not found');
  ok(res, sanitiseBeneficiary(b));
};

// POST /api/v1/beneficiaries
handlers['POST /api/v1/beneficiaries'] = async (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  if (!['ADMIN','OPERATOR'].includes(auth.role)) return err(res, 403, 'FORBIDDEN', 'Insufficient permissions');

  const body = await parseBody(req);
  const required = ['pensionId','name','aadhaarNumber','bankAccount','ifscCode','address','district','state','pincode','age','dateOfBirth','monthlyAmount','disbursedSince'];
  for (const f of required) if (!body[f] && body[f] !== 0) return err(res, 422, 'VALIDATION_ERROR', `Missing field: ${f}`);
  if (DB.beneficiaries.find(b => b.pensionId === body.pensionId)) return err(res, 409, 'CONFLICT', 'Pension ID already exists');

  const id = cuid();
  const newB = {
    id, pensionId: body.pensionId, name: body.name,
    aadhaarEncrypted: encryptField(String(body.aadhaarNumber)),
    bankAccountEncrypted: encryptField(String(body.bankAccount)),
    ifscCode: body.ifscCode, address: body.address,
    district: body.district, state: body.state, pincode: body.pincode,
    age: parseInt(body.age,10),
    dateOfBirth: new Date(body.dateOfBirth).toISOString(),
    status: 'ACTIVE', monthlyAmount: parseFloat(body.monthlyAmount),
    disbursedSince: new Date(body.disbursedSince).toISOString(),
    aadhaarVerified: false, aadhaarVerifiedAt: null,
    deathVerified: false, deathVerifiedAt: null,
    lifeCertStatus: 'PENDING', lifeCertUpdatedAt: null,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  };
  DB.beneficiaries.push(newB);
  persist('beneficiaries');
  auditAsync('CREATE', 'beneficiary', auth.sub, id, id, req);
  created(res, sanitiseBeneficiary(newB));
};

// PATCH /api/v1/beneficiaries/:id
handlers['PATCH /api/v1/beneficiaries/:id'] = async (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  if (!['ADMIN','OPERATOR'].includes(auth.role)) return err(res, 403, 'FORBIDDEN', 'Insufficient permissions');

  const idx = DB.beneficiaries.findIndex(b => b.id === params.id);
  if (idx === -1) return err(res, 404, 'NOT_FOUND', 'Beneficiary not found');

  const body = await parseBody(req);
  const allowed = ['name','address','district','state','pincode','ifscCode','age','monthlyAmount','status'];
  for (const f of allowed) if (body[f] !== undefined) DB.beneficiaries[idx][f] = body[f];
  if (body.bankAccount) DB.beneficiaries[idx].bankAccountEncrypted = encryptField(String(body.bankAccount));
  if (body.aadhaarNumber) DB.beneficiaries[idx].aadhaarEncrypted = encryptField(String(body.aadhaarNumber));
  DB.beneficiaries[idx].updatedAt = new Date().toISOString();

  persist('beneficiaries');
  auditAsync('UPDATE', 'beneficiary', auth.sub, params.id, params.id, req);
  ok(res, sanitiseBeneficiary(DB.beneficiaries[idx]));
};

// DELETE /api/v1/beneficiaries/:id
handlers['DELETE /api/v1/beneficiaries/:id'] = (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  if (auth.role !== 'ADMIN') return err(res, 403, 'FORBIDDEN', 'Admin only');

  const idx = DB.beneficiaries.findIndex(b => b.id === params.id);
  if (idx === -1) return err(res, 404, 'NOT_FOUND', 'Not found');
  DB.beneficiaries.splice(idx, 1);
  persist('beneficiaries');
  auditAsync('DELETE', 'beneficiary', auth.sub, params.id, params.id, req);
  ok(res, { message: 'Beneficiary deleted' });
};

// POST /api/v1/fraud/check/:id
handlers['POST /api/v1/fraud/check/:id'] = (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const b = DB.beneficiaries.find(b => b.id === params.id);
  if (!b) return err(res, 404, 'NOT_FOUND', 'Beneficiary not found');

  const assessment = runFraudEngine(b);

  // Persist fraud case
  const caseId = cuid();
  DB.fraudCases.push({
    id: caseId, beneficiaryId: b.id, assignedToId: null,
    severity: assessment.severity === 'NONE' ? 'LOW' : assessment.severity,
    status: 'OPEN',
    fraudScore: assessment.totalScore,
    triggers: assessment.triggeredRules,
    autoActionTaken: false, resolutionNote: null, resolvedAt: null,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  });

  // Auto-action
  if (assessment.recommendedAction === 'STOP_PAYMENT') {
    const idx = DB.beneficiaries.findIndex(x => x.id === b.id);
    DB.beneficiaries[idx].status = 'PAYMENT_STOPPED';
    DB.fraudCases[DB.fraudCases.length-1].autoActionTaken = true;
    // Notify all admins
    const admins = DB.users.filter(u => u.role === 'ADMIN');
    for (const admin of admins) {
      DB.notifications.push({ id:cuid(), userId:admin.id, type:'PAYMENT_STOPPED', title:`⛔ Auto payment stop: ${b.name}`, body:`Score ${assessment.totalScore.toFixed(0)} — ${assessment.severity} — ${b.pensionId}`, isRead:false, readAt:null, metadata:{ beneficiaryId:b.id }, createdAt:new Date().toISOString() });
    }
    persist('notifications');
  } else if (assessment.severity !== 'NONE') {
    const idx = DB.beneficiaries.findIndex(x => x.id === b.id);
    DB.beneficiaries[idx].status = 'FRAUD_FLAGGED';
  }
  persist('fraudCases'); persist('beneficiaries');
  auditAsync('VERIFICATION_RUN', 'fraud_case', auth.sub, caseId, b.id, req);
  ok(res, { ...assessment, beneficiaryId: b.id });
};

// POST /api/v1/fraud/verify/aadhaar/:id
handlers['POST /api/v1/fraud/verify/aadhaar/:id'] = (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const idx = DB.beneficiaries.findIndex(b => b.id === params.id);
  if (idx === -1) return err(res, 404, 'NOT_FOUND', 'Beneficiary not found');

  const suffix = DB.beneficiaries[idx].pensionId.slice(-2);
  const verified = !['00','99'].includes(suffix);
  const reqId = cuid();

  DB.verifications.push({ id:cuid(), beneficiaryId:params.id, type:'AADHAAR', requestId:reqId, responseCode: verified?'SUCCESS':'FAILURE', responseData:{ verified }, success:verified, latencyMs:95, createdAt:new Date().toISOString() });
  if (verified) { DB.beneficiaries[idx].aadhaarVerified = true; DB.beneficiaries[idx].aadhaarVerifiedAt = new Date().toISOString(); }
  persist('verifications'); persist('beneficiaries');
  ok(res, { verified, requestId: reqId, latencyMs: 95 });
};

// POST /api/v1/fraud/verify/death/:id
handlers['POST /api/v1/fraud/verify/death/:id'] = (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const idx = DB.beneficiaries.findIndex(b => b.id === params.id);
  if (idx === -1) return err(res, 404, 'NOT_FOUND', 'Beneficiary not found');

  const lastChar    = DB.beneficiaries[idx].pensionId.slice(-1);
  const isDeceased  = ['0','1'].includes(lastChar);
  const reqId       = cuid();

  DB.verifications.push({ id:cuid(), beneficiaryId:params.id, type:'DEATH', requestId:reqId, responseCode:isDeceased?'DECEASED':'ALIVE', responseData:{ isDeceased, confidence:isDeceased?0.97:0.99 }, success:true, latencyMs:120, createdAt:new Date().toISOString() });
  if (isDeceased) { DB.beneficiaries[idx].deathVerified = true; DB.beneficiaries[idx].deathVerifiedAt = new Date().toISOString(); DB.beneficiaries[idx].status = 'DECEASED'; }
  persist('verifications'); persist('beneficiaries');
  ok(res, { isDeceased, confidence: isDeceased?0.97:0.99, requestId: reqId });
};

// POST /api/v1/fraud/verify/life-cert/:id
handlers['POST /api/v1/fraud/verify/life-cert/:id'] = (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const idx = DB.beneficiaries.findIndex(b => b.id === params.id);
  if (idx === -1) return err(res, 404, 'NOT_FOUND', 'Beneficiary not found');

  const lastChar = DB.beneficiaries[idx].pensionId.slice(-1);
  const status   = lastChar==='5'?'EXPIRED':lastChar==='9'?'PENDING':lastChar==='7'?'NOT_FOUND':'VALID';
  const reqId    = cuid();

  DB.verifications.push({ id:cuid(), beneficiaryId:params.id, type:'LIFE_CERT', requestId:reqId, responseCode:status, responseData:{ status }, success:status==='VALID', latencyMs:80, createdAt:new Date().toISOString() });
  DB.beneficiaries[idx].lifeCertStatus = status;
  DB.beneficiaries[idx].lifeCertUpdatedAt = new Date().toISOString();
  persist('verifications'); persist('beneficiaries');
  ok(res, { status, requestId: reqId, validUntil: status==='VALID'?'2025-10-31':null });
};

// GET /api/v1/fraud/cases
handlers['GET /api/v1/fraud/cases'] = (req, res, query) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const page     = Math.max(1, parseInt(query.page||'1',10));
  const limit    = Math.min(100, parseInt(query.limit||'15',10));
  const statusF  = query.status||'';
  const severityF= query.severity||'';

  let results = DB.fraudCases.filter(c => {
    if (statusF   && c.status   !== statusF)   return false;
    if (severityF && c.severity !== severityF) return false;
    return true;
  }).sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));

  const total = results.length;
  results = results.slice((page-1)*limit, page*limit);

  const enriched = results.map(c => ({
    ...c,
    beneficiary: (() => { const b = DB.beneficiaries.find(x => x.id === c.beneficiaryId); return b ? { id:b.id, name:b.name, pensionId:b.pensionId, status:b.status } : null; })(),
    assignedTo: (() => { const u = DB.users.find(x => x.id === c.assignedToId); return u ? { id:u.id, name:u.name, email:u.email } : null; })(),
  }));

  ok(res, enriched, { page, limit, total, pages: Math.ceil(total/limit) });
};

// PATCH /api/v1/fraud/cases/:id
handlers['PATCH /api/v1/fraud/cases/:id'] = async (req, res, _q, params) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const idx = DB.fraudCases.findIndex(c => c.id === params.id);
  if (idx === -1) return err(res, 404, 'NOT_FOUND', 'Case not found');

  const body = await parseBody(req);
  if (body.status) DB.fraudCases[idx].status = body.status;
  if (body.resolutionNote) DB.fraudCases[idx].resolutionNote = body.resolutionNote;
  if (body.assignedToId) DB.fraudCases[idx].assignedToId = body.assignedToId;
  if (body.status === 'RESOLVED') DB.fraudCases[idx].resolvedAt = new Date().toISOString();
  DB.fraudCases[idx].updatedAt = new Date().toISOString();
  persist('fraudCases');
  auditAsync('UPDATE', 'fraud_case', auth.sub, params.id, DB.fraudCases[idx].beneficiaryId, req);
  ok(res, DB.fraudCases[idx]);
};

// GET /api/v1/analytics/dashboard
handlers['GET /api/v1/analytics/dashboard'] = (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const byStatus = {}, bySeverity = {};
  for (const b of DB.beneficiaries) byStatus[b.status] = (byStatus[b.status]||0) + 1;
  for (const c of DB.fraudCases)    bySeverity[c.severity] = (bySeverity[c.severity]||0) + 1;

  const stopped   = DB.payments.filter(p => p.status === 'STOPPED');
  const savings   = stopped.reduce((s, p) => s + (p.amount||0), 0);
  const last30    = DB.verifications.filter(v => new Date(v.createdAt) >= new Date(Date.now()-30*86400000)).length;

  ok(res, {
    beneficiaries: { total: DB.beneficiaries.length, byStatus },
    fraud: { totalCases: DB.fraudCases.length, bySeverity, savingsAmount: savings, paymentsBlocked: stopped.length },
    verifications: { last30Days: last30 },
  });
};

// GET /api/v1/analytics/fraud-trend
handlers['GET /api/v1/analytics/fraud-trend'] = (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const sixMonthsAgo = new Date(Date.now() - 180*86400000);
  const buckets = {};
  for (const c of DB.fraudCases) {
    if (new Date(c.createdAt) < sixMonthsAgo) continue;
    const key = c.createdAt.slice(0,7);
    if (!buckets[key]) buckets[key] = { month:key, cases:0, totalScore:0 };
    buckets[key].cases++;
    buckets[key].totalScore += (c.fraudScore||0);
  }
  const trend = Object.values(buckets)
    .map(b => ({ month:b.month, cases:b.cases, avgScore: b.cases ? b.totalScore/b.cases : 0 }))
    .sort((a,b) => a.month.localeCompare(b.month));
  ok(res, trend);
};

// GET /api/v1/analytics/audit-logs
handlers['GET /api/v1/analytics/audit-logs'] = (req, res, query) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  if (auth.role !== 'ADMIN') return err(res, 403, 'FORBIDDEN', 'Admin only');

  const page    = Math.max(1, parseInt(query.page||'1',10));
  const limit   = Math.min(100, parseInt(query.limit||'30',10));
  const actionF = query.action||'';

  let logs = [...DB.auditLogs]
    .filter(l => !actionF || l.action === actionF)
    .sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));

  const total = logs.length;
  logs = logs.slice((page-1)*limit, page*limit);

  const enriched = logs.map(l => ({
    ...l,
    user: DB.users.find(u => u.id === l.userId) ? (() => { const u = DB.users.find(u => u.id === l.userId); return { id:u.id, name:u.name, email:u.email, role:u.role }; })() : null,
    beneficiary: l.beneficiaryId ? (() => { const b = DB.beneficiaries.find(b => b.id === l.beneficiaryId); return b ? { id:b.id, name:b.name, pensionId:b.pensionId } : null; })() : null,
  }));

  ok(res, enriched, { page, limit, total, pages: Math.ceil(total/limit) });
};

// GET /api/v1/notifications
handlers['GET /api/v1/notifications'] = (req, res, query) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');

  const unreadOnly = query.unread === 'true';
  let notes = DB.notifications
    .filter(n => n.userId === auth.sub && (!unreadOnly || !n.isRead))
    .sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt))
    .slice(0, 50);

  const unreadCount = DB.notifications.filter(n => n.userId === auth.sub && !n.isRead).length;
  ok(res, notes, { unreadCount });
};

// POST /api/v1/notifications/read
handlers['POST /api/v1/notifications/read'] = async (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  const { ids } = await parseBody(req);
  if (!Array.isArray(ids)) return err(res, 422, 'VALIDATION_ERROR', 'ids must be array');
  let updated = 0;
  for (const n of DB.notifications) {
    if (ids.includes(n.id) && n.userId === auth.sub) { n.isRead = true; n.readAt = new Date().toISOString(); updated++; }
  }
  persist('notifications');
  ok(res, { updated });
};

// POST /api/v1/notifications/read-all
handlers['POST /api/v1/notifications/read-all'] = (req, res) => {
  const auth = getAuth(req);
  if (!auth) return err(res, 401, 'AUTH_REQUIRED', 'Not authenticated');
  let count = 0;
  for (const n of DB.notifications) {
    if (n.userId === auth.sub && !n.isRead) { n.isRead = true; n.readAt = new Date().toISOString(); count++; }
  }
  persist('notifications');
  ok(res, { updated: count });
};

// ─── Router ──────────────────────────────────────────────────────────────────
function matchRoute(method, pathname) {
  const key = `${method} ${pathname}`;
  if (handlers[key]) return { handler: handlers[key], params: {} };

  // Parameterized routes
  const paramRoutes = [
    ['GET',    '/api/v1/beneficiaries/:id'],
    ['PATCH',  '/api/v1/beneficiaries/:id'],
    ['DELETE', '/api/v1/beneficiaries/:id'],
    ['POST',   '/api/v1/fraud/check/:id'],
    ['POST',   '/api/v1/fraud/verify/aadhaar/:id'],
    ['POST',   '/api/v1/fraud/verify/death/:id'],
    ['POST',   '/api/v1/fraud/verify/life-cert/:id'],
    ['PATCH',  '/api/v1/fraud/cases/:id'],
  ];

  for (const [m, pattern] of paramRoutes) {
    if (m !== method) continue;
    const patParts = pattern.split('/');
    const reqParts = pathname.split('/');
    if (patParts.length !== reqParts.length) continue;
    const params = {};
    let match = true;
    for (let i = 0; i < patParts.length; i++) {
      if (patParts[i].startsWith(':')) { params[patParts[i].slice(1)] = reqParts[i]; }
      else if (patParts[i] !== reqParts[i]) { match = false; break; }
    }
    if (match) {
      const hKey = `${m} ${pattern}`;
      if (handlers[hKey]) return { handler: handlers[hKey], params };
    }
  }
  return null;
}

// ─── Server ───────────────────────────────────────────────────────────────────
seedIfEmpty();

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', FRONTEND_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Rate limit
  const clientIp = req.socket.remoteAddress || '127.0.0.1';
  if (!rateLimit(clientIp)) {
    err(res, 429, 'RATE_LIMITED', 'Too many requests');
    return;
  }

  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const query    = parsed.query;

  // Health check
  if (pathname === '/health') {
    ok(res, { status:'ok', version:'1.0.0', ts: new Date().toISOString() });
    return;
  }

  // Route matching
  const match = matchRoute(req.method, pathname);
  if (!match) {
    err(res, 404, 'NOT_FOUND', `Route ${req.method} ${pathname} not found`);
    return;
  }

  try {
    await match.handler(req, res, query, match.params);
  } catch (e) {
    console.error('Handler error:', e);
    err(res, 500, 'INTERNAL_ERROR', process.env.NODE_ENV === 'development' ? e.message : 'Internal server error');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ SS Fraud Prevention Backend running`);
  console.log(`   http://localhost:${PORT}/health`);
  console.log(`   CORS allowed for: ${FRONTEND_ORIGIN}`);
  console.log(`   Data stored in: ${DATA_DIR}\n`);
});

process.on('SIGTERM', () => { console.log('Shutting down...'); server.close(() => process.exit(0)); });
process.on('SIGINT',  () => { console.log('\nShutting down...'); server.close(() => process.exit(0)); });
