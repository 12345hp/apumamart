// ApumaMart Backend - hardened entry point (Hostinger + Railway).
//
// PERMANENT-RELIABILITY DESIGN (1-year warranty):
//  1. The HTTP server ALWAYS starts listening, even if the DB is down or a
//     module fails to load. Degraded JSON (503) beats a dead process.
//  2. DB init runs in the background with retries: transient DB outages at
//     boot no longer require a redeploy to recover from.
//  3. Uncaught errors are logged, never fatal: the process does NOT exit on
//     uncaughtException/unhandledRejection (Hostinger does not reliably
//     restart the process, so exiting turns a transient bug into a full
//     outage).
//  4. Complete /api/auth/* REST surface lives here, so the /api/actions
//     forwards (login, signUp, logout, OTP, forgot-password, applock) resolve
//     instead of 404ing into "bad gateway response".
//
// Env vars needed: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
//   MSG91_AUTH_KEY, MSG91_DLT_TEMPLATE_ID,
//   RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
const express = require('express');
const crypto = require('crypto');
const https = require('https');

// ---------------------------------------------------------------------------
// Safe module loading: a broken/missing module must never prevent boot.
// ---------------------------------------------------------------------------
function safeRequire(name) {
  try {
    return require(name);
  } catch (e) {
    console.error(JSON.stringify({
      ts: new Date().toISOString(), level: 'error',
      msg: 'module failed to load: ' + name, error: e.message,
    }));
    return null;
  }
}

const db = safeRequire('./db');
const initDb = db && typeof db.initDb === 'function' ? db.initDb : null;
function dbReady() {
  try { return !!(db && typeof db.isReady === 'function' && db.isReady()); }
  catch (_) { return false; }
}
function dbLastError() {
  try { return db && typeof db.dbError === 'function' ? db.dbError() : null; }
  catch (_) { return null; }
}
function getPool() {
  if (!db || typeof db.getPool !== 'function') {
    const e = new Error('database module not loaded');
    e.code = 'DB_NOT_CONNECTED';
    throw e;
  }
  return db.getPool(); // throws DB_NOT_CONNECTED when pool is null
}
function getPoolIfReady() {
  try { return db && typeof db.getPoolIfReady === 'function' ? db.getPoolIfReady() : null; }
  catch (_) { return null; }
}

let bcrypt = safeRequire('bcryptjs');
if (!bcrypt) {
  console.error(JSON.stringify({
    ts: new Date().toISOString(), level: 'error',
    msg: 'bcryptjs not available: password signup/login disabled until installed',
  }));
}

// ---------------------------------------------------------------------------
// Structured JSON logger
// ---------------------------------------------------------------------------
function log(level, msg, meta) {
  const entry = { ts: new Date().toISOString(), level, msg, ...(meta || {}) };
  const out = JSON.stringify(entry);
  if (level === 'error' || level === 'fatal') console.error(out);
  else console.log(out);
}

const app = express();
app.set('trust proxy', 1);

// Request ID + request logging
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  const start = Date.now();
  res.on('finish', () => {
    log('info', 'request', {
      reqId: req.id, method: req.method, path: req.path,
      status: res.statusCode, ms: Date.now() - start,
    });
  });
  next();
});

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// JSON body parsing. The verify hook stashes the exact raw bytes on
// req.rawBody: the Razorpay webhook signature is HMAC over the raw body,
// so it can never be checked against re-serialized parsed JSON.
app.use(express.json({
  limit: '2mb',
  verify: (req, res, buf) => { req.rawBody = buf; },
}));

// Request timeout: clean JSON 503 instead of a hanging socket.
app.use((req, res, next) => {
  const t = setTimeout(() => {
    if (!res.headersSent) {
      res.status(503).json({ ok: false, error: 'request timeout, please retry' });
    }
  }, 25000);
  res.on('finish', () => clearTimeout(t));
  next();
});

// ---------------------------------------------------------------------------
// Auth helpers (local copies: zero dependency on other modules at request time)
// ---------------------------------------------------------------------------
function hashToken(t) {
  return crypto.createHash('sha256').update(String(t)).digest('hex');
}
function normMobile(m) {
  let d = String(m || '').replace(/\D/g, '');
  if (d.length === 12 && d.startsWith('91')) d = d.slice(2);
  else if (d.length === 11 && d.startsWith('0')) d = d.slice(1);
  return d;
}

// International mobiles (2026-10-22, India+UAE build Phase 1).
// India: 10-digit national, stored bare (the system's historic format).
// UAE: 9-digit national starting with 5; stored FULL as '971' + national so
// it can never collide with an Indian number in the UNIQUE mobile column.
// Returns { country, national, full, stored } or null when unrecognised.
function parseIntlMobile(m) {
  let d = String(m || '').replace(/\D/g, '');
  if (d.startsWith('00')) d = d.slice(2);
  if (d.length === 12 && d.startsWith('971')) return { country: 'AE', national: d.slice(3), full: d, stored: d };
  if (d.length === 9 && d.startsWith('5')) return { country: 'AE', national: d, full: '971' + d, stored: '971' + d };
  if (d.length === 12 && d.startsWith('91')) return { country: 'IN', national: d.slice(2), full: d, stored: d.slice(2) };
  if (d.length === 11 && d.startsWith('0')) return { country: 'IN', national: d.slice(1), full: '91' + d.slice(1), stored: d.slice(1) };
  if (d.length === 10) return { country: 'IN', national: d, full: '91' + d, stored: d };
  return null;
}

function mobForStorage(m) { const p = parseIntlMobile(m); return p ? p.stored : normMobile(m); }

function pubUser(u) {
  if (!u) return u;
  const { password_hash, security_answer_hash, app_pin_hash, ...rest } = u; // eslint-disable-line no-unused-vars
  return rest;
}

// Login brute-force throttle: 5 failed attempts / mobile / 15 min -> 429.
const loginFails = new Map();
function loginBlocked(mob) {
  const r = loginFails.get(mob);
  if (!r) return false;
  if (Date.now() - r.first > 15 * 60 * 1000) { loginFails.delete(mob); return false; }
  return r.count >= 5;
}
function loginFailed(mob) {
  let r = loginFails.get(mob);
  if (!r || Date.now() - r.first > 15 * 60 * 1000) r = { count: 0, first: Date.now() };
  r.count += 1;
  loginFails.set(mob, r);
  if (loginFails.size > 5000) loginFails.clear(); // safety cap
}
function loginOk(mob) { loginFails.delete(mob); }

function logEvent(userId, event, ip, detail) {
  // Fire-and-forget: logging must never break a request.
  try {
    if (!dbReady()) return;
    getPool().execute(
      'INSERT INTO security_events (user_id, event, ip, detail) VALUES (?,?,?,?)',
      [userId || null, event, ip || null, detail ? String(detail).slice(0, 255) : null]
    ).catch(() => {});
  } catch (_) { /* ignore */ }
}

// Session lookup mirroring the /api/actions auth semantics:
// 30-min sliding idle window, 8-hour absolute cap, outer expires_at bound.
async function authSession(req) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!m) return { error: 'missing bearer token', status: 401 };
  if (!dbReady()) return { error: 'database not available', status: 503 };
  const pool = getPool();
  const [rows] = await pool.execute(
    `SELECT s.id AS sid, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.is_locked,
            u.name, u.mobile, u.role, u.business_name, u.business_address, u.business_phone,
            u.app_lock_enabled
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`,
    [hashToken(m[1])]
  );
  const s = rows[0];
  if (!s) return { error: 'invalid token', status: 401 };
  const now = Date.now();
  const expired =
    (s.expires_at && now > new Date(s.expires_at).getTime()) ||
    (s.created_at && now - new Date(s.created_at).getTime() > 8 * 3600 * 1000) ||
    (s.last_seen_at && now - new Date(s.last_seen_at).getTime() > 30 * 60 * 1000);
  if (expired) {
    await pool.execute('DELETE FROM sessions WHERE id = ?', [s.sid]);
    return { error: 'session expired', status: 401 };
  }
  await pool.execute(
    'UPDATE sessions SET last_seen_at = NOW(), expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE id = ?',
    [s.sid]
  );
  return {
    user: {
      id: s.user_id, name: s.name, mobile: s.mobile, role: s.role,
      business_name: s.business_name, business_address: s.business_address,
      business_phone: s.business_phone, app_lock_enabled: !!s.app_lock_enabled,
    },
    sessionId: s.sid,
    locked: !!s.is_locked,
  };
}

// MSG91 helper (OTP send/verify fallback)
function msg91Get(path) {
  return new Promise((resolve, reject) => {
    const authkey = process.env.MSG91_AUTH_KEY;
    if (!authkey) { reject(new Error('MSG91_AUTH_KEY not configured')); return; }
    const sep = path.includes('?') ? '&' : '?';
    const url = `https://control.msg91.com${path}${sep}authkey=${encodeURIComponent(authkey)}`;
    const r = https.get(url, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (_) { resolve({ raw: data }); } });
    });
    r.on('error', reject);
    r.setTimeout(10000, () => r.destroy(new Error('MSG91 timeout')));
  });
}

// ---------------------------------------------------------------------------
// Plain status / health endpoints (never depend on DB or the actions router)
// ---------------------------------------------------------------------------
app.get('/', (req, res) => res.json({ ok: true, service: 'apumamart-backend' }));

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'apumamart-backend', db: dbReady(), ts: new Date().toISOString() });
});

app.get('/api/actions/health', (req, res) => {
  res.json({ ok: true, db: dbReady(), ts: new Date().toISOString() });
});

// ---------------------------------------------------------------------------
// /api/auth/* REST endpoints.
// Used directly by the app AND by the /api/actions forwards
// (login, signUp, logout, requestOtp, verifyOtp, getSecurityQuestion,
//  resetPassword, configureAppLock, lockApp, unlockApp).
// Response carries every shape clients expect:
//   { ok, token, session_token, user, account: { session_token, user } }
// ---------------------------------------------------------------------------
function needDb(res) {
  if (!dbReady()) { res.status(503).json({ ok: false, error: 'database not available' }); return false; }
  return true;
}
function needBcrypt(res) {
  if (!bcrypt) { res.status(500).json({ ok: false, error: 'password auth temporarily unavailable' }); return false; }
  return true;
}
function authOkBody(token, user) {
  const u = pubUser(user);
  return { ok: true, token, session_token: token, user: u, account: { session_token: token, user: u } };
}

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    if (!needDb(res) || !needBcrypt(res)) return;
    const b = req.body || {};
    const name = b.name ? String(b.name).slice(0, 100) : null;
    const mob = mobForStorage(b.mobile);
    const signupCountry = (parseIntlMobile(b.mobile) || {}).country || (String(b.country || '').toUpperCase() === 'AE' ? 'AE' : 'IN');
    const password = b.password ? String(b.password) : '';
    const sq = String(b.security_question || b.securityQuestion || '').slice(0, 255);
    const sa = String(b.security_answer || b.securityAnswer || '');
    const biz = String(b.business_name || b.businessName || '').slice(0, 150) || null;
    if (!mob) return res.status(400).json({ ok: false, error: 'mobile is required' });
    // Country-select rule (Admin, 2026-10-22): the country picked FIRST at
    // signup must match the mobile number's country, and the number must
    // be a real India (10-digit) or UAE (9-digit) mobile. Anything else is
    // refused before anything is created - no silent wrong-country
    // accounts, no junk-number accounts.
    const pickedCountry = String(b.country || '').toUpperCase();
    const intlParsed = parseIntlMobile(b.mobile);
    if (!intlParsed) {
      return res.status(400).json({ ok: false, error: 'Sahi mobile number dalo - India ka 10 digit ya UAE ka 9 digit number' });
    }
    if ((pickedCountry === 'AE' || pickedCountry === 'IN') && intlParsed.country !== pickedCountry) {
      return res.status(400).json({ ok: false, error: 'Country aur mobile ka desh match nahi ho raha - sahi country chuno, ya usi desh ka mobile number dalo' });
    }
    if (!password || password.length < 4) return res.status(400).json({ ok: false, error: 'password must be at least 4 characters' });
    if (!sq || !sa) return res.status(400).json({ ok: false, error: 'security question and answer are required' });
    const pool = getPool();
    const [ex] = await pool.execute(
      'SELECT id FROM users WHERE mobile = ? OR mobile = ? OR mobile = ?',
      [mob, '91' + mob, '0' + mob]
    );
    if (ex.length) return res.status(409).json({ ok: false, error: 'mobile already registered' });
    const [cnt] = await pool.execute('SELECT COUNT(*) AS c FROM users');
    const role = cnt[0].c === 0 ? 'owner' : 'staff'; // first-ever user becomes owner
    const password_hash = await bcrypt.hash(password, 12);
    const security_answer_hash = await bcrypt.hash(sa.toLowerCase().trim(), 12);
    const [r] = await pool.execute(
      'INSERT INTO users (name, mobile, password_hash, security_question, security_answer_hash, role, business_name, country) VALUES (?,?,?,?,?,?,?,?)',
      [name, mob, password_hash, sq, security_answer_hash, role, biz, signupCountry]
    );
    const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [r.insertId]);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.execute(
      'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))',
      [r.insertId, hashToken(token)]
    );
    logEvent(r.insertId, 'signup', req.ip, 'role=' + role);
    res.status(201).json(authOkBody(token, rows[0]));
  } catch (e) {
    log('error', 'signup failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'signup mein error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    if (!needDb(res) || !needBcrypt(res)) return;
    const mob = mobForStorage(req.body && req.body.mobile);
    const password = req.body && req.body.password ? String(req.body.password) : '';
    if (!mob || !password) return res.status(400).json({ ok: false, error: 'mobile and password required' });
    if (loginBlocked(mob)) {
      logEvent(null, 'login_blocked', req.ip, mob);
      return res.status(429).json({ ok: false, error: 'too many failed attempts, try again later' });
    }
    const pool = getPool();
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE mobile = ? OR mobile = ? OR mobile = ?',
      [mob, '91' + mob, '0' + mob]
    );
    const u = rows[0];
    const ok = u && u.password_hash ? await bcrypt.compare(password, u.password_hash) : false;
    if (!ok) {
      loginFailed(mob);
      logEvent(u ? u.id : null, 'login_failed', req.ip, mob);
      return res.status(401).json({ ok: false, error: 'invalid mobile or password' });
    }
    loginOk(mob);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.execute(
      'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))',
      [u.id, hashToken(token)]
    );
    logEvent(u.id, 'login_ok', req.ip, null);
    res.json(authOkBody(token, u));
  } catch (e) {
    log('error', 'login failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'login mein error' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', async (req, res) => {
  try {
    if (!needDb(res)) return;
    const a = await authSession(req);
    if (a.error) return res.status(a.status || 401).json({ ok: false, error: a.error });
    await getPool().execute('DELETE FROM sessions WHERE id = ?', [a.sessionId]);
    logEvent(a.user.id, 'logout', req.ip, null);
    res.json({ ok: true });
  } catch (e) {
    log('error', 'logout failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'logout mein error' });
  }
});

// GET /api/auth/me — validate current session
app.get('/api/auth/me', async (req, res) => {
  try {
    if (!needDb(res)) return;
    const a = await authSession(req);
    if (a.error) return res.status(a.status || 401).json({ ok: false, error: a.error });
    res.json({ ok: true, user: a.user, locked: a.locked });
  } catch (e) {
    log('error', 'me failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/forgot/start — returns the security question for a mobile
app.post('/api/auth/forgot/start', async (req, res) => {
  try {
    if (!needDb(res)) return;
    const mob = mobForStorage(req.body && req.body.mobile);
    if (!mob) return res.status(400).json({ ok: false, error: 'mobile is required' });
    const [rows] = await getPool().execute(
      'SELECT security_question FROM users WHERE mobile = ? OR mobile = ? OR mobile = ?',
      [mob, '91' + mob, '0' + mob]
    );
    if (!rows.length || !rows[0].security_question) {
      return res.json({ ok: true, message: 'if this number is registered, use the security answer to reset' });
    }
    res.json({ ok: true, security_question: rows[0].security_question });
  } catch (e) {
    log('error', 'forgot/start failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/forgot/reset — verify answer, set new password
app.post('/api/auth/forgot/reset', async (req, res) => {
  try {
    if (!needDb(res) || !needBcrypt(res)) return;
    const b = req.body || {};
    const mob = mobForStorage(b.mobile);
    const answer = b.answer ? String(b.answer) : '';
    const newPassword = b.new_password || b.newPassword ? String(b.new_password || b.newPassword) : '';
    if (!mob || !answer) return res.status(400).json({ ok: false, error: 'mobile and answer required' });
    if (!newPassword || newPassword.length < 4) return res.status(400).json({ ok: false, error: 'new password must be at least 4 characters' });
    const pool = getPool();
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE mobile = ? OR mobile = ? OR mobile = ?',
      [mob, '91' + mob, '0' + mob]
    );
    const u = rows[0];
    const ok = u && u.security_answer_hash
      ? await bcrypt.compare(answer.toLowerCase().trim(), u.security_answer_hash)
      : false;
    if (!ok) {
      logEvent(u ? u.id : null, 'forgot_reset_failed', req.ip, mob);
      return res.status(401).json({ ok: false, error: 'wrong answer' });
    }
    const password_hash = await bcrypt.hash(newPassword, 12);
    await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [password_hash, u.id]);
    await pool.execute('DELETE FROM sessions WHERE user_id = ?', [u.id]); // log out everywhere
    logEvent(u.id, 'password_reset', req.ip, null);
    res.json({ ok: true });
  } catch (e) {
    log('error', 'forgot/reset failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/applock — enable/disable app PIN lock (verify current password)
app.post('/api/auth/applock', async (req, res) => {
  try {
    if (!needDb(res) || !needBcrypt(res)) return;
    const a = await authSession(req);
    if (a.error) return res.status(a.status || 401).json({ ok: false, error: a.error });
    const b = req.body || {};
    const enabled = !!b.enabled;
    const pin = b.pin ? String(b.pin) : '';
    const password = b.password ? String(b.password) : '';
    if (!password) return res.status(400).json({ ok: false, error: 'current password required' });
    if (enabled && !/^\d{4,8}$/.test(pin)) return res.status(400).json({ ok: false, error: 'PIN must be 4-8 digits' });
    const pool = getPool();
    const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [a.user.id]);
    const u = rows[0];
    const ok = u && u.password_hash ? await bcrypt.compare(password, u.password_hash) : false;
    if (!ok) {
      logEvent(a.user.id, 'applock_failed', req.ip, null);
      return res.status(401).json({ ok: false, error: 'password is incorrect' });
    }
    const pinHash = enabled ? await bcrypt.hash(pin, 12) : null;
    try {
      await pool.execute('UPDATE users SET app_lock_enabled = ?, app_pin_hash = ? WHERE id = ?', [enabled ? 1 : 0, pinHash, a.user.id]);
    } catch (colErr) {
      return res.status(500).json({ ok: false, error: 'applock columns missing, redeploy DB migrations' });
    }
    await pool.execute('UPDATE sessions SET is_locked = 0 WHERE user_id = ?', [a.user.id]);
    logEvent(a.user.id, enabled ? 'applock_enabled' : 'applock_disabled', req.ip, null);
    res.json({ ok: true, enabled });
  } catch (e) {
    log('error', 'applock failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/applock/lock — lock the current session now
app.post('/api/auth/applock/lock', async (req, res) => {
  try {
    if (!needDb(res)) return;
    const a = await authSession(req);
    if (a.error) return res.status(a.status || 401).json({ ok: false, error: a.error });
    const pool = getPool();
    let enabled = false;
    try {
      const [rows] = await pool.execute('SELECT app_lock_enabled FROM users WHERE id = ?', [a.user.id]);
      enabled = !!(rows[0] && rows[0].app_lock_enabled);
    } catch (_) { /* columns missing -> treat as disabled */ }
    if (!enabled) return res.json({ ok: true, locked: false });
    await pool.execute('UPDATE sessions SET is_locked = 1 WHERE id = ?', [a.sessionId]);
    logEvent(a.user.id, 'app_locked', req.ip, null);
    res.json({ ok: true, locked: true });
  } catch (e) {
    log('error', 'applock/lock failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/applock/unlock — unlock with PIN (checks session manually:
// a locked session must not go through the 423ing auth path)
app.post('/api/auth/applock/unlock', async (req, res) => {
  try {
    if (!needDb(res) || !needBcrypt(res)) return;
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    if (!m) return res.status(401).json({ ok: false, error: 'missing bearer token' });
    const pin = req.body && req.body.pin ? String(req.body.pin) : '';
    if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ ok: false, error: 'PIN must be 4-8 digits' });
    const pool = getPool();
    let s = null;
    try {
      const [rows] = await pool.execute(
        'SELECT s.id AS sid, s.user_id, u.app_lock_enabled, u.app_pin_hash FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?',
        [hashToken(m[1])]
      );
      s = rows[0] || null;
    } catch (_) { return res.status(500).json({ ok: false, error: 'applock columns missing, redeploy DB migrations' }); }
    if (!s) return res.status(401).json({ ok: false, error: 'invalid token' });
    const ok = s.app_lock_enabled && s.app_pin_hash ? await bcrypt.compare(pin, s.app_pin_hash) : false;
    if (!ok) {
      logEvent(s.user_id, 'applock_unlock_failed', req.ip, null);
      return res.status(401).json({ ok: false, error: 'PIN is incorrect' });
    }
    await pool.execute('UPDATE sessions SET is_locked = 0, last_seen_at = NOW(), expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE id = ?', [s.sid]);
    logEvent(s.user_id, 'app_unlocked', req.ip, null);
    res.json({ ok: true });
  } catch (e) {
    log('error', 'applock/unlock failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/otp/request — owner/admin OTP via MSG91 (self-generated, DB-verified)
app.post('/api/auth/otp/request', async (req, res) => {
  try {
    if (!needDb(res)) return;
    const mobile = String((req.body && req.body.mobile) || '').replace(/\D/g, '').slice(-10);
    if (mobile.length !== 10) return res.status(400).json({ ok: false, error: '10 digit mobile required' });
    const pool = getPool();
    const [u] = await pool.execute(
      "SELECT id, role FROM users WHERE (mobile = ? OR mobile = ? OR mobile = ?) AND role IN ('owner','admin')",
      [mobile, '91' + mobile, '0' + mobile]
    );
    if (!u[0]) return res.status(403).json({ ok: false, error: 'sirf owner/admin OTP login kar sakte hain' });
    const otp = String(Math.floor(1000 + Math.random() * 9000));
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
    const expiresAt = Date.now() + 5 * 60 * 1000;
    try {
      await pool.execute('DELETE FROM mart_otps WHERE mobile = ?', [mobile]);
      await pool.execute(
        'INSERT INTO mart_otps (mobile, otp_hash, attempts, expires_at, created_at) VALUES (?, ?, 0, ?, ?)',
        [mobile, otpHash, expiresAt, Date.now()]
      );
    } catch (_) { /* table may not exist yet, continue */ }
    const dltTemplate = process.env.MSG91_DLT_TEMPLATE_ID || '';
    let otpPath = `/api/v5/otp?mobile=91${mobile}&otp=${otp}`;
    if (dltTemplate) otpPath += `&template_id=${encodeURIComponent(dltTemplate)}`;
    let result;
    try {
      result = await msg91Get(otpPath);
    } catch (msgErr) {
      return res.status(502).json({ ok: false, error: 'SMS bhejne mein fail: ' + (msgErr.message || 'network error') });
    }
    if (result && result.type === 'success') return res.json({ ok: true, message: 'OTP bheja gaya!' });
    return res.status(502).json({ ok: false, error: (result && result.message) || 'OTP bhejne mein fail' });
  } catch (e) {
    log('error', 'otp/request failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// POST /api/auth/otp/verify — verify OTP, create 30-day session
app.post('/api/auth/otp/verify', async (req, res) => {
  try {
    if (!needDb(res)) return;
    const mobile = String((req.body && req.body.mobile) || '').replace(/\D/g, '').slice(-10);
    const otp = String((req.body && req.body.otp) || '').trim();
    if (mobile.length !== 10 || !otp) return res.status(400).json({ ok: false, error: 'mobile aur otp required' });
    const pool = getPool();
    let verified = false;
    try {
      const [rows] = await pool.execute(
        'SELECT * FROM mart_otps WHERE mobile = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1',
        [mobile]
      );
      const rec = rows[0];
      if (rec) {
        if (Date.now() > Number(rec.expires_at)) {
          await pool.execute('DELETE FROM mart_otps WHERE mobile = ?', [mobile]);
        } else if (Number(rec.attempts) >= 5) {
          return res.status(429).json({ ok: false, error: '5 galat attempts! 15 min ruko.' });
        } else {
          const hash = crypto.createHash('sha256').update(otp).digest('hex');
          if (hash === rec.otp_hash) {
            verified = true;
            await pool.execute('UPDATE mart_otps SET consumed_at = ? WHERE id = ?', [Date.now(), rec.id]);
          } else {
            await pool.execute('UPDATE mart_otps SET attempts = attempts + 1 WHERE id = ?', [rec.id]);
          }
        }
      }
    } catch (_) { /* fall through to MSG91 */ }
    if (!verified && process.env.MSG91_AUTH_KEY) {
      try {
        const result = await msg91Get(`/api/v5/otp/verify?mobile=91${mobile}&otp=${encodeURIComponent(otp)}`);
        if (result && (result.type === 'success' || result.message === 'OTP verified successfully.')) verified = true;
      } catch (_) {}
    }
    if (!verified) return res.status(400).json({ ok: false, error: 'galat OTP!' });
    const [u] = await pool.execute(
      "SELECT * FROM users WHERE (mobile = ? OR mobile = ? OR mobile = ?) AND role IN ('owner','admin')",
      [mobile, '91' + mobile, '0' + mobile]
    );
    const user = u[0];
    if (!user) return res.status(404).json({ ok: false, error: 'user not found' });
    const token = crypto.randomBytes(32).toString('hex');
    await pool.execute(
      'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))',
      [user.id, hashToken(token)]
    );
    logEvent(user.id, 'otp_login_ok', req.ip, null);
    res.json(authOkBody(token, user));
  } catch (e) {
    log('error', 'otp/verify failed', { reqId: req.id, error: e.message });
    res.status(500).json({ ok: false, error: 'server error' });
  }
});

// ---------------------------------------------------------------------------
// Actions router (guarded: a broken actions.js must not take the server down)
// ---------------------------------------------------------------------------
let actionsRouter = null;
try {
  actionsRouter = require('./actions');
} catch (e) {
  log('fatal', 'actions router failed to load; mounting degraded stub', { error: e.message, stack: e.stack });
}
if (actionsRouter) {
  app.use('/api/actions', actionsRouter);
} else {
  app.use('/api/actions', (req, res) => {
    if (req.path === '/health') return res.json({ ok: true, db: dbReady(), degraded: true });
    res.status(503).json({ ok: false, error: 'backend updating, please retry shortly' });
  });
}

// Centralized error handler (must be last)
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  log('error', 'unhandled request error', { reqId: req.id, error: err.message, stack: err.stack });
  if (!res.headersSent) {
    const status = err.status || 500;
    const message = status >= 500 ? 'Internal server error' : err.message;
    res.status(status).json({ ok: false, error: message });
  }
});

// ---------------------------------------------------------------------------
// Startup: LISTEN FIRST, then init DB in the background with retries.
// A DB outage at boot must never prevent the port from opening.
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
let server = null;

async function initDbBackground() {
  if (!initDb) {
    log('warn', 'db module not loaded; running without database (no retries)');
    return;
  }
  let attempt = 0;
  for (;;) {
    attempt += 1;
    try {
      await initDb();
    } catch (e) {
      log('error', 'DB init threw; retrying in 30s', { attempt, error: e.message });
    }
    if (dbReady()) {
      log('info', 'database ready', { attempt });
      return;
    }
    const errMsg = dbLastError() || '';
    if (/env vars missing/i.test(errMsg)) {
      log('warn', 'DB env vars missing; running without database (set vars + redeploy to enable)');
      return; // retrying is pointless without a redeploy
    }
    log('warn', 'database not ready; retrying in 30s', { attempt, error: errMsg || undefined });
    await new Promise((r) => setTimeout(r, 30000));
  }
}

async function gracefulShutdown(signal) {
  log('info', `received ${signal}, starting graceful shutdown`);
  if (server) {
    await new Promise((resolve) => {
      const timer = setTimeout(() => { log('warn', 'force closing server after 10s timeout'); resolve(); }, 10000);
      server.close(() => { clearTimeout(timer); log('info', 'server closed'); resolve(); });
    });
  }
  try {
    const pool = getPoolIfReady();
    if (pool) { await pool.end(); log('info', 'database pool closed'); }
  } catch (e) {
    log('error', 'error closing DB pool', { error: e.message });
  }
  log('info', 'graceful shutdown complete');
  process.exit(0);
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// PERMANENT-RELIABILITY: log fatal errors but KEEP SERVING.
// Hostinger does not reliably restart a dead process (observed: hours-long
// 503s after "Completed" deployments), so exiting on an uncaught error turns
// a transient bug into a total outage. Every request path above has its own
// try/catch; these handlers are the last line of defense, not a suicide switch.
process.on('uncaughtException', (err) => {
  log('fatal', 'uncaught exception (server keeps running)', { error: err.message, stack: err.stack });
});
process.on('unhandledRejection', (reason) => {
  log('fatal', 'unhandled rejection (server keeps running)', { reason: String(reason && reason.stack || reason) });
});

server = app.listen(PORT, () => {
  log('info', 'server listening', { port: PORT, db: dbReady(), actions: actionsRouter ? 'loaded' : 'STUB' });
});
// DB init must not block the port from opening.
initDbBackground().catch((e) => log('fatal', 'db background loop died', { error: String(e && e.message || e) }));

module.exports = app;
