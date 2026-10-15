// ApumaMart Backend - Railway/Heroku entry point.
// Mounts the actions router at /api/actions (same as Hostinger).
// Env vars needed: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
//   RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
//
// 1-Year Warranty Reliability:
// - Structured JSON logging with request IDs
// - Graceful shutdown (SIGTERM/SIGINT)
// - Exit on untrusted errors (let Railway restart)
const express = require('express');
const crypto = require('crypto');
const { initDb, getPoolIfReady } = require('./db');

const app = express();

// Trust Railway/Heroku proxy for correct IPs (rate limiting).
app.set('trust proxy', 1);

// ===== Structured JSON Logger =====
function log(level, msg, meta) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...(meta || {}),
  };
  const out = JSON.stringify(entry);
  if (level === 'error' || level === 'fatal') {
    console.error(out);
  } else {
    console.log(out);
  }
}

// Request ID middleware + request logging
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    log('info', 'request', {
      reqId: req.id,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ms,
    });
  });
  next();
});

// CORS: allow the frontend to call the API.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// JSON body parsing (webhook route uses its own raw parser).
app.use(express.json({ limit: '2mb' }));

// Mount API router (actions, /health, /razorpay-webhook).
app.use('/api/actions', require('./actions'));

// Root: simple status page.
app.get('/', (req, res) => res.json({ ok: true, service: 'apumamart-backend' }));

// Centralized error handler (must be last)
app.use((err, req, res, next) => {
  log('error', 'unhandled request error', {
    reqId: req.id,
    error: err.message,
    stack: err.stack,
  });
  res.status(500).json({ ok: false, error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
let server = null;

// ===== Graceful Shutdown =====
async function gracefulShutdown(signal) {
  log('info', `received ${signal}, starting graceful shutdown`);

  // Stop accepting new connections, drain in-flight (10s max)
  if (server) {
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        log('warn', 'force closing server after 10s timeout');
        resolve();
      }, 10000);
      server.close(() => {
        clearTimeout(timer);
        log('info', 'server closed, no longer accepting connections');
        resolve();
      });
    });
  }

  // Close DB pool
  try {
    const pool = getPoolIfReady();
    if (pool) {
      await pool.end();
      log('info', 'database pool closed');
    }
  } catch (e) {
    log('error', 'error closing DB pool', { error: e.message });
  }

  log('info', 'graceful shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ===== Exit on Untrusted Errors (let Railway restart) =====
process.on('uncaughtException', (err) => {
  log('fatal', 'uncaught exception, exiting', {
    error: err.message,
    stack: err.stack,
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  log('fatal', 'unhandled rejection, exiting', {
    reason: String(reason),
  });
  process.exit(1);
});

// ===== Start Server =====
(async () => {
  try {
    if (typeof initDb === 'function') await initDb();
    log('info', 'database initialized');
  } catch (e) {
    log('error', 'DB init warning', { error: e.message });
  }
  server = app.listen(PORT, () => {
    log('info', `server listening`, { port: PORT });
  });
})();
