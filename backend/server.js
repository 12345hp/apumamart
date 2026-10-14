// ApumaMart Backend - Railway/Heroku entry point.
// Mounts the actions router at /api/actions (same as Hostinger).
// Env vars needed: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
//   RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
const express = require('express');
const { initDb } = require('./db');

const app = express();

// Trust Railway/Heroku proxy for correct IPs (rate limiting).
app.set('trust proxy', 1);

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

const PORT = process.env.PORT || 3000;

(async () => {
  try {
    if (typeof initDb === 'function') await initDb();
  } catch (e) {
    console.error('[server] DB init warning:', e.message);
  }
  app.listen(PORT, () => console.log('[server] listening on :' + PORT));
})();
