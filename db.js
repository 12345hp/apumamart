// ApumaMart backend — MySQL pool + idempotent schema init.
// DB credentials come ONLY from env vars. If they are missing or the DB is
// unreachable, the API still boots and /api/health keeps responding.
const mysql = require('mysql2/promise');

let pool = null;
let ready = false;
let lastError = null;

function getPool() {
  if (!pool) {
    const err = new Error('Database not connected' + (lastError ? ': ' + lastError : ''));
    err.code = 'DB_NOT_CONNECTED';
    throw err;
  }
  return pool;
}
// Unsafe accessor for shutdown paths that must not throw.
function getPoolIfReady() { return pool; }
function isReady() { return ready; }
function dbError() { return lastError; }

const SCHEMA = [
`CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NULL,
  mobile VARCHAR(20) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NULL,
  security_question VARCHAR(255) NULL,
  security_answer_hash VARCHAR(255) NULL,
  role ENUM('owner','admin','staff') NOT NULL DEFAULT 'staff',
  business_name VARCHAR(150) NULL,
  business_address TEXT NULL,
  business_phone VARCHAR(20) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sessions_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS customers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  mobile VARCHAR(20) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_customers_user (user_id),
  INDEX idx_customers_user_name (user_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS bills (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  customer_id INT NULL,
  bill_no VARCHAR(40) NULL,
  mode ENUM('future','modern') NOT NULL DEFAULT 'future',
  items JSON NOT NULL,
  subtotal DECIMAL(12,2) NOT NULL DEFAULT 0,
  discount DECIMAL(12,2) NOT NULL DEFAULT 0,
  gst_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
  total DECIMAL(12,2) NOT NULL,
  joma DECIMAL(12,2) NOT NULL DEFAULT 0,
  baki DECIMAL(12,2) NOT NULL DEFAULT 0,
  counter VARCHAR(50) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_bills_user_created (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  customer_id INT NOT NULL,
  amount DECIMAL(12,2) NOT NULL,
  note VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_payments_user_customer (user_id, customer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS suppliers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  mobile VARCHAR(20) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_suppliers_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS supplier_txns (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  supplier_id INT NOT NULL,
  type ENUM('credit','payment') NOT NULL,
  amount DECIMAL(12,2) NOT NULL,
  note VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_stxn_user_supplier (user_id, supplier_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(150) NOT NULL,
  sku VARCHAR(60) NULL,
  barcode VARCHAR(60) NULL,
  price DECIMAL(12,2) NOT NULL DEFAULT 0,
  cost DECIMAL(12,2) NOT NULL DEFAULT 0,
  gst_pct DECIMAL(5,2) NOT NULL DEFAULT 0,
  stock DECIMAL(12,3) NOT NULL DEFAULT 0,
  low_stock_at DECIMAL(12,3) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_products_user (user_id),
  INDEX idx_products_user_barcode (user_id, barcode)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS expenses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  amount DECIMAL(12,2) NOT NULL,
  category VARCHAR(80) NULL,
  note VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_expenses_user_created (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS security_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  event VARCHAR(80) NOT NULL,
  ip VARCHAR(60) NULL,
  detail VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS mart_otps (
  id INT AUTO_INCREMENT PRIMARY KEY,
  mobile VARCHAR(20) NOT NULL,
  otp_hash VARCHAR(255) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  expires_at BIGINT NOT NULL,
  consumed_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  INDEX idx_mart_otps_mobile (mobile)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS counters (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(80) NOT NULL,
  cashier VARCHAR(100) NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_counters_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS coupons (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  code VARCHAR(40) NOT NULL,
  pct DECIMAL(5,2) NOT NULL DEFAULT 0,
  flat DECIMAL(12,2) NOT NULL DEFAULT 0,
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_coupons_user_code (user_id, code),
  INDEX idx_coupons_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  mobile VARCHAR(20) NULL,
  points INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_members_user (user_id),
  INDEX idx_members_user_name (user_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS purchase_orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  supplier_id INT NULL,
  items JSON NOT NULL,
  total DECIMAL(12,2) NOT NULL DEFAULT 0,
  status ENUM('pending','received') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_po_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS day_closes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  counter_id INT NULL,
  date DATE NOT NULL,
  expected_cash DECIMAL(12,2) NOT NULL DEFAULT 0,
  actual_cash DECIMAL(12,2) NOT NULL DEFAULT 0,
  note VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_daycloses_user_date (user_id, date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS staff (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  mobile VARCHAR(20) NULL,
  pin_hash VARCHAR(255) NOT NULL,
  role VARCHAR(30) NOT NULL DEFAULT 'staff',
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_staff_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS stores (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(150) NOT NULL,
  address VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_stores_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS staff_attendance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  staff_id INT NOT NULL,
  check_in TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  check_out TIMESTAMP NULL,
  INDEX idx_att_user_staff (user_id, staff_id),
  INDEX idx_att_checkin (check_in)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS pos_staff (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  phone VARCHAR(20) NULL,
  monthly_salary DECIMAL(12,2) NOT NULL DEFAULT 0,
  join_date DATE NULL,
  staff_pin VARCHAR(255) NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_posstaff_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS pos_attendance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  staff_id INT NOT NULL,
  date DATE NOT NULL,
  status ENUM('present','absent','half','leave') NOT NULL DEFAULT 'present',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_posatt_user_staff_date (user_id, staff_id, date),
  INDEX idx_posatt_user_date (user_id, date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS pos_advance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  staff_id INT NOT NULL,
  amount DECIMAL(12,2) NOT NULL,
  date DATE NOT NULL,
  note VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_posadv_user_staff (user_id, staff_id),
  INDEX idx_posadv_user_date (user_id, date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS rate_cards (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  rate DECIMAL(12,2) NOT NULL DEFAULT 0,
  unit VARCHAR(20) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_rate_cards_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS app_settings (
  user_id INT NOT NULL PRIMARY KEY,
  support_phone VARCHAR(30) NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS subscriptions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  product_id VARCHAR(100) NULL,
  purchase_token TEXT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'pending_verification',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sub_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS web_subscription_orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  plan_id VARCHAR(50) NOT NULL,
  razorpay_order_id VARCHAR(100) UNIQUE NOT NULL,
  razorpay_payment_id VARCHAR(100),
  amount INT NOT NULL,
  status VARCHAR(20) DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  paid_at DATETIME,
  INDEX idx_user (user_id),
  INDEX idx_order (razorpay_order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS user_subscriptions (
  user_id INT PRIMARY KEY,
  tier VARCHAR(20) NOT NULL,
  plan_id VARCHAR(50) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS branches (
  id INT AUTO_INCREMENT PRIMARY KEY,
  owner_user_id INT NOT NULL,
  name VARCHAR(150) NOT NULL,
  address TEXT NULL,
  phone VARCHAR(20) NULL,
  manager_name VARCHAR(100) NULL,
  manager_mobile VARCHAR(20) NULL,
  access_token CHAR(64) NOT NULL UNIQUE,
  token_active TINYINT(1) NOT NULL DEFAULT 1,
  branch_user_id INT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_branches_owner (owner_user_id),
  INDEX idx_branches_token (access_token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS pos_gift_cards (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  code VARCHAR(50) NOT NULL,
  amount DECIMAL(12,2) NOT NULL DEFAULT 0,
  balance DECIMAL(12,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_giftcards_user (user_id),
  INDEX idx_giftcards_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS pos_recurring_bills (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  title VARCHAR(150) NOT NULL,
  amount DECIMAL(12,2) NOT NULL DEFAULT 0,
  frequency VARCHAR(20) NOT NULL DEFAULT 'monthly',
  customer_name VARCHAR(100) NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_recbills_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
`CREATE TABLE IF NOT EXISTS pos_online_orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  customer_name VARCHAR(100) NULL,
  phone VARCHAR(20) NULL,
  items JSON NULL,
  total DECIMAL(12,2) NOT NULL DEFAULT 0,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_onlineorders_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

// Delivery slots + OTP (2026-10-19): real tables for delivery.html standalone page
`CREATE TABLE IF NOT EXISTS pos_delivery_slots (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  slot_time VARCHAR(50) NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_deliveryslots_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS pos_delivery_otps (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  order_id INT NOT NULL,
  otp_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  verified TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_deliveryotps_user_order (user_id, order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

// Security pack (2026-10-15): OTP brute-force lock + admin activity log + login alerts
`CREATE TABLE IF NOT EXISTS otp_attempts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  mobile VARCHAR(20) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMP NULL,
  last_attempt_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_otp_mobile (mobile),
  INDEX idx_otp_locked (locked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS admin_activity_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  mobile VARCHAR(20) NULL,
  action VARCHAR(100) NOT NULL,
  details TEXT NULL,
  ip VARCHAR(45) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_activity_user (user_id),
  INDEX idx_activity_action (action),
  INDEX idx_activity_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

`CREATE TABLE IF NOT EXISTS login_alerts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  mobile VARCHAR(20) NOT NULL,
  ip VARCHAR(45) NULL,
  user_agent VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_loginalert_user (user_id),
  INDEX idx_loginalert_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
];

// Add columns to bills that didn't exist in the original schema.
// MySQL has no ADD COLUMN IF NOT EXISTS, so check INFORMATION_SCHEMA first.
async function ensureBillColumns(pool) {
  const defs = {
    counter_id: 'INT NULL',
    payment_mode: 'VARCHAR(20) NULL',
    coupon_code: 'VARCHAR(40) NULL',
  };
  for (const [col, def] of Object.entries(defs)) {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'bills' AND COLUMN_NAME = ?`,
      [col]
    );
    if (!rows[0].c) {
      await pool.execute(`ALTER TABLE bills ADD COLUMN ${col} ${def}`);
      console.log('[db] bills: added column ' + col);
    }
  }
  // Branch support: branch_id on bills, customers, payments, expenses, suppliers (NULL = head/main, no branch filter)
  const branchTables = ['bills', 'customers', 'payments', 'expenses', 'suppliers'];
  for (const tbl of branchTables) {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'branch_id'`,
      [tbl]
    );
    if (!rows[0].c) {
      await pool.execute(`ALTER TABLE ${tbl} ADD COLUMN branch_id INT NULL, ADD INDEX idx_${tbl}_branch (branch_id)`);
      console.log('[db] ' + tbl + ': added column branch_id');
    }
  }
  // Business profile columns on users (needed by getBusinessProfile; missing columns crashed the Business tab)
  const userCols = [
    ['upi_id', 'VARCHAR(100) NULL'],
    ['loyalty_rate', 'DECIMAL(5,2) NULL'],
    ['store_code', 'VARCHAR(50) NULL'],
    ['online_store_enabled', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['shop_hours', 'VARCHAR(255) NULL'],
    ['return_policy', 'TEXT NULL'],
    ['gst_rate', 'DECIMAL(5,2) NULL'],
    ['gstin', 'VARCHAR(20) NULL'],
    ['pan_number', 'VARCHAR(20) NULL'],
    ['discount_percent', 'DECIMAL(5,2) NULL'],
    ['business_category', 'VARCHAR(100) NULL'],
    ['business_subcategory', 'VARCHAR(100) NULL'],
    ['photo_url', 'VARCHAR(500) NULL'],
  ];
  for (const [col, def] of userCols) {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = ?`,
      [col]
    );
    if (!rows[0].c) {
      await pool.execute(`ALTER TABLE users ADD COLUMN ${col} ${def}`);
      console.log('[db] users: added column ' + col);
    }
  }
}

async function initDb() {
  const { DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD } = process.env;
  if (!DB_HOST || !DB_NAME || !DB_USER) {
    lastError = 'DB env vars missing (need DB_HOST, DB_NAME, DB_USER). Running without database; only /api/health will respond.';
    console.warn('[db] ' + lastError);
    return;
  }
  try {
    pool = mysql.createPool({
      host: DB_HOST,
      port: DB_PORT ? Number(DB_PORT) : 3306,
      user: DB_USER,
      password: DB_PASSWORD || '',
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 50,
      connectTimeout: 10000,
      charset: 'utf8mb4',
    });
    // Pool error handler: log but don't crash (pool recovers itself).
    pool.on('error', (err) => {
      console.error('[db] pool error:', err.message);
    });
    const c = await pool.getConnection();
    try { await c.ping(); } finally { c.release(); }
    for (const sql of SCHEMA) await pool.execute(sql);
    // V8 migration: branch_user_id for branch staff auto-login
    try {
      const [cols] = await pool.execute("SHOW COLUMNS FROM branches LIKE 'branch_user_id'");
      if (!cols.length) await pool.execute("ALTER TABLE branches ADD COLUMN branch_user_id INT NULL");
    } catch (_) {}
    await ensureBillColumns(pool);
    // One-time migration: normalize stored mobile numbers (strip leading 0 / 91)
    try {
      await pool.execute("UPDATE users SET mobile = SUBSTRING(mobile, 2) WHERE mobile LIKE '0%' AND LENGTH(mobile) = 11");
      await pool.execute("UPDATE users SET mobile = SUBSTRING(mobile, 3) WHERE mobile LIKE '91%' AND LENGTH(mobile) = 12");
      await pool.execute("UPDATE customers SET mobile = SUBSTRING(mobile, 2) WHERE mobile LIKE '0%' AND LENGTH(mobile) = 11");
      await pool.execute("UPDATE customers SET mobile = SUBSTRING(mobile, 3) WHERE mobile LIKE '91%' AND LENGTH(mobile) = 12");
      await pool.execute("UPDATE suppliers SET mobile = SUBSTRING(mobile, 2) WHERE mobile LIKE '0%' AND LENGTH(mobile) = 11");
      await pool.execute("UPDATE suppliers SET mobile = SUBSTRING(mobile, 3) WHERE mobile LIKE '91%' AND LENGTH(mobile) = 12");
    } catch (e) { console.warn('[db] mobile migration skipped:', e.message); }
    ready = true;
    // Migration: ensure last_seen_at exists
    try {
      const [cols] = await pool.execute("SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sessions' AND COLUMN_NAME = 'last_seen_at'");
      if (cols[0].c === 0) {
        await pool.execute("ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP");
      }
    } catch (e) { console.warn('[db] migration skipped:', e.message); }
    // Migration: app PIN lock (Security) columns
    try {
      const [c1] = await pool.execute("SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'app_lock_enabled'");
      if (c1[0].c === 0) {
        await pool.execute("ALTER TABLE users ADD COLUMN app_lock_enabled TINYINT(1) NOT NULL DEFAULT 0");
      }
      const [c2] = await pool.execute("SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'app_pin_hash'");
      if (c2[0].c === 0) {
        await pool.execute("ALTER TABLE users ADD COLUMN app_pin_hash VARCHAR(255) NULL");
      }
      const [c3] = await pool.execute("SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sessions' AND COLUMN_NAME = 'is_locked'");
      if (c3[0].c === 0) {
        await pool.execute("ALTER TABLE sessions ADD COLUMN is_locked TINYINT(1) NOT NULL DEFAULT 0");
      }
    } catch (e) { console.warn('[db] applock migration skipped:', e.message); }
    // Migration: business profile columns (for getBusinessProfile/saveBusinessProfile actions)
    try {
      const bizCols = {
        upi_id: 'VARCHAR(60) NULL',
        loyalty_rate: 'DECIMAL(5,2) NULL',
        store_code: 'VARCHAR(40) NULL',
        online_store_enabled: 'TINYINT(1) NOT NULL DEFAULT 0',
        shop_hours: 'VARCHAR(255) NULL',
        return_policy: 'TEXT NULL',
        gstin: 'VARCHAR(15) NULL',
        pan_number: 'VARCHAR(10) NULL',
        business_category: 'VARCHAR(100) NULL',
        business_subcategory: 'VARCHAR(100) NULL',
        gst_rate: 'DECIMAL(5,2) NULL',
        discount_percent: 'DECIMAL(5,2) NULL',
        photo_url: 'MEDIUMTEXT NULL',
      };
      for (const [col, def] of Object.entries(bizCols)) {
        const [cc] = await pool.execute(
          `SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = ?`,
          [col]
        );
        if (cc[0].c === 0) {
          await pool.execute(`ALTER TABLE users ADD COLUMN ${col} ${def}`);
          console.log('[db] users: added column ' + col);
        }
      }
    } catch (e) { console.warn('[db] business profile migration skipped:', e.message); }
    // Migration: branch photo column
    try {
      const [cc] = await pool.execute(
        `SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'stores' AND COLUMN_NAME = 'photo_url'`
      );
      if (cc[0].c === 0) {
        await pool.execute(`ALTER TABLE stores ADD COLUMN photo_url MEDIUMTEXT NULL`);
        console.log('[db] stores: added column photo_url');
      }
    } catch (e) { console.warn('[db] stores photo migration skipped:', e.message); }
    console.log('[db] connected; schema ready');
  } catch (e) {
    lastError = 'DB init failed: ' + e.message;
    console.error('[db] ' + lastError);
    try { if (pool) await pool.end(); } catch (_) { /* ignore */ }
    pool = null;
  }
}

module.exports = { initDb, getPool, getPoolIfReady, isReady, dbError };
