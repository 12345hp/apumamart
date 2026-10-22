// Small shared helpers.
function pageParams(q) {
  let limit = parseInt(q.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0) limit = 50;
  limit = Math.min(limit, 200);
  let page = parseInt(q.page, 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  return { limit, offset: (page - 1) * limit, page };
}

function badNumber(name) {
  const e = new Error(name + ' must be a valid number');
  e.status = 400;
  return e;
}

// Optional number: returns def when missing/empty, throws 400 when invalid.
function num(v, def = 0) {
  if (v === undefined || v === null || v === '') return def;
  const n = Number(v);
  if (!Number.isFinite(n)) throw badNumber('value');
  return n;
}

// Required number: throws 400 when missing or invalid.
function reqNum(v, name) {
  if (v === undefined || v === null || v === '') throw badNumber(name);
  const n = Number(v);
  if (!Number.isFinite(n)) throw badNumber(name);
  return n;
}

function normMobile(m) {
  let d = String(m || '').replace(/\D/g, '');
  // Normalize Indian mobiles: 9198XXXXXXXX -> 98XXXXXXXX, 098XXXXXXXX -> 98XXXXXXXX
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

const COUNTRY_META = {
  IN: { country: 'IN', currency: 'INR', symbol: '\u20B9', tax_label: 'GST', dial_code: '91' },
  AE: { country: 'AE', currency: 'AED', symbol: 'AED ', tax_label: 'VAT', dial_code: '971' },
};
function countryMeta(c) { return COUNTRY_META[c === 'AE' ? 'AE' : 'IN']; }

function pubUser(u) {
  if (!u) return u;
  const { password_hash, security_answer_hash, ...rest } = u; // eslint-disable-line no-unused-vars
  return rest;
}

module.exports = { pageParams, num, reqNum, normMobile, pubUser, parseIntlMobile, COUNTRY_META, countryMeta };
