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

function pubUser(u) {
  if (!u) return u;
  const { password_hash, security_answer_hash, ...rest } = u; // eslint-disable-line no-unused-vars
  return rest;
}

module.exports = { pageParams, num, reqNum, normMobile, pubUser };
