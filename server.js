// Jill's Budget — a tiny zero-dependency budget tracker.
// Run with: PASSCODE=... ADMIN_PASSCODE=... node server.js

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'budget.json');
const PASSCODE = process.env.PASSCODE;
const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE;
const SESSION_DAYS = 180;
const MAX_CENTS = 100_000_00;

if (!PASSCODE || !ADMIN_PASSCODE || PASSCODE === ADMIN_PASSCODE) {
  console.error(
    'Set two different passcodes before starting:\n' +
      '  PASSCODE        — used to log in and track spending\n' +
      '  ADMIN_PASSCODE  — same access, plus setting the monthly amount'
  );
  process.exit(1);
}

// ---------- storage (one small JSON file) ----------

fs.mkdirSync(DATA_DIR, { recursive: true });

let db = { secret: crypto.randomBytes(32).toString('hex'), budgets: {}, expenses: [] };
if (fs.existsSync(DATA_FILE)) {
  db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) };
} else {
  save();
}

function save() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// The budget for a month is the most recent amount set in or before it,
// so changing the amount never rewrites earlier months.
function budgetFor(month) {
  const key = Object.keys(db.budgets)
    .filter((m) => m <= month)
    .sort()
    .pop();
  return key ? db.budgets[key] : null;
}

// ---------- auth ----------

const sign = (value) => crypto.createHmac('sha256', db.secret).update(value).digest('hex');
const sha = (value) => crypto.createHash('sha256').update(String(value)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function makeToken(role) {
  const body = `${role}.${Date.now() + SESSION_DAYS * 864e5}`;
  return `${body}.${sign(body)}`;
}

function roleFromRequest(req) {
  const match = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie || '');
  if (!match) return null;
  const [role, expires, sig] = match[1].split('.');
  if (!sig || !same(sig, sign(`${role}.${expires}`))) return null;
  if (Number(expires) < Date.now()) return null;
  return role === 'admin' || role === 'member' ? role : null;
}

function sessionCookie(req, token, maxAgeSeconds) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

// Slow down passcode guessing: 10 misses per IP per 15 minutes.
const misses = new Map();
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;
}
function isLockedOut(ip) {
  const entry = misses.get(ip);
  if (entry && entry.resetAt < Date.now()) misses.delete(ip);
  return (misses.get(ip)?.count || 0) >= 10;
}
function recordMiss(ip) {
  const entry = misses.get(ip) || { count: 0, resetAt: Date.now() + 15 * 60e3 };
  entry.count += 1;
  misses.set(ip, entry);
}

// ---------- helpers ----------

const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;
const DATE_RE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const validCents = (n) => Number.isInteger(n) && n > 0 && n <= MAX_CENTS;

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    if (!(req.headers['content-type'] || '').startsWith('application/json')) {
      return reject(new Error('Expected JSON'));
    }
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 10_000) reject(new Error('Too large'));
    });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(raw || '{}');
        if (!parsed || typeof parsed !== 'object') throw new Error('Bad JSON');
        resolve(parsed);
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function monthView(month, role) {
  const expenses = db.expenses
    .filter((e) => e.date.startsWith(month))
    .sort((a, b) => b.date.localeCompare(a.date) || b.createdAt - a.createdAt);
  return {
    role,
    month,
    budgetCents: budgetFor(month),
    spentCents: expenses.reduce((sum, e) => sum + e.amountCents, 0),
    expenses,
  };
}

// ---------- routes ----------

const INDEX = path.join(__dirname, 'public', 'index.html');

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const route = `${req.method} ${url.pathname}`;

  if (route === 'GET /') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return fs.createReadStream(INDEX).pipe(res);
  }
  if (route === 'GET /healthz') return send(res, 200, { ok: true });

  if (route === 'POST /api/login') {
    const ip = clientIp(req);
    if (isLockedOut(ip)) return send(res, 429, { error: 'Too many tries. Wait a few minutes.' });
    const { passcode } = await readJson(req);
    const role = same(passcode, ADMIN_PASSCODE) ? 'admin' : same(passcode, PASSCODE) ? 'member' : null;
    if (!role) {
      recordMiss(ip);
      return send(res, 401, { error: 'That passcode is not right.' });
    }
    return send(res, 200, { role }, { 'Set-Cookie': sessionCookie(req, makeToken(role), SESSION_DAYS * 86400) });
  }

  if (route === 'POST /api/logout') {
    return send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', 0) });
  }

  if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found' });

  const role = roleFromRequest(req);
  if (!role) return send(res, 401, { error: 'Please log in.' });

  if (route === 'GET /api/month') {
    const month = url.searchParams.get('m') || '';
    if (!MONTH_RE.test(month)) return send(res, 400, { error: 'Bad month' });
    return send(res, 200, monthView(month, role));
  }

  if (route === 'POST /api/expenses') {
    const { date, amountCents, note } = await readJson(req);
    if (!DATE_RE.test(date || '')) return send(res, 400, { error: 'Pick a date.' });
    if (!validCents(amountCents)) return send(res, 400, { error: 'Enter an amount.' });
    db.expenses.push({
      id: crypto.randomUUID(),
      date,
      amountCents,
      note: String(note || '').trim().slice(0, 80),
      createdAt: Date.now(),
    });
    save();
    return send(res, 201, monthView(date.slice(0, 7), role));
  }

  if (req.method === 'DELETE' && url.pathname.startsWith('/api/expenses/')) {
    const id = url.pathname.slice('/api/expenses/'.length);
    const expense = db.expenses.find((e) => e.id === id);
    if (!expense) return send(res, 404, { error: 'Already gone.' });
    db.expenses = db.expenses.filter((e) => e.id !== id);
    save();
    return send(res, 200, monthView(expense.date.slice(0, 7), role));
  }

  if (route === 'PUT /api/budget') {
    if (role !== 'admin') return send(res, 403, { error: 'Only the admin can set the budget.' });
    const { month, amountCents } = await readJson(req);
    if (!MONTH_RE.test(month || '')) return send(res, 400, { error: 'Bad month' });
    if (!validCents(amountCents)) return send(res, 400, { error: 'Enter an amount.' });
    db.budgets[month] = amountCents;
    save();
    return send(res, 200, monthView(month, role));
  }

  return send(res, 404, { error: 'Not found' });
}

http
  .createServer((req, res) => {
    handle(req, res).catch((err) => {
      if (!res.headersSent) send(res, 400, { error: err.message || 'Bad request' });
      else res.end();
    });
  })
  .listen(PORT, () => console.log(`Jill's Budget is running on port ${PORT}`));
