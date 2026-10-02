import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { google } from 'googleapis';
import PDFDocument from 'pdfkit';
import nodemailer from 'nodemailer';
import path from 'path';
import fs from 'fs';
import { Readable } from 'stream';
import crypto from 'crypto';
import zlib from 'zlib';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Retry Google API calls that hit per-minute quota limits (429) or brief server errors
google.options({
  retry: true,
  retryConfig: {
    retry: 5,
    retryDelay: 2000,
    statusCodesToRetry: [[429, 429], [500, 599]],
  },
});

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

/* ======================================================================
   Server-side login (Batch 3)

   Turn it on by setting the L2H_USERS environment variable on Render, e.g.
   [{"key":"dan","name":"Dan","admin":true,"password":"..."},
    {"key":"ella","name":"Ella","admin":false,"password":"..."}]
   The value here is each person's TEMPORARY password. On first login they are
   made to choose their own, which is stored as a hash in the "Users" tab of
   the tracker sheet and takes over from then on. To add a team member, add
   one more entry to L2H_USERS. A "passwordHash" ("salt:scrypt-hex") can be
   used instead of "password". Optional per-person fields: fullName, title,
   email, phone (used for the contact line on submission documents).
   Until L2H_USERS is set the server behaves exactly as before. Once set,
   every /api call except the public application form needs a signed token
   from POST /api/login (username and password).
   ====================================================================== */
app.set('trust proxy', 1);

const AUTH_USERS = (() => {
  try {
    const raw = process.env.L2H_USERS;
    if (!raw) return null;
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr) || !arr.length) return null;
    return arr.map(u => ({
      key: String(u.key || '').toLowerCase(),
      name: u.name || u.key,
      admin: !!u.admin,
      password: u.password,
      passwordHash: u.passwordHash,
      fullName: u.fullName, title: u.title, email: u.email, phone: u.phone,
    })).filter(u => u.key);
  } catch (e) {
    console.error('L2H_USERS is not valid JSON:', e.message);
    return null;
  }
})();
const AUTH_ENABLED = !!(AUTH_USERS && AUTH_USERS.length);
const AUTH_SECRET = process.env.AUTH_SECRET ||
  crypto.createHash('sha256').update('l2h-auth|' + (process.env.GOOGLE_SERVICE_ACCOUNT_JSON || 'dev')).digest('hex');
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!p.exp || p.exp < Date.now()) return null;
    return p;
  } catch (e) {
    return null;
  }
}

function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function checkPassword(user, pw) {
  if (user.passwordHash) {
    const [salt, hash] = String(user.passwordHash).split(':');
    if (!salt || !hash) return false;
    return safeEqual(crypto.scryptSync(String(pw), salt, 64).toString('hex'), hash);
  }
  return user.password ? safeEqual(user.password, pw) : false;
}

function isAdmin(req) {
  if (req.user) return !!req.user.admin;
  return String(req.get('X-User-Role') || '').toLowerCase() === 'dan';
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Only Dan can do this' });
  next();
}

function actorOf(req) {
  if (req && req.user && req.user.key) return req.user.key;
  return String((req && req.get && req.get('X-User-Role')) || 'unknown').toLowerCase();
}

// Audit entries made while an admin is using "View as" are recorded as "dan (as ella)"
function auditActorOf(req) {
  if (req && req.user && req.user.va && req.user.rk) return `${req.user.rk} (as ${req.user.key})`;
  return actorOf(req);
}

/* ---------- Team contact details (used on submission documents) ---------- */
const TEAM_DEFAULTS = {
  dan: { fullName: 'Dan Brown', title: 'Director', email: 'dan.brown@live2helprecruitment.co.uk', phone: '07424 087576' },
  ella: { fullName: 'Ella Pietrzak', title: 'Talent Acquisition and Business Development Consultant', email: 'ella@live2helprecruitment.co.uk', phone: '07434 351996' },
};

function titleCase(s) { s = String(s || ''); return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

function profileOf(keyOrName) {
  const k = String(keyOrName || '').trim().toLowerCase();
  const u = (AUTH_USERS || []).find(x => x.key === k || String(x.name || '').toLowerCase() === k) || null;
  const key = u ? u.key : k;
  const d = TEAM_DEFAULTS[key] || null;
  const fb = TEAM_DEFAULTS.dan;
  return {
    key,
    name: (u && u.name) || titleCase(key) || 'Dan',
    fullName: (u && u.fullName) || (d && d.fullName) || (u && u.name) || fb.fullName,
    title: (u && u.title) || (d && d.title) || fb.title,
    email: (u && u.email) || (d && d.email) || fb.email,
    phone: (u && u.phone) || (d && d.phone) || fb.phone,
  };
}

function contactLineFor(keyOrName) {
  const p = profileOf(keyOrName);
  return [p.email, p.phone, 'www.live2helprecruitment.co.uk'].filter(Boolean).join('  |  ');
}

/* ---------- Personal passwords (Users tab) ---------- */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pw), salt, 64).toString('hex');
}

let usersTable = null; // created once the sheet helpers exist (see below)
let credCache = { at: 0, map: null };
function invalidateCreds() { credCache = { at: 0, map: credCache.map }; }
async function loadCreds() {
  if (credCache.map && Date.now() - credCache.at < 30000) return credCache.map;
  try {
    const rows = await usersTable.list();
    const m = new Map();
    rows.forEach(r => { if (r.id) m.set(String(r.id).toLowerCase(), r); });
    credCache = { at: Date.now(), map: m };
  } catch (e) {
    console.error('Users tab read failed:', e.message);
    if (!credCache.map) throw e;
  }
  return credCache.map;
}

// true when the password is right for this person (own password if set, else the temporary one)
function verifyUserPassword(user, row, pw) {
  if (!user || !pw) return { ok: false, mustChange: false };
  if (row && row.password_hash) {
    return { ok: checkPassword({ passwordHash: row.password_hash }, pw), mustChange: String(row.must_change).toUpperCase() === 'TRUE' };
  }
  return { ok: checkPassword(user, pw), mustChange: true };
}

function sessionToken(user, extra) {
  const now = Date.now();
  return signToken(Object.assign({ key: user.key, name: user.name, admin: user.admin, iat: now, exp: now + TOKEN_TTL_MS }, extra || {}));
}

const loginAttempts = new Map();
app.post('/api/login', async (req, res) => {
  if (!AUTH_ENABLED) return res.status(501).json({ error: 'Server login is not configured' });
  const body = req.body || {};
  const username = String(body.username || '').trim().toLowerCase();
  const pw = String(body.password || '');
  const ip = req.ip || 'unknown';
  const lockKey = ip + '|' + username;
  const now = Date.now();
  let rec = loginAttempts.get(lockKey);
  if (!rec || rec.reset < now) rec = { count: 0, reset: now + 15 * 60 * 1000 };
  if (rec.count >= 10) return res.status(429).json({ error: 'Too many attempts. Please try again in a few minutes.' });
  let creds;
  try { creds = await loadCreds(); } catch (e) {
    return res.status(503).json({ error: 'Sign in is temporarily unavailable. Please try again in a minute.' });
  }
  const user = username ? AUTH_USERS.find(u => u.key === username) : null;
  const check = verifyUserPassword(user, creds.get(username), pw);
  if (!check.ok) {
    rec.count++;
    loginAttempts.set(lockKey, rec);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  loginAttempts.delete(lockKey);
  const token = sessionToken(user, check.mustChange ? { mc: true } : {});
  res.json({ token, user: { key: user.key, name: user.name, admin: user.admin }, mustChange: check.mustChange });
  auditLog(user.key, 'login', 'session', user.name, '');
});

// Routes that stay public: the careers site application form, the Career Hub AI proxy,
// and the daily reminder cron (which can be locked with CRON_SECRET).
const PUBLIC_API = [
  { method: 'POST', re: /^\/api\/login$/ },
  { method: 'POST', re: /^\/api\/applications\/[^/]+$/ },
  { method: 'POST', re: /^\/api\/claude$/ },
  { method: 'GET', re: /^\/api\/public\/roles(\/[a-z0-9-]+)?$/ },
  { method: 'GET', re: /^\/api\/health$/ },
];
let cronWarned = false;
// The automation sends its secret in the x-cron-key header (the ?key= form still works)
function cronKeyOf(req) { return String(req.get('x-cron-key') || req.query.key || ''); }

app.use('/api', async (req, res, next) => {
  if (req.method === 'OPTIONS' || !AUTH_ENABLED) return next();
  const p = req.originalUrl.split('?')[0].replace(/\/+$/, '');
  if (PUBLIC_API.some(r => r.method === req.method && r.re.test(p))) return next();
  if (p.startsWith('/api/cron/') && process.env.CRON_SECRET && cronKeyOf(req) === process.env.CRON_SECRET) return next();
  if (p === '/api/check-invoice-reminders') {
    const secret = process.env.CRON_SECRET;
    if (!secret) {
      if (!cronWarned) { console.warn('CRON_SECRET is not set: /api/check-invoice-reminders is open'); cronWarned = true; }
      return next();
    }
    if (cronKeyOf(req) === secret) return next();
  }
  const header = String(req.get('Authorization') || '');
  let token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token && req.method === 'GET' && req.query.token) token = String(req.query.token);
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Please sign in again', code: 'AUTH' });
  try {
    // a password reset or change ends every older session for that person
    const creds = await loadCreds();
    const row = creds.get(String(payload.rk || payload.key || '').toLowerCase());
    if (row && row.updated_at && Date.parse(row.updated_at) > (payload.iat || 0) + 50) {
      return res.status(401).json({ error: 'Please sign in again', code: 'AUTH' });
    }
  } catch (e) { /* if the Users tab cannot be read, the signed token still stands */ }
  if (payload.mc && p !== '/api/change-password') {
    return res.status(403).json({ error: 'Please choose a new password first', code: 'MUST_CHANGE' });
  }
  req.user = payload;
  req.headers['x-user-role'] = payload.key;
  next();
});


app.post('/api/change-password', async (req, res) => {
  try {
    if (!AUTH_ENABLED || !req.user) return res.status(501).json({ error: 'Server login is not configured' });
    if (req.user.va) return res.status(403).json({ error: 'Passwords cannot be changed while using View as' });
    const b = req.body || {};
    const current = String(b.currentPassword || '');
    const next = String(b.newPassword || '');
    if (next.length < 8) return res.status(400).json({ error: 'Choose a password of at least 8 characters' });
    if (next === current) return res.status(400).json({ error: 'Your new password must be different from the current one' });
    const user = AUTH_USERS.find(u => u.key === req.user.key);
    if (!user) return res.status(403).json({ error: 'Unknown user' });
    const creds = await loadCreds();
    const check = verifyUserPassword(user, creds.get(user.key), current);
    if (!check.ok) return res.status(401).json({ error: 'Your current password is not right' });
    await usersTable.upsert({ id: user.key, password_hash: hashPassword(next), must_change: 'FALSE', updated_at: new Date().toISOString(), updated_by: user.key });
    invalidateCreds();
    await new Promise(r => setTimeout(r, 5));
    const token = sessionToken(user);
    auditLog(user.key, 'password_changed', 'session', user.name, '');
    res.json({ ok: true, token, user: { key: user.key, name: user.name, admin: user.admin } });
  } catch (e) {
    console.error('POST /api/change-password error:', e.message);
    res.status(500).json({ error: 'Could not save the new password. Please try again.' });
  }
});

// Admin: who has a login, and whether they have set their own password yet
app.get('/api/admin/users', async (req, res) => {
  try {
    if (!isAdmin(req) || (req.user && req.user.va)) return res.status(403).json({ error: 'Only Dan can do this' });
    if (!AUTH_ENABLED) return res.json({ data: [] });
    const creds = await loadCreds();
    res.json({ data: AUTH_USERS.map(u => {
      const r = creds.get(u.key);
      const own = !!(r && r.password_hash);
      return { key: u.key, name: u.name, admin: u.admin, hasOwnPassword: own, mustChange: own ? String(r.must_change).toUpperCase() === 'TRUE' : true, updatedAt: own ? r.updated_at : '' };
    }) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin: give someone a one-time temporary password (they must choose their own at next login)
app.post('/api/admin/users/:key/reset-password', async (req, res) => {
  try {
    if (!isAdmin(req) || (req.user && req.user.va)) return res.status(403).json({ error: 'Only Dan can do this' });
    const user = AUTH_USERS.find(u => u.key === String(req.params.key || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'Unknown user' });
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    let tmp = '';
    const bytes = crypto.randomBytes(8);
    for (let i = 0; i < 8; i++) tmp += alphabet[bytes[i] % alphabet.length];
    tmp = 'l2h-' + tmp;
    await usersTable.upsert({ id: user.key, password_hash: hashPassword(tmp), must_change: 'TRUE', updated_at: new Date().toISOString(), updated_by: actorOf(req) });
    invalidateCreds();
    auditLog(auditActorOf(req), 'password_reset', 'session', user.name, '');
    res.json({ ok: true, tempPassword: tmp });
  } catch (e) {
    console.error('POST reset-password error:', e.message);
    res.status(500).json({ error: 'Could not reset the password' });
  }
});

// Admin: see the dashboard exactly as another person does, without needing their password
app.post('/api/view-as', async (req, res) => {
  try {
    if (!AUTH_ENABLED || !req.user || !req.user.admin || req.user.va) return res.status(403).json({ error: 'Only Dan can do this' });
    const target = AUTH_USERS.find(u => u.key === String((req.body || {}).key || '').toLowerCase());
    if (!target) return res.status(404).json({ error: 'Unknown user' });
    if (target.key === req.user.key) return res.status(400).json({ error: 'You are already signed in as yourself' });
    const token = sessionToken(target, { va: true, rk: req.user.key, rn: req.user.name });
    auditLog(req.user.key, 'view_as_started', 'session', target.name, '');
    res.json({ token, user: { key: target.key, name: target.name, admin: target.admin } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


const API_KEY = process.env.ANTHROPIC_API_KEY;

if (!API_KEY) {
  console.error('ERROR: ANTHROPIC_API_KEY environment variable not set');
  process.exit(1);
}

app.post('/api/claude', async (req, res) => {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

/* ----------------------------------------------------------------------
   Pipeline dashboard - Google Sheets backed candidate store.

   Requires two env vars (set on Render, never committed to the repo):
     GOOGLE_SERVICE_ACCOUNT_JSON  - full contents of the service account
                                    JSON key file, pasted as one value
     SHEET_ID                     - the tracker spreadsheet ID

   Expects a tab named "Dashboard" in that spreadsheet with header row:
     id | company | role | name | stage | date | notes | salary | email | phone |
     invoice_number | start_date
---------------------------------------------------------------------- */

const SHEET_ID = process.env.SHEET_ID;
const SUBMISSIONS_FOLDER_ID = '1MplgUUbCNy64ZxDz4EQtc8GtnZ7S9Ipo';
const TAB = 'Dashboard';
const RANGE = `${TAB}!A2:L`;

let sheetsClientCache = null;
let driveClientCache = null;

function getAuthClient() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not set on this server');
  let creds;
  try {
    creds = JSON.parse(raw);
  } catch (e) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON - paste the full key file contents as-is');
  }
  return new google.auth.JWT(
    creds.client_email,
    null,
    creds.private_key,
    ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
  );
}

function getSheetsClient() {
  if (sheetsClientCache) return sheetsClientCache;
  const auth = getAuthClient();
  sheetsClientCache = google.sheets({ version: 'v4', auth });
  return sheetsClientCache;
}

function getDriveClient() {
  if (driveClientCache) return driveClientCache;
  const auth = getAuthClient();
  driveClientCache = google.drive({ version: 'v3', auth });
  return driveClientCache;
}

// Drive client used for creating folders and saving CV files.
// Service accounts have no Drive storage, so uploads must be made as a real Google
// user (Dan) via OAuth. Set GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET and
// GOOGLE_OAUTH_REFRESH_TOKEN on Render. Without them it falls back to the service
// account, which Google rejects for file uploads.
let uploadDriveCache = null;
function oauthUploadsConfigured() {
  return !!(process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET && process.env.GOOGLE_OAUTH_REFRESH_TOKEN);
}
function getUploadDriveClient() {
  if (uploadDriveCache) return uploadDriveCache;
  if (oauthUploadsConfigured()) {
    const oauth = new google.auth.OAuth2(process.env.GOOGLE_OAUTH_CLIENT_ID, process.env.GOOGLE_OAUTH_CLIENT_SECRET);
    oauth.setCredentials({ refresh_token: process.env.GOOGLE_OAUTH_REFRESH_TOKEN });
    uploadDriveCache = google.drive({ version: 'v3', auth: oauth });
  } else {
    uploadDriveCache = getDriveClient();
  }
  return uploadDriveCache;
}
function friendlyDriveError(e) {
  const msg = String((e && e.message) || e);
  if (/storage quota/i.test(msg) || /invalid_grant/i.test(msg) || /unauthorized_client/i.test(msg)) {
    return oauthUploadsConfigured()
      ? 'Google sign-in for uploads has expired or been revoked - the refresh token needs regenerating'
      : 'Google sign-in for uploads is not set up on the server yet';
  }
  return msg;
}

async function readAllRows() {
  if (!SHEET_ID) throw new Error('SHEET_ID is not set on this server');
  const sheets = getSheetsClient();
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: RANGE,
  });
  return result.data.values || [];
}

function rowToCandidate(row) {
  return {
    id: row[0] || '',
    company: row[1] || '',
    role: row[2] || '',
    name: row[3] || '',
    stage: row[4] || 'submitted',
    date: row[5] || '',
    notes: row[6] || '',
    salary: row[7] || '',
    email: row[8] || '',
    phone: row[9] || '',
    invoiceNumber: row[10] || '',
    startDate: row[11] || '',
  };
}

function candidateToRow(c) {
  return [
    c.id, c.company, c.role, c.name, c.stage || 'submitted',
    c.date || new Date().toISOString().slice(0, 10),
    c.notes || '', c.salary || '', c.email || '', c.phone || '',
    c.invoiceNumber || '', c.startDate || '',
  ];
}

// Parse filename pattern: "Candidate Submission [FirstName] [LastInitial] [Role]"
function parseSubmissionFilename(filename) {
  const match = filename.match(/^Candidate Submission\s+(\S+)\s+(\S)\s+(.+?)(?:\..+)?$/i);
  if (!match) return null;
  return { name: (match[1] + ' ' + match[2]).trim(), role: match[3].trim() };
}

async function listFolderContents(folderId) {
  const drive = getDriveClient();
  const result = await drive.files.list({
    q: `'${folderId}' in parents and trashed=false`,
    spaces: 'drive',
    pageSize: 100,
    fields: 'files(id, name, mimeType)',
  });
  return result.data.files || [];
}

// Pseudo-company bucket for form applications not yet assigned to a client
const UNASSIGNED_LABEL = 'Unassigned - New Applications';

// ---- Shared forms: one application form can feed several vacancies ----------
// The Applications tab is named after the FORM (e.g. "Sales Manager South"). An
// applicant can be assigned to a different vacancy (e.g. "Sales Manager South 2").
// This table remembers that assignment so the pipeline uses the vacancy while every
// lookup of the original answers still finds the form tab.
const applicantRolesTable = makeSimpleTable({
  tab: 'Applicant Roles',
  header: ['id', 'assigned_role', 'form_role', 'name'],
  path: null,
  label: 'Applicant role',
});
let applicantRolesCache = { at: 0, list: null };
async function getApplicantRoles() {
  if (applicantRolesCache.list && Date.now() - applicantRolesCache.at < 15000) return applicantRolesCache.list;
  const list = await applicantRolesTable.list();
  applicantRolesCache = { at: Date.now(), list };
  return list;
}
function dropApplicantRolesCache() { applicantRolesCache = { at: 0, list: null }; }

function normPersonName(n) { return String(n || '').trim().toLowerCase().replace(/\s+/g, ' '); }
function personNameMatches(a, b) {
  const x = normPersonName(a), y = normPersonName(b);
  if (!x || !y) return false;
  if (x === y) return true;
  const px = x.split(' '), py = y.split(' ');
  if (px.length >= 2 && py.length >= 2 && px[0] === py[0]) {
    const lx = px[px.length - 1], ly = py[py.length - 1];
    return lx.charAt(0) === ly.charAt(0) && (lx.length === 1 || ly.length === 1 || lx === ly);
  }
  return false;
}

// Which Applications tab holds this person's form answers for this vacancy?
async function formRoleFor(name, role) {
  try {
    const want = String(role || '').trim().toLowerCase();
    const hit = (await getApplicantRoles()).find(a =>
      String(a.assigned_role || '').trim().toLowerCase() === want && personNameMatches(a.name, name));
    if (hit && hit.form_role) return hit.form_role;
  } catch (e) { /* fall back to the role itself */ }
  return role;
}

async function migratePoolRole(name, fromRole, toRole) {
  if (!name || !fromRole || !toRole || fromRole === toRole) return;
  try {
    await withPoolLock(async () => {
      const sheets = getSheetsClient();
      const rows = await readPoolRows();
      const fromId = poolIdFor(name, fromRole), toId = poolIdFor(name, toRole);
      const idx = rows.findIndex(r => r && r[0] === fromId);
      if (idx === -1 || rows.some(r => r && r[0] === toId)) return;
      const row = padPoolRow(rows[idx]);
      row[0] = toId; row[5] = toRole;
      const n = idx + 2;
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID, range: `'${POOL_TAB}'!A${n}:${POOL_LAST_COL}${n}`,
        valueInputOption: 'RAW', requestBody: { values: [row] },
      });
    });
  } catch (e) { console.error('Could not move the pool record to the new role:', e.message); }
}

// Called when the dashboard saves a form-sourced candidate: remember (or clear) the vacancy assignment
async function syncApplicantRole(c) {
  try {
    if (!c || c.sourceTab !== 'application' || !c.formRole || !c.id) return;
    const list = await getApplicantRoles();
    const existing = list.find(a => a.id === c.id);
    if (c.role && c.role !== c.formRole) {
      if (existing && existing.assigned_role === c.role) return;
      const previous = existing ? existing.assigned_role : c.formRole;
      await applicantRolesTable.upsert({ id: c.id, assigned_role: c.role, form_role: c.formRole, name: c.name });
      dropApplicantRolesCache();
      await migratePoolRole(c.name, previous, c.role);
    } else if (existing) {
      await applicantRolesTable.remove(c.id);
      dropApplicantRolesCache();
      await migratePoolRole(c.name, existing.assigned_role, c.formRole);
    }
  } catch (e) { console.error('Could not save the vacancy assignment:', e.message); }
}

async function purgeApplicantRoles(variants) {
  try {
    const list = await applicantRolesTable.listAll();
    for (const a of list) {
      if ([...variants].some(v => personNameMatches(a.name, v))) await applicantRolesTable.remove(a.id);
    }
    dropApplicantRolesCache();
  } catch (e) { console.error('Erase: applicant roles:', e.message); }
}

// Helper: read from Applications tabs and convert to candidates with 'applied' stage
async function readApplicationsRows(strict = false) {
  const sheets = getSheetsClient();
  const allApplications = [];
  try {
    const spreadsheet = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID });
    const tabs = spreadsheet.data.sheets;
    let assigns = new Map();
    try { assigns = new Map((await getApplicantRoles()).map(a => [a.id, a])); } catch (e) { /* no assignments yet */ }

    for (const tab of tabs) {
      const tabName = tab.properties.title;
      if (!tabName.startsWith('Applications -')) continue;

      const result = await sheets.spreadsheets.values.get({
        spreadsheetId: SHEET_ID,
        range: `'${tabName}'!A2:Z`,
      });

      const rows = result.data.values || [];
      rows.forEach(row => {
        if (!row[2]) return; // Skip if no candidate name (col C)
        allApplications.push({
          id: row[0] || '',
          company: row[17] || '', // Company is column R
          contact: row[18] || '', // Contact is column S
          role: (assigns.get(row[0]) && assigns.get(row[0]).assigned_role) || tabName.replace('Applications - ', ''),
          formRole: tabName.replace('Applications - ', ''),
          name: row[2] || '', // Candidate name is column C
          stage: row[19] || 'applied', // Status is column T
          date: row[1] || '', // Date Applied is column B
          notes: row[20] || '', // Notes is column U
          salary: row[15] || '', // Salary Expectation is column P
          email: row[3] || '', // Email is column D
          phone: row[4] || '', // Phone is column E
          consentApp: row[21] || '', // Consent to process application is column V
          consentDate: (row[22] || '').slice(0, 10), // Consent date is column W
          consentPool: row[24] || '', // Talent pool consent is column Y
          cvLink: row[25] || '', // CV link is column Z
          sourceTab: 'application'
        });
      });
    }
  } catch (e) {
    console.error('Error reading Applications tabs:', e.message);
    if (strict) throw e;
  }
  return allApplications;
}

// GET all candidates, grouped by company then role - shape the dashboard expects.
// Includes Dashboard tab rows plus form Applications tab rows. Applications with
// no company assigned yet are grouped under UNASSIGNED_LABEL so Ella can see and
// assign them from the board, rather than being silently dropped.
app.get('/api/candidates', async (req, res) => {
  try {
    const dashboardRows = await readAllRows();
    const applicationRows = await readApplicationsRows();

    const grouped = {};

    dashboardRows.filter(r => r[0]).forEach(r => {
      const c = rowToCandidate(r);
      if (!grouped[c.company]) grouped[c.company] = {};
      if (!grouped[c.company][c.role]) grouped[c.company][c.role] = [];
      grouped[c.company][c.role].push(c);
    });

    applicationRows.forEach(c => {
      const companyKey = c.company || UNASSIGNED_LABEL;
      if (!grouped[companyKey]) grouped[companyKey] = {};
      if (!grouped[companyKey][c.role]) grouped[companyKey][c.role] = [];
      grouped[companyKey][c.role].push(c);
    });

    res.json({ data: grouped });
  } catch (e) {
    console.error('GET /api/candidates error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Create or update a single candidate (upsert by id).
// Applications-tab candidates (sourceTab === 'application') are written back to
// their "Applications - <Role>" tab, matched by candidate name - this is how
// Ella's company/contact assignment gets saved. Everything else goes to Dashboard.
app.post('/api/candidates', async (req, res) => {
  res.on('finish', () => { if (res.statusCode < 400) scheduleReconcile(); });
  try {
    const c = req.body;
    const __before = await snapshotCandidate(c);
    res.on('finish', () => { if (res.statusCode < 400) auditCandidateChange(req, c, __before); });
    if (!c.id || !c.role || !c.name) {
      return res.status(400).json({ error: 'id, role and name are required' });
    }
    const sheets = getSheetsClient();
    await syncApplicantRole(c);

    // Graduate to Dashboard: once a form-sourced candidate reaches offer stage
    // or later, they need fields (start date, invoice tracking) that the
    // Applications tab doesn't have. From this point on they live as a normal
    // Dashboard row and stop being written back to the Applications tab.
    const GRADUATE_STAGES = ['offer', 'start_date', 'day1', 'week1', 'month1'];
    if (c.sourceTab === 'application' && GRADUATE_STAGES.includes(c.stage) && c.company) {
      const dashboardId = `${c.company}-${c.name}`.toLowerCase().replace(/\s+/g, '-');
      await sheets.spreadsheets.values.append({
        spreadsheetId: SHEET_ID,
        range: RANGE,
        valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS',
        requestBody: { values: [candidateToRow({ ...c, id: dashboardId })] },
      });
      return res.json({ ok: true, migrated: true, id: dashboardId });
    }

    if (c.sourceTab === 'application') {
      const tabName = `Applications - ${c.formRole || c.role}`;
      const allRows = await sheets.spreadsheets.values.get({
        spreadsheetId: SHEET_ID,
        range: `'${tabName}'!A2:T`,
      });
      const rows = allRows.data.values || [];
      const rowIndex = rows.findIndex(r => (r[2] || '').trim().toLowerCase() === c.name.trim().toLowerCase());

      if (rowIndex === -1) {
        return res.status(404).json({ error: `Candidate not found in ${tabName}` });
      }

      const sheetRowNumber = rowIndex + 2;
      const existing = rows[rowIndex];
      const appRow = [
        existing[0] || c.id, existing[1], existing[2], c.email || existing[3], c.phone || existing[4],
        existing[5], existing[6], existing[7], existing[8], existing[9], existing[10], existing[11],
        existing[12], existing[13], existing[14], c.salary || existing[15], existing[16],
        c.company !== undefined ? c.company : (existing[17] || ''),
        c.contact !== undefined ? c.contact : (existing[18] || ''),
        c.stage || existing[19] || 'applied',
        c.notes !== undefined ? c.notes : (existing[20] || ''),
      ];

      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID,
        range: `'${tabName}'!A${sheetRowNumber}:U${sheetRowNumber}`,
        valueInputOption: 'RAW',
        requestBody: { values: [appRow] },
      });
      return res.json({ ok: true });
    }

    if (!c.company) {
      return res.status(400).json({ error: 'company is required for Dashboard candidates' });
    }

    const rows = await readAllRows();
    const rowIndex = rows.findIndex(r => r[0] === c.id);
    const values = [candidateToRow(c)];

    if (rowIndex === -1) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: SHEET_ID,
        range: RANGE,
        valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS',
        requestBody: { values },
      });
    } else {
      const sheetRowNumber = rowIndex + 2;
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID,
        range: `${TAB}!A${sheetRowNumber}:L${sheetRowNumber}`,
        valueInputOption: 'RAW',
        requestBody: { values },
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/candidates error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// If this candidate came in through a screening form, mark their existing
// Applications tab row as submitted (and lock in the company) rather than
// letting the code below create a separate, duplicate Dashboard row.
async function tryMarkApplicationSubmitted(companyName, role, candidateName) {
  const sheets = getSheetsClient();
  const tabName = `Applications - ${await formRoleFor(candidateName, role)}`;
  try {
    const allRows = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A2:U`,
    });
    const rows = allRows.data.values || [];
    
    // Try exact full name match first (case-insensitive)
    const nameNormalized = candidateName.trim().toLowerCase();
    let rowIndex = rows.findIndex(r => (r[2] || '').trim().toLowerCase() === nameNormalized);
    
    if (rowIndex === -1) {
      // Fallback to first-name-initial match (e.g. "Kelly B" matches "Kelly Brammer")
      const parts = candidateName.split(' ');
      if (parts.length >= 2) {
        const firstName = parts[0].toLowerCase();
        const initial = parts[1].charAt(0).toLowerCase();
        rowIndex = rows.findIndex(r => {
          const fullName = (r[2] || '').toLowerCase().trim();
          const nameParts = fullName.split(' ');
          return nameParts[0] === firstName && nameParts[1] && nameParts[1].charAt(0) === initial;
        });
      }
    }
    
    if (rowIndex === -1) return false;

    const sheetRowNumber = rowIndex + 2;
    const existing = rows[rowIndex];

    // Stage guard: only promote to Submitted from Applied (or blank).
    // Anyone already moved on (interview requested, rejected, offer, etc.)
    // is left exactly as they are, even if their pack is still in Drive.
    const currentStage = (existing[19] || 'applied').trim().toLowerCase();
    if (currentStage !== 'applied') {
      console.log(`Skipped stage change for ${candidateName} (${role}): already at "${currentStage}"`);
      return { matched: true, changed: false, fullName: existing[2] || candidateName }; // matched, so no duplicate Dashboard row is created
    }

    existing[17] = companyName;       // Company (column R)
    existing[19] = 'submitted';       // Status (column T)
    while (existing.length < 21) existing.push('');

    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A${sheetRowNumber}:U${sheetRowNumber}`,
      valueInputOption: 'RAW',
      requestBody: { values: [existing] },
    });
    stageAutomation({ name: existing[2] || candidateName, role, company: companyName, notes: existing[20] || '' }, 'submitted');
    return { matched: true, changed: true, fullName: existing[2] || candidateName };
  } catch (e) {
    // Tab probably doesn't exist for this role - candidate wasn't sourced from a form
    console.error(`Error marking application submitted for ${candidateName} in ${tabName}:`, e.message);
    return false;
  }
}

// Sync submissions folder - detect new candidate submission files.
// Prefers updating a matching Applications tab row (form-sourced candidates);
// only creates a new Dashboard row when no Applications tab match is found.
app.post('/api/sync-submissions', async (req, res) => {
  try {
    const companyFolders = await listFolderContents(SUBMISSIONS_FOLDER_ID);
    const existingRows = await readAllRows();
    const existingIds = new Set(existingRows.map(r => r[0]));

    let created = 0;
    let updated = 0;
    const newlySubmitted = [];

    for (const companyFolder of companyFolders) {
      if (companyFolder.mimeType !== 'application/vnd.google-apps.folder') continue;
      if (companyFolder.name === POOL_CV_FOLDER_NAME) continue;

      const submissionFiles = await listFolderContents(companyFolder.id);
      const docFiles = submissionFiles.filter(f => !f.mimeType.includes('folder'));

      for (const file of docFiles) {
        const parsed = parseSubmissionFilename(file.name);
        if (!parsed) continue;

        const matchedApplication = await tryMarkApplicationSubmitted(companyFolder.name, parsed.role, parsed.name);
        if (matchedApplication) {
          updated++;
          if (matchedApplication.changed) {
            newlySubmitted.push({ name: matchedApplication.fullName, role: parsed.role, company: companyFolder.name });
          }
          console.log(`Marked as submitted: ${parsed.name} for ${parsed.role} at ${companyFolder.name}`);
          continue;
        }

        const candidateId = `${companyFolder.name.toLowerCase().replace(/\s+/g, '-')}-${parsed.name.toLowerCase().replace(/\s+/g, '-')}`;

        if (!existingIds.has(candidateId)) {
          const newCandidate = {
            id: candidateId,
            company: companyFolder.name,
            role: parsed.role,
            name: parsed.name,
            stage: 'submitted',
            date: new Date().toISOString().slice(0, 10),
            notes: '',
            salary: '',
            email: '',
            phone: '',
          };

          await fetch(`http://localhost:${process.env.PORT || 10000}/api/candidates`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newCandidate),
          });

          created++;
          newlySubmitted.push({ name: parsed.name, role: parsed.role, company: companyFolder.name });
          console.log(`Auto-created candidate: ${parsed.name} for ${parsed.role} at ${companyFolder.name}`);
        }
      }
    }

    if (created > 0 || newlySubmitted.length > 0) scheduleReconcile();
    res.json({ synced: true, created, updated, newlySubmitted });
  } catch (e) {
    console.error('GET /api/sync-submissions error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// Applications intake - form submissions from screening forms
// Requires a CV (pdf, doc, docx, 5MB max) and the privacy notice tick box.
const APPLICATION_WORDING_VERSION = 'v1 - 30 Sep 2026';
const MAX_CV_BASE64_LENGTH = 7 * 1024 * 1024; // roughly 5MB of file once decoded

// ---- Sales Manager forms (Ceasefire) - self-creating tabs, longer question set ----
// Columns A-Z keep the standard layout the dashboard reads. The 8 slots H-O hold the
// first eight role questions, P is salary, Q is additional info, and the remaining
// role questions overflow into AA onward.
const SALES_MANAGER_FORMS = {
  'sales-manager-midlands': { roleName: 'Sales Manager Midlands', region: 'Midlands' },
  'sales-manager-south': { roleName: 'Sales Manager South', region: 'South' },
};
const SALES_MANAGER_ROLE_NAMES = new Set(Object.values(SALES_MANAGER_FORMS).map(f => f.roleName));
const SM_ARRAY_FIELDS = new Set(['fireSectors', 'tradeRelationships']);
const SM_SLOT_FIELDS = [
  { key: 'fireYears', col: 7, label: 'Years in the fire safety, fire protection or life safety industry' },
  { key: 'fireSectors', col: 8, label: 'Parts of the fire industry sold into' },
  { key: 'currentRoleEmployer', col: 9, label: 'Current or most recent job title and employer' },
  { key: 'tradeRelationships', col: 10, label: 'Existing trade partner relationships' },
  { key: 'namedPartners', col: 11, label: 'Trade partners, distributors or installers they could approach in the first 90 days' },
  { key: 'dayOneDoors', col: 12, label: 'Relationships they could open doors with from day one' },
  { key: 'newPartnerExample', col: 13, label: 'Example of signing up a new trade partner or distributor from scratch' },
  { key: 'distributionExperience', col: 14, label: 'Experience building or growing a distribution network' },
  { key: 'salaryExpectation', col: 15, label: 'Salary Expectation' },
  { key: 'additionalInfo', col: 16, label: 'Additional Info' },
  { key: 'targetAchieved', col: 26, label: 'Annual sales target carried and achieved in last role' },
  { key: 'targetConsistency', col: 27, label: 'Consistency in hitting or beating target over the last three years' },
  { key: 'totalPackage', col: 28, label: 'Total package last year including bonus or commission' },
  { key: 'managesPeople', col: 29, label: 'Currently manages or leads people' },
  { key: 'trainingAttitude', col: 30, label: 'View on a structured 6 month training and onboarding programme' },
  { key: 'crmConfidence', col: 31, label: 'Confidence with CRM systems and sales reporting' },
  { key: 'drivingLicence', col: 32, label: 'Full UK driving licence' },
  { key: 'travelComfort', col: 33, label: 'Comfort with regular travel and overnight stays' },
  { key: 'territoryLocation', col: 34, label: 'Home location (postcode area)' },
  { key: 'territoryCoverage', col: 35, label: 'Comfortable covering the territory' },
];
const SM_REQUIRED = ['fireYears', 'fireSectors', 'currentRoleEmployer', 'tradeRelationships', 'namedPartners', 'dayOneDoors',
  'newPartnerExample', 'distributionExperience', 'targetAchieved', 'targetConsistency', 'totalPackage', 'managesPeople',
  'trainingAttitude', 'crmConfidence', 'drivingLicence', 'travelComfort', 'territoryLocation', 'territoryCoverage',
  'employmentStatus', 'noticePeriod', 'salaryExpectation'];

function smHeaderRow(region) {
  const h = new Array(36).fill('');
  h[0] = 'Application ID'; h[1] = 'Date Applied'; h[2] = 'Name'; h[3] = 'Email'; h[4] = 'Phone';
  h[5] = 'Current Employment Status'; h[6] = 'Notice Period';
  SM_SLOT_FIELDS.forEach(f => { h[f.col] = f.label; });
  h[34] = `Home location in the ${region} (postcode area)`;
  h[35] = `Comfortable covering the ${region}, including regular travel`;
  h[17] = 'Company'; h[18] = 'Contact'; h[19] = 'Status'; h[20] = 'Notes';
  h[21] = 'Privacy Notice Accepted'; h[22] = 'Consent Date'; h[23] = 'Wording Version';
  h[24] = 'Talent Pool Consent'; h[25] = 'CV Link';
  return h;
}

const smTabLocks = new Map();
async function ensureSalesManagerTab(tabName, region) {
  if (smTabLocks.has(tabName)) return smTabLocks.get(tabName);
  const p = (async () => {
    const sheets = getSheetsClient();
    const ss = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties.title' });
    if (!(ss.data.sheets || []).some(t => t.properties.title === tabName)) {
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId: SHEET_ID,
        requestBody: { requests: [{ addSheet: { properties: { title: tabName, gridProperties: { frozenRowCount: 1 } } } }] },
      });
    }
    const head = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tabName}'!A1:AJ1` });
    const first = head.data.values && head.data.values[0];
    if (!first || first[0] !== 'Application ID') {
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID, range: `'${tabName}'!A1:AJ1`,
        valueInputOption: 'RAW', requestBody: { values: [smHeaderRow(region)] },
      });
    }
  })();
  smTabLocks.set(tabName, p);
  p.catch(() => smTabLocks.delete(tabName));
  return p;
}

async function handleSalesManagerApplication(req, res, form) {
  try {
    const b = req.body || {};
    const { name, email, phone, cvData, cvFileName, consentApplication, consentPool } = b;
    if (!name || !email || !phone) return res.status(400).json({ error: 'Missing required fields' });
    if (consentApplication !== true && consentApplication !== 'Yes') {
      return res.status(400).json({ error: 'Privacy notice must be accepted' });
    }
    if (!cvData || !cvFileName) return res.status(400).json({ error: 'CV is required' });
    if (!/\.(pdf|docx?)$/i.test(String(cvFileName))) return res.status(400).json({ error: 'CV must be a PDF, DOC or DOCX file' });
    if (String(cvData).length > MAX_CV_BASE64_LENGTH) return res.status(400).json({ error: 'CV is larger than 5MB' });
    const missing = SM_REQUIRED.filter(k => {
      const v = b[k];
      return Array.isArray(v) ? v.length === 0 : !String(v || '').trim();
    });
    if (missing.length) return res.status(400).json({ error: 'Please answer every required question' });

    const roleName = form.roleName;
    const tabName = `Applications - ${roleName}`;
    await ensureSalesManagerTab(tabName, form.region);

    const sheets = getSheetsClient();
    const slug = roleName.toLowerCase().replace(/\s+/g, '-');
    const applicationId = `${slug}-${Date.now()}`;
    const dateApplied = new Date().toISOString();
    const poolConsent = (consentPool === true || consentPool === 'Yes') ? 'Yes' : 'No';

    const cleanName = String(name).trim().replace(/\s+/g, ' ').replace(/['"\\]/g, '');
    let saved = null;
    try {
      saved = await saveCandidateCv({ company: '', name, fileName: cvFileName, fileData: cvData });
    } catch (cvErr) {
      console.error(`CV could not be saved for application from ${cleanName}:`, cvErr.message);
    }

    const row = new Array(36).fill('');
    row[0] = applicationId; row[1] = dateApplied; row[2] = name; row[3] = email; row[4] = phone;
    row[5] = b.employmentStatus || ''; row[6] = b.noticePeriod || '';
    SM_SLOT_FIELDS.forEach(f => {
      const v = b[f.key];
      row[f.col] = Array.isArray(v) ? v.join(', ') : String(v == null ? '' : v);
    });
    row[19] = 'applied';
    row[21] = 'Yes'; row[22] = dateApplied; row[23] = APPLICATION_WORDING_VERSION;
    row[24] = poolConsent; row[25] = saved ? saved.link : '';

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID, range: `'${tabName}'!A:AJ`,
      valueInputOption: 'USER_ENTERED', requestBody: { values: [row] },
    });

    try {
      const poolId = poolIdFor(name, roleName);
      await upsertPoolEntry({
        name, role: roleName, company: '', stage: 'applied', source: 'application',
        email, phone, dateAdded: dateApplied, consentDate: dateApplied.slice(0, 10),
        consentBasis: poolConsent === 'Yes' ? 'Application form - talent pool' : 'Application form - this role only',
      }, true, { createOnly: true });
      if (saved) await attachCvToPool(poolId, saved);
    } catch (poolErr) {
      console.error('Could not create pool record for application:', poolErr.message);
    }

    res.json({ success: true, applicationId });
    sendApplicationAck({ name, email, roleName });
  } catch (err) {
    console.error('POST /api/applications (sales manager) error:', err);
    res.status(500).json({ error: 'Failed to save application' });
  }
}

// Header-driven screening fields for tabs that do not use the Transport Coordinator layout
async function getScreeningFieldsForRole(role) {
  if (!SALES_MANAGER_ROLE_NAMES.has(role)) return null;
  const sheets = getSheetsClient();
  const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'Applications - ${role}'!A1:AJ1` });
  const header = (r.data.values && r.data.values[0]) || [];
  const cols = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35];
  const labels = { 2: 'Candidate Name', 3: 'Email', 4: 'Phone' };
  return cols.map(c => ({ key: `col${c}`, label: String(labels[c] || header[c] || `Question ${c}`).trim(), col: c }));
}

app.post('/api/applications/:role', async (req, res) => {
  res.on('finish', () => { if (res.statusCode < 400) scheduleReconcile(); });
  try {
    const { role } = req.params;
    if (SALES_MANAGER_FORMS[role]) return await handleSalesManagerApplication(req, res, SALES_MANAGER_FORMS[role]);
    const {
      name,
      email,
      phone,
      employmentStatus,
      noticePeriod,
      transportBackground,
      recentRole,
      liaisonHauliers,
      kpiComfort,
      excelSkill,
      priorityRating,
      workEnvironment,
      location,
      commute,
      salaryExpectation,
      additionalInfo,
      cvData,
      cvFileName,
      consentApplication,
      consentPool
    } = req.body;

    if (!name || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (consentApplication !== true && consentApplication !== 'Yes') {
      return res.status(400).json({ error: 'Privacy notice must be accepted' });
    }
    if (!cvData || !cvFileName) {
      return res.status(400).json({ error: 'CV is required' });
    }
    if (!/\.(pdf|docx?)$/i.test(String(cvFileName))) {
      return res.status(400).json({ error: 'CV must be a PDF, DOC or DOCX file' });
    }
    if (String(cvData).length > MAX_CV_BASE64_LENGTH) {
      return res.status(400).json({ error: 'CV is larger than 5MB' });
    }

    const sheets = getSheetsClient();
    const applicationId = `${role}-${Date.now()}`;
    const dateApplied = new Date().toISOString();
    const roleName = role.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    const poolConsent = (consentPool === true || consentPool === 'Yes') ? 'Yes' : 'No';

    // Save the CV first so the application row can carry the link.
    // If Drive rejects the file the application is still recorded (without a CV link)
    // so no candidate is ever lost; the failure is logged for follow-up.
    const cleanName = String(name).trim().replace(/\s+/g, ' ').replace(/['"\\]/g, '');
    let saved = null;
    try {
      saved = await saveCandidateCv({ company: '', name, fileName: cvFileName, fileData: cvData });
    } catch (cvErr) {
      console.error(`CV could not be saved for application from ${cleanName}:`, cvErr.message);
    }
    const driveName = saved ? saved.fileName : '';

    // Tab name format: "Applications - Transport Coordinator"
    const tabName = `Applications - ${roleName}`;
    const range = `'${tabName}'!A:Z`;

    const row = [
      applicationId,
      dateApplied,
      name,
      email,
      phone,
      employmentStatus,
      noticePeriod,
      transportBackground,
      recentRole,
      liaisonHauliers,
      kpiComfort,
      excelSkill,
      priorityRating,
      workEnvironment,
      location,
      salaryExpectation,
      additionalInfo || '',
      '',        // Company - assigned by Ella
      '',        // Contact - assigned by Ella
      'applied', // Status
      '',        // Notes (column U)
      'Yes',                        // V: privacy notice accepted
      dateApplied,                  // W: consent date and time
      APPLICATION_WORDING_VERSION,  // X: wording version shown
      poolConsent,                  // Y: agreed to be kept for future roles
      saved ? saved.link : ''       // Z: CV link
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: range,
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [row] }
    });

    // Create the pool record straight away with the CV and consent attached
    try {
      const poolId = poolIdFor(name, roleName);
      await upsertPoolEntry({
        name, role: roleName, company: '', stage: 'applied', source: 'application',
        email, phone, dateAdded: dateApplied,
        consentDate: dateApplied.slice(0, 10),
        consentBasis: poolConsent === 'Yes' ? 'Application form - talent pool' : 'Application form - this role only',
      }, true, { createOnly: true });
      if (saved) await attachCvToPool(poolId, saved);
    } catch (poolErr) {
      console.error('Could not create pool record for application:', poolErr.message);
    }

    res.json({ success: true, applicationId });
    sendApplicationAck({ name, email, roleName });

  } catch (err) {
    console.error('POST /api/applications error:', err);
    res.status(500).json({ error: 'Failed to save application' });
  }
});

// Delete a candidate by id
// Find a form-application candidate by id across every "Applications - [Role]" tab
async function findApplicationRowById(id) {
  const sheets = getSheetsClient();
  const spreadsheet = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID });
  for (const tab of spreadsheet.data.sheets) {
    const tabName = tab.properties.title;
    if (!tabName.startsWith('Applications -')) continue;
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A2:Z`,
    });
    const rows = result.data.values || [];
    const idx = rows.findIndex(r => r && r[0] === id && r[2]);
    if (idx === -1) continue;
    const row = rows[idx];
    return {
      tabName,
      sheetRowNumber: idx + 2,
      candidate: {
        id: row[0] || '',
        company: row[17] || '',
        contact: row[18] || '',
        role: tabName.replace('Applications - ', ''),
        name: row[2] || '',
        stage: row[19] || 'applied',
        date: row[1] || '',
        notes: row[20] || '',
        salary: row[15] || '',
        email: row[3] || '',
        phone: row[4] || '',
      },
    };
  }
  return null;
}

app.delete('/api/candidates/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: 'id is required' });
    }
    const sheets = getSheetsClient();
    const rows = await readAllRows();
    const rowIndex = rows.findIndex(r => r[0] === id);

    if (rowIndex === -1) {
      // Not on the Dashboard tab: Applied (and not-yet-graduated Submitted) candidates
      // live only in their "Applications - [Role]" tab, so look there by id.
      const app = await findApplicationRowById(id);
      if (!app) {
        return res.status(404).json({ error: 'candidate not found' });
      }
      try {
        const gone = app.candidate;
        if (gone.name && gone.role) {
          auditLog(auditActorOf(req), 'candidate_deleted', 'candidate', `${gone.name} - ${gone.role}`, `stage ${gone.stage}`);
          await upsertPoolEntry({ ...gone, dateAdded: gone.date, source: 'application' }, false);
        }
      } catch (snapErr) {
        console.error('Could not snapshot application to pool before delete:', snapErr.message);
      }
      await sheets.spreadsheets.values.clear({
        spreadsheetId: SHEET_ID,
        range: `'${app.tabName}'!A${app.sheetRowNumber}:Z${app.sheetRowNumber}`,
      });
      return res.json({ ok: true, deleted: id, source: 'application' });
    }

    try {
      const gone = rowToCandidate(rows[rowIndex]);
      if (gone.name && gone.role) {
        auditLog(auditActorOf(req), 'candidate_deleted', 'candidate', `${gone.name} - ${gone.role}`, `stage ${gone.stage}`);
        await upsertPoolEntry({ ...gone, dateAdded: gone.date, source: 'dashboard' }, false);
      }
    } catch (snapErr) {
      console.error('Could not snapshot candidate to pool before delete:', snapErr.message);
    }

    const sheetRowNumber = rowIndex + 2;
    await sheets.spreadsheets.values.clear({
      spreadsheetId: SHEET_ID,
      range: `${TAB}!A${sheetRowNumber}:L${sheetRowNumber}`,
    });
    res.json({ ok: true, deleted: id });
  } catch (e) {
    console.error('DELETE /api/candidates/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   Client Management - L2H Client Contacts sheet.
   
   Uses CLIENT_SHEET_ID and CLIENT_TAB with columns:
   Timestamp | Company | Address | Postcode | Contact Name | Job Title | Email | Phone | Folder Created
   ====================================================================== */

const CLIENT_SHEET_ID = '1gFoG7F9OU_ax-cJ7AJYPzXBPYPHGxronprXCXA2u5so';
const CLIENT_TAB = 'Dashboard';
const CLIENT_RANGE = `${CLIENT_TAB}!A2:J`;
const LEAD_CLIENT_TAB = 'Lead Clients';
const LEAD_CLIENT_RANGE = `${LEAD_CLIENT_TAB}!A2:J`;
const INVOICES_TAB = 'Invoices';
const INVOICES_RANGE = `${INVOICES_TAB}!A2:K`;
const KPI_TARGETS_TAB = 'KPI Targets';
const KPI_TARGETS_RANGE = `${KPI_TARGETS_TAB}!A2:E`;

function rowToClient(row) {
  return {
    timestamp: row[0] || '',
    company: row[1] || '',
    address: row[2] || '',
    postcode: row[3] || '',
    contactName: row[4] || '',
    jobTitle: row[5] || '',
    email: row[6] || '',
    phone: row[7] || '',
    folderCreated: row[8] || 'No',
    notes: row[9] || '',
  };
}

function clientToRow(c) {
  return [
    c.timestamp || new Date().toISOString(),
    c.company || '',
    c.address || '',
    c.postcode || '',
    c.contactName || '',
    c.jobTitle || '',
    c.email || '',
    c.phone || '',
    c.folderCreated || 'No',
    c.notes || '',
  ];
}

async function readClientRows() {
  if (!CLIENT_SHEET_ID) throw new Error('CLIENT_SHEET_ID is not set');
  const sheets = getSheetsClient();
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: CLIENT_SHEET_ID,
    range: CLIENT_RANGE,
  });
  return result.data.values || [];
}

async function readLeadClientRows() {
  if (!CLIENT_SHEET_ID) throw new Error('CLIENT_SHEET_ID is not set');
  const sheets = getSheetsClient();
  try {
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: CLIENT_SHEET_ID,
      range: LEAD_CLIENT_RANGE,
    });
    return result.data.values || [];
  } catch (e) {
    // Tab doesn't exist yet - return empty
    return [];
  }
}

// GET all clients
app.get('/api/clients', async (req, res) => {
  try {
    const rows = await readClientRows();
    const clients = rows.filter(r => r[1]).map(r => rowToClient(r));
    res.json({ data: clients });
  } catch (e) {
    console.error('GET /api/clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST add new client
app.post('/api/clients', async (req, res) => {
  try {
    const { company, address, postcode, contactName, jobTitle, email, phone, notes } = req.body;
    
    if (!company || !email) {
      return res.status(400).json({ error: 'company and email are required' });
    }

    const sheets = getSheetsClient();
    const newClient = {
      timestamp: new Date().toISOString(),
      company,
      address,
      postcode,
      contactName,
      jobTitle,
      email,
      phone,
      folderCreated: 'No',
      notes: notes || '',
    };

    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: CLIENT_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [clientToRow(newClient)] },
    });

    // Create the client's Drive folders (including its folder in Candidates Submissions).
    // The client is already saved, so a Drive problem never blocks adding them.
    let folders = { ok: false };
    try {
      const f = await ensureClientFolders(company);
      await markClientFolders(company);
      newClient.folderCreated = 'Yes';
      folders = { ok: true, created: f.created };
    } catch (fe) {
      console.error('Client folders could not be created:', fe.message);
      folders = { ok: false, error: fe.message };
    }

    res.json({ ok: true, client: newClient, folders });
  } catch (e) {
    console.error('POST /api/clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE client(s) by company
app.delete('/api/clients/:company', async (req, res) => {
  try {
    const { company } = req.params;
    const sheets = getSheetsClient();
    const rows = await readClientRows();
    
    const indicesToDelete = [];
    rows.forEach((row, index) => {
      if (row[1] && row[1].trim() === decodeURIComponent(company)) {
        indicesToDelete.push(index + 2);
      }
    });
    
    if (indicesToDelete.length === 0) {
      return res.status(404).json({ error: 'No clients found for that company' });
    }
    
    for (let i = indicesToDelete.length - 1; i >= 0; i--) {
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId: CLIENT_SHEET_ID,
        requestBody: {
          requests: [{
            deleteDimension: {
              range: {
                sheetId: 0,
                dimension: 'ROWS',
                startIndex: indicesToDelete[i] - 1,
                endIndex: indicesToDelete[i],
              },
            },
          }],
        },
      });
    }
    
    res.json({ ok: true, deleted: indicesToDelete.length });
  } catch (e) {
    console.error('DELETE /api/clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   Lead Clients - prospect management
   ====================================================================== */

// GET all lead clients
app.get('/api/lead-clients', async (req, res) => {
  try {
    const rows = await readLeadClientRows();
    const clients = rows.filter(r => r[1]).map(r => rowToClient(r));
    res.json({ data: clients });
  } catch (e) {
    console.error('GET /api/lead-clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST add new lead client
app.post('/api/lead-clients', async (req, res) => {
  try {
    const { company, address, postcode, contactName, jobTitle, email, phone, notes } = req.body;
    
    if (!company || !email) {
      return res.status(400).json({ error: 'company and email are required' });
    }

    const sheets = getSheetsClient();
    const newLeadClient = {
      timestamp: new Date().toISOString(),
      company,
      address,
      postcode,
      contactName,
      jobTitle,
      email,
      phone,
      folderCreated: 'No',
      notes: notes || '',
    };

    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: LEAD_CLIENT_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [clientToRow(newLeadClient)] },
    });

    res.json({ ok: true, client: newLeadClient });
  } catch (e) {
    console.error('POST /api/lead-clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE lead client by company and contact name
app.delete('/api/lead-clients/:company/:contactName', async (req, res) => {
  try {
    const { company, contactName } = req.params;
    const sheets = getSheetsClient();
    const rows = await readLeadClientRows();
    
    const companyName = decodeURIComponent(company);
    const contactNameDecoded = decodeURIComponent(contactName);
    
    const rowIndex = rows.findIndex(row =>
      row[1] && row[1].trim() === companyName &&
      row[4] && row[4].trim() === contactNameDecoded
    );
    
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Lead client not found' });
    }
    
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: CLIENT_SHEET_ID,
      requestBody: {
        requests: [{
          deleteDimension: {
            range: {
              sheetId: 0,
              dimension: 'ROWS',
              startIndex: rowIndex + 1,
              endIndex: rowIndex + 2,
            },
          },
        }],
      },
    });
    
    res.json({ ok: true, deleted: true });
  } catch (e) {
    console.error('DELETE /api/lead-clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   Invoices - Dan only

   Columns: invoice_number | invoice_date | due_date | company | role |
            candidate_name | salary | fee_percentage | amount | status |
            payment_date
====================================================================== */

const GOLD = '#C9A84C';
const DARK = '#1A1A1A';
const GREY = '#444444';
const LIGHT_GREY = '#888888';
const BORDER = '#DDDDDD';

function calculatePlacementFee(salary) {
  const s = Number(salary) || 0;
  let rate;
  if (s <= 22000) rate = 0.12;
  else if (s <= 30000) rate = 0.15;
  else if (s <= 40000) rate = 0.20;
  else rate = 0.25;
  return { rate, fee: Math.round(s * rate * 100) / 100 };
}

function generateInvoiceNumber(date = new Date()) {
  const dd = String(date.getDate()).padStart(2, '0');
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const yy = String(date.getFullYear()).slice(-2);
  return `RS${dd}${mm}${yy}`;
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

function toISODate(date) {
  return new Date(date).toISOString().slice(0, 10);
}

function formatDateUK(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
}

function formatCurrency(amount) {
  return `£${Number(amount).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function rowToInvoice(row) {
  return {
    number: row[0] || '',
    date: row[1] || '',
    dueDate: row[2] || '',
    company: row[3] || '',
    role: row[4] || '',
    candidateName: row[5] || '',
    salary: row[6] || '',
    feePercentage: row[7] || '',
    amount: parseFloat(row[8]) || 0,
    status: row[9] || 'pending',
    paymentDate: row[10] || '',
  };
}

function invoiceToRow(inv) {
  return [
    inv.number || '', inv.date || '', inv.dueDate || '', inv.company || '',
    inv.role || '', inv.candidateName || '', inv.salary || '', inv.feePercentage || '',
    inv.amount || 0, inv.status || 'pending', inv.paymentDate || '',
  ];
}

async function readInvoiceRows() {
  const sheets = getSheetsClient();
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: CLIENT_SHEET_ID,
    range: INVOICES_RANGE,
  });
  return result.data.values || [];
}

// Brevo SMTP transporter for the daily invoice reminder email
const emailTransporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.BREVO_SMTP_USER,
    pass: process.env.BREVO_SMTP_PASS,
  },
});

// Restricts invoice create/update/delete to Dan's login. The dashboard sends
// its role in this header on invoice-mutating requests. Not a real auth
// system - just stops Ella's UI (or a casual API call) from touching invoices.
function requireDan(req, res, next) {
  if (!isAdmin(req)) {
    return res.status(403).json({ error: 'Only Dan can generate or manage invoices' });
  }
  next();
}

// GET all invoices
app.get('/api/invoices', async (req, res) => {
  try {
    const rows = await readInvoiceRows();
    const invoices = rows.filter(r => r[0]).map(r => rowToInvoice(r));
    res.json({ data: invoices });
  } catch (e) {
    console.error('GET /api/invoices error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST generate a new invoice for a placed candidate.
// Body: { candidateId, company, role, candidateName, salary }
// Fee is always calculated server-side from salary - never trust a client-sent amount.
app.post('/api/invoices', requireDan, async (req, res) => {
  auditOnFinish(req, res, () => ({ action: 'invoice_created', type: 'invoice', entity: `${(req.body || {}).candidateName || ''} - ${(req.body || {}).company || ''}`, detail: `salary ${(req.body || {}).salary || ''}` }));
  try {
    const { candidateId, company, role, candidateName, salary } = req.body;
    if (!company || !candidateName || !salary) {
      return res.status(400).json({ error: 'company, candidateName and salary are required' });
    }

    const sheets = getSheetsClient();
    const today = new Date();
    const { rate, fee } = calculatePlacementFee(salary);
    const newInvoice = {
      number: generateInvoiceNumber(today),
      date: toISODate(today),
      dueDate: toISODate(addDays(today, 30)),
      company,
      role: role || '',
      candidateName,
      salary,
      feePercentage: `${rate * 100}%`,
      amount: fee,
      status: 'pending',
      paymentDate: '',
    };

    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: INVOICES_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [invoiceToRow(newInvoice)] },
    });

    // Best-effort: stamp the invoice number back onto the Dashboard candidate
    // row so the daily reminder check knows not to remind about this one again.
    if (candidateId) {
      try {
        const rows = await readAllRows();
        const rowIndex = rows.findIndex(r => r[0] === candidateId);
        if (rowIndex !== -1) {
          const updated = [...rows[rowIndex]];
          updated[10] = newInvoice.number;
          await sheets.spreadsheets.values.update({
            spreadsheetId: SHEET_ID,
            range: `${TAB}!A${rowIndex + 2}:L${rowIndex + 2}`,
            valueInputOption: 'RAW',
            requestBody: { values: [updated] },
          });
        }
      } catch (e) {
        console.error('Could not stamp invoice number onto Dashboard row:', e.message);
      }
    }

    res.json({ ok: true, invoice: newInvoice });
  } catch (e) {
    console.error('POST /api/invoices error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// PUT update invoice status (pending / sent / paid) and payment date
app.put('/api/invoices/:number', requireDan, async (req, res) => {
  auditOnFinish(req, res, () => ({ action: 'invoice_updated', type: 'invoice', entity: req.params.number, detail: JSON.stringify(req.body || {}).slice(0, 200) }));
  try {
    const { number } = req.params;
    const { status, paymentDate } = req.body;

    const sheets = getSheetsClient();
    const rows = await readInvoiceRows();

    const rowIndex = rows.findIndex(r => r[0] === number);
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const updatedRow = [...rows[rowIndex]];
    if (status !== undefined) updatedRow[9] = status;
    if (paymentDate !== undefined) updatedRow[10] = paymentDate;

    await sheets.spreadsheets.values.update({
      spreadsheetId: CLIENT_SHEET_ID,
      range: `${INVOICES_TAB}!A${rowIndex + 2}:K${rowIndex + 2}`,
      valueInputOption: 'RAW',
      requestBody: { values: [updatedRow] },
    });

    res.json({ ok: true, invoice: rowToInvoice(updatedRow) });
  } catch (e) {
    console.error('PUT /api/invoices error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE an invoice record
app.delete('/api/invoices/:number', requireDan, async (req, res) => {
  auditOnFinish(req, res, () => ({ action: 'invoice_deleted', type: 'invoice', entity: req.params.number }));
  try {
    const { number } = req.params;
    const sheets = getSheetsClient();
    const rows = await readInvoiceRows();
    const rowIndex = rows.findIndex(r => r[0] === number);
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    await sheets.spreadsheets.values.clear({
      spreadsheetId: CLIENT_SHEET_ID,
      range: `${INVOICES_TAB}!A${rowIndex + 2}:K${rowIndex + 2}`,
    });
    res.json({ ok: true, deleted: number });
  } catch (e) {
    console.error('DELETE /api/invoices error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET branded invoice PDF, matching the Live 2 Help RS-format layout
app.get('/api/invoices/:number/pdf', async (req, res) => {
  try {
    const { number } = req.params;
    const rows = await readInvoiceRows();
    const row = rows.find(r => r[0] === number);
    if (!row) return res.status(404).json({ error: 'Invoice not found' });
    const inv = rowToInvoice(row);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=${inv.number}.pdf`);

    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    doc.pipe(res);

    try {
      doc.image(path.join(__dirname, 'assets', 'Logo_3.png'), 50, 45, { width: 160 });
    } catch (e) { /* logo optional */ }

    doc.font('Helvetica-Bold').fontSize(32).fillColor(DARK).text('INVOICE', 0, 55, { align: 'right' });
    doc.font('Helvetica').fontSize(11).fillColor(LIGHT_GREY).text(inv.number, 0, 90, { align: 'right' });
    doc.moveTo(50, 130).lineTo(545, 130).strokeColor(GOLD).lineWidth(2).stroke();

    const colY = 150;
    doc.font('Helvetica-Bold').fontSize(9).fillColor(GOLD).text('FROM', 50, colY);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(DARK).text('Live 2 Help Recruitment Ltd', 50, colY + 14);
    doc.font('Helvetica').fontSize(9).fillColor(GREY)
      .text('dan.brown@live2helprecruitment.co.uk', 50, colY + 30)
      .text('07424 087576', 50, colY + 43)
      .text('www.live2helprecruitment.co.uk', 50, colY + 56);

    doc.font('Helvetica-Bold').fontSize(9).fillColor(GOLD).text('BILLED TO', 220, colY);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(DARK).text(inv.company, 220, colY + 14);

    doc.font('Helvetica-Bold').fontSize(9).fillColor(GOLD).text('INVOICE DATE', 400, colY);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(DARK).text(formatDateUK(inv.date), 400, colY + 14);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(GOLD).text('DUE DATE', 400, colY + 40);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(DARK).text(formatDateUK(inv.dueDate), 400, colY + 54);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(GOLD).text('PAYMENT TERMS', 400, colY + 80);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(DARK).text('30 days', 400, colY + 94);

    doc.moveTo(50, 260).lineTo(545, 260).strokeColor(BORDER).lineWidth(1).stroke();

    const tableTop = 280;
    doc.rect(50, tableTop, 495, 26).fill(DARK);
    doc.font('Helvetica-Bold').fontSize(9).fillColor('#FFFFFF')
      .text('DESCRIPTION', 60, tableTop + 8)
      .text('QTY', 340, tableTop + 8)
      .text('UNIT PRICE', 400, tableTop + 8)
      .text('AMOUNT', 480, tableTop + 8);

    const rowY = tableTop + 36;
    doc.font('Helvetica-Bold').fontSize(10).fillColor(DARK)
      .text(`Supply of Permanent Staff - ${inv.candidateName}`, 60, rowY, { width: 260 });
    doc.font('Helvetica').fontSize(8).fillColor(LIGHT_GREY).text('Permanent placement fee', 60, rowY + 14, { width: 260 });
    doc.font('Helvetica').fontSize(10).fillColor(DARK)
      .text('1', 340, rowY)
      .text(formatCurrency(inv.amount), 400, rowY)
      .text(formatCurrency(inv.amount), 480, rowY);

    const totalsTop = rowY + 50;
    doc.moveTo(340, totalsTop).lineTo(545, totalsTop).strokeColor(BORDER).lineWidth(1).stroke();
    doc.font('Helvetica').fontSize(10).fillColor(GREY)
      .text('Subtotal', 400, totalsTop + 10)
      .text(formatCurrency(inv.amount), 480, totalsTop + 10);

    doc.rect(340, totalsTop + 30, 205, 28).fill(GOLD);
    doc.font('Helvetica-Bold').fontSize(11).fillColor('#FFFFFF')
      .text('TOTAL DUE', 350, totalsTop + 39)
      .text(formatCurrency(inv.amount), 480, totalsTop + 39);

    const payTop = totalsTop + 90;
    doc.moveTo(50, payTop).lineTo(545, payTop).strokeColor(BORDER).lineWidth(1).stroke();
    doc.font('Helvetica-Bold').fontSize(9).fillColor(GOLD).text('PAYMENT DETAILS', 50, payTop + 16);

    const details = [
      ['Account Name:', 'Live 2 Help Recruitment Ltd'],
      ['Account Number:', '12847344'],
      ['Sort Code:', '60-83-71'],
      ['Reference:', inv.number],
    ];
    let detailY = payTop + 36;
    details.forEach(([label, value]) => {
      doc.font('Helvetica').fontSize(9).fillColor(GREY).text(label, 130, detailY);
      doc.font('Helvetica-Bold').fontSize(9).fillColor(DARK).text(value, 260, detailY);
      detailY += 16;
    });

    doc.moveTo(50, 760).lineTo(545, 760).strokeColor(BORDER).lineWidth(1).stroke();
    doc.font('Helvetica-Oblique').fontSize(8).fillColor(LIGHT_GREY)
      .text('Live 2 Help Recruitment Ltd  •  Anyone · Anywhere · Anytime', 50, 772, { align: 'center', width: 495 });

    doc.end();
  } catch (e) {
    console.error('GET /api/invoices/:number/pdf error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET daily check - candidates starting tomorrow with no invoice generated yet.
// Called once a day by an external scheduler (EasyCron).
app.get('/api/check-invoice-reminders', async (req, res) => {
  try {
    const rows = await readAllRows();
    const tomorrow = toISODate(addDays(new Date(), 1));

    const due = rows.filter(r => {
      const candidate = rowToCandidate(r);
      return candidate.stage === 'start_date' && candidate.startDate === tomorrow && !candidate.invoiceNumber;
    }).map(rowToCandidate);

    for (const candidate of due) {
      const { rate, fee } = calculatePlacementFee(candidate.salary);
      await emailTransporter.sendMail({
        from: process.env.BREVO_SENDER_EMAIL,
        to: process.env.REMINDER_EMAIL_TO || process.env.BREVO_SENDER_EMAIL,
        subject: `Invoice Reminder - ${candidate.name} starts tomorrow`,
        text: `Hi Dan,

${candidate.name} is starting at ${candidate.company} tomorrow (${formatDateUK(candidate.startDate)}).

Salary: £${candidate.salary}
Placement Fee: £${fee} (${rate * 100}%)

Generate and send the invoice from the dashboard's Invoices tab.

Thanks,
Live 2 Help System`,
      });
    }

    res.json({ remindersSent: due.length, candidates: due.map(c => c.name) });
  } catch (e) {
    console.error('GET /api/check-invoice-reminders error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   KPI Targets - Dan sets, Ella views
   
   Columns: Quarter | Target Roles | Target New Clients | Target Avg Fill Speed Days
====================================================================== */

function rowToKPITarget(row) {
  return {
    quarter: row[0] || '',
    targetRoles: parseInt(row[1]) || 0,
    targetNewClients: parseInt(row[2]) || 0,
    targetAvgFillSpeedDays: parseInt(row[3]) || 0,
    owner: String(row[4] || '').toLowerCase(),
  };
}

function kpiTargetToRow(kpi) {
  return [
    kpi.quarter || '',
    kpi.targetRoles || 0,
    kpi.targetNewClients || 0,
    kpi.targetAvgFillSpeedDays || 0,
    kpi.owner || '',
  ];
}

async function readKPITargetRows() {
  const sheets = getSheetsClient();
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: CLIENT_SHEET_ID,
    range: KPI_TARGETS_RANGE,
  });
  return result.data.values || [];
}

function normOwner(o) {
  const v = String(o || '').trim().toLowerCase();
  return v === 'team' || v === 'all' ? '' : v;
}

// GET all KPI targets (owner is blank for team-wide targets)
app.get('/api/kpi-targets', async (req, res) => {
  try {
    const rows = await readKPITargetRows();
    res.json({ data: rows.filter(r => r && r[0]).map(r => rowToKPITarget(r)) });
  } catch (e) {
    console.error('GET /api/kpi-targets error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST add or update a KPI target for a quarter and a person (or the whole team)
app.post('/api/kpi-targets', requireAdmin, async (req, res) => {
  try {
    const { quarter, targetRoles, targetNewClients, targetAvgFillSpeedDays } = req.body;
    if (!quarter) return res.status(400).json({ error: 'quarter is required' });
    const owner = normOwner(req.body.owner);
    const sheets = getSheetsClient();
    const rows = await readKPITargetRows();

    const newKPI = {
      quarter,
      targetRoles: parseInt(targetRoles) || 0,
      targetNewClients: parseInt(targetNewClients) || 0,
      targetAvgFillSpeedDays: parseInt(targetAvgFillSpeedDays) || 0,
      owner,
    };

    const head = await sheets.spreadsheets.values.get({ spreadsheetId: CLIENT_SHEET_ID, range: `${KPI_TARGETS_TAB}!E1` });
    if (!(head.data.values && head.data.values[0] && head.data.values[0][0])) {
      await sheets.spreadsheets.values.update({
        spreadsheetId: CLIENT_SHEET_ID, range: `${KPI_TARGETS_TAB}!E1`, valueInputOption: 'RAW', requestBody: { values: [['Owner']] },
      });
    }

    const idx = rows.findIndex(r => r && r[0] === quarter && normOwner(r[4]) === owner);
    if (idx >= 0) {
      const n = idx + 2;
      await sheets.spreadsheets.values.update({
        spreadsheetId: CLIENT_SHEET_ID, range: `${KPI_TARGETS_TAB}!A${n}:E${n}`, valueInputOption: 'RAW',
        requestBody: { values: [kpiTargetToRow(newKPI)] },
      });
    } else {
      await sheets.spreadsheets.values.append({
        spreadsheetId: CLIENT_SHEET_ID, range: KPI_TARGETS_RANGE, valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS', requestBody: { values: [kpiTargetToRow(newKPI)] },
      });
    }
    auditLog(auditActorOf(req), idx >= 0 ? 'updated' : 'created', 'kpi_target', `${quarter} - ${owner || 'team'}`, `roles ${newKPI.targetRoles}, clients ${newKPI.targetNewClients}, fill ${newKPI.targetAvgFillSpeedDays}`);
    res.json({ ok: true, kpiTarget: newKPI });
  } catch (e) {
    console.error('POST /api/kpi-targets error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE a KPI target by quarter and owner (?owner= blank for team)
app.delete('/api/kpi-targets/:quarter', requireAdmin, async (req, res) => {
  try {
    const quarter = decodeURIComponent(req.params.quarter || '');
    if (!quarter) return res.status(400).json({ error: 'quarter is required' });
    const owner = normOwner(req.query.owner);
    const sheets = getSheetsClient();
    const rows = await readKPITargetRows();
    const idx = rows.findIndex(r => r && r[0] === quarter && normOwner(r[4]) === owner);
    if (idx === -1) return res.status(404).json({ error: 'KPI target not found' });

    const ss = await sheets.spreadsheets.get({ spreadsheetId: CLIENT_SHEET_ID, fields: 'sheets.properties(sheetId,title)' });
    const tab = (ss.data.sheets || []).find(t => t.properties.title === KPI_TARGETS_TAB);
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: CLIENT_SHEET_ID,
      requestBody: { requests: [{ deleteDimension: { range: {
        sheetId: tab ? tab.properties.sheetId : 0, dimension: 'ROWS', startIndex: idx + 1, endIndex: idx + 2,
      } } }] },
    });
    auditLog(auditActorOf(req), 'deleted', 'kpi_target', `${quarter} - ${owner || 'team'}`, '');
    res.json({ ok: true, message: 'KPI target deleted' });
  } catch (e) {
    console.error('DELETE /api/kpi-targets/:quarter error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   Metrics - Progress and Business Health Calculations
====================================================================== */

// Helper: Get current quarter
function getCurrentQuarter() {
  const now = new Date();
  const month = now.getMonth() + 1;
  const year = now.getFullYear();
  if (month <= 3) return { quarter: 'Q1', year };
  if (month <= 6) return { quarter: 'Q2', year };
  if (month <= 9) return { quarter: 'Q3', year };
  return { quarter: 'Q4', year };
}

// Helper: Check if date is in current quarter
function isInCurrentQuarter(dateStr) {
  const { quarter, year } = getCurrentQuarter();
  const date = new Date(dateStr);
  const dateYear = date.getFullYear();
  const month = date.getMonth() + 1;
  
  if (dateYear !== year) return false;
  
  if (quarter === 'Q1') return month >= 1 && month <= 3;
  if (quarter === 'Q2') return month >= 4 && month <= 6;
  if (quarter === 'Q3') return month >= 7 && month <= 9;
  return month >= 10 && month <= 12;
}

// Progress and business health metrics now live in the Automation Batch A block below.

/* ======================================================================
   Bulk Import - Import 32 existing client records
====================================================================== */

app.post('/api/bulk-import-clients', async (req, res) => {
  try {
    const { clients } = req.body;
    
    if (!Array.isArray(clients) || clients.length === 0) {
      return res.status(400).json({ error: 'clients array is required and must not be empty' });
    }

    const sheets = getSheetsClient();
    const rows = clients.map(c => clientToRow(c));

    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: CLIENT_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: rows },
    });

    res.json({ ok: true, imported: clients.length });
  } catch (e) {
    console.error('POST /api/bulk-import-clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   One-time Initialization - Bulk Import Initial Client Data
   Call once: GET /api/init-bulk-clients
   (Will import the 31 initial client records)
====================================================================== */

const INITIAL_CLIENTS = [
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Guy Saunders", "jobTitle": "Supply Chain Manager", "email": "Guy.Saunders@rsbpltd.co.uk", "phone": "07920815549", "folderCreated": "No", "notes": ""},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Andy Shepherd", "jobTitle": "NPD / Engineering", "email": "Andy.Shepherd@rsbpltd.co.uk", "phone": "07483 036306", "folderCreated": "No", "notes": ""},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Liam Furlong", "jobTitle": "Group Operations Director", "email": "Liam.Furlong@rsbpltd.co.uk", "phone": "07805473844", "folderCreated": "No", "notes": "Good friend of Dan's. Hiring contact for CAD Technician role - went quiet mid-process and hired externally, no fee. Don't over-invest before re-confirming engagement."},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Daniel Gisborne", "jobTitle": "CAD Manager", "email": "Daniel.Gisborne@rsbpltd.co.uk", "phone": "07483036329", "folderCreated": "No", "notes": "MAIN CONTACT. Dan has worked with her a long time - the priority relationship for Ella to build on and maintain."},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Amy Cunningham", "jobTitle": "Group ER & Operations Manager", "email": "Amy.Cunningham@rsbpltd.co.uk", "phone": "07825776462", "folderCreated": "No", "notes": "Personal relationship with Dan - Dan used to work for him, and Jon gave Dan the opportunity to develop the recruitment business. Warm, high-value relationship."},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Jon Sherry", "jobTitle": "Managing Director", "email": "Jon.Sherry@rsbpltd.co.uk", "phone": "07780700832", "folderCreated": "No", "notes": "Good friend of Dan's, alongside Daniel Gisborne."},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Conrad Litherland", "jobTitle": "Production Manager", "email": "Conrad.Litherland@rsbpltd.co.uk", "phone": "07976419231", "folderCreated": "No", "notes": "Based at Venesta's Manchester site."},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Natalie Furlong", "jobTitle": "Group Despatch Manager", "email": "Natalie.Furlong@rsbpltd.co.uk", "phone": "07483036278", "folderCreated": "No", "notes": ""},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "Alderflat Drive/Newstead Ind Trading Est, Stoke-on-Trent", "postcode": "ST4 8HX", "contactName": "Danny Bowers", "jobTitle": "Financial Controller", "email": "Danny.Bowers@rsbpltd.co.uk", "phone": "07483036319", "folderCreated": "No", "notes": "Email domain confirmed as venesta.co.uk - exact address to confirm."},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Venesta Ltd", "address": "St. George's Centre, 1st Floor, Units 19-23, St George's Square, Gravesend", "postcode": "DA11 0TA", "contactName": "Gary Edkins", "jobTitle": "Commercial Manager", "email": "Gary.Edkins@venesta.co.uk", "phone": "", "folderCreated": "No", "notes": ""},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Spares Dept / Hyve Solutions", "address": "Manchester", "postcode": "", "contactName": "Richard", "jobTitle": "Manager", "email": "richard@hyve.com", "phone": "", "folderCreated": "No", "notes": "Dan's colleague at Hyve - sourcing opportunities"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Mariana Tech Ltd", "address": "286b Chase Road, Southgate, London", "postcode": "N14 6HF", "contactName": "Tech Team", "jobTitle": "Hiring", "email": "careers@marianatech.com", "phone": "", "folderCreated": "No", "notes": "Zoom Workshop client - Future Tech Academy"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Ceasefire Industries UK", "address": "Stoke-on-Trent", "postcode": "", "contactName": "Hiring Manager", "jobTitle": "Sales Manager", "email": "careers@ceasefire.co.uk", "phone": "", "folderCreated": "No", "notes": "Fire extinguisher sales - Midlands territory"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "DHL", "address": "Manchester Airport", "postcode": "", "contactName": "Recruitment", "jobTitle": "HR", "email": "recruitment@dhl.com", "phone": "", "folderCreated": "No", "notes": "Ground handling and operations"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "We Buy Any Car", "address": "Multiple locations", "postcode": "", "contactName": "Branch Manager", "jobTitle": "Management", "email": "careers@wbac.co.uk", "phone": "", "folderCreated": "No", "notes": "Vehicle valuations and sales"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Robust UK", "address": "Stoke area", "postcode": "", "contactName": "Hiring", "jobTitle": "Operations", "email": "careers@robustuk.com", "phone": "", "folderCreated": "No", "notes": "Steel door manufacturing"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Sayfa Group", "address": "Loughborough", "postcode": "", "contactName": "Procurement", "jobTitle": "Supply Chain", "email": "careers@sayfa.com", "phone": "", "folderCreated": "No", "notes": "Manufacturing and procurement"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Hattons of London", "address": "London", "postcode": "", "contactName": "Distribution", "jobTitle": "Manager", "email": "careers@hattons.com", "phone": "", "folderCreated": "No", "notes": "Distribution and logistics"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "TIMCO (T I Midwood & Co)", "address": "Midlands", "postcode": "", "contactName": "Warehouse Manager", "jobTitle": "Inventory", "email": "careers@timco.com", "phone": "", "folderCreated": "No", "notes": "Warehouse and stock management"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Dunelm", "address": "Various", "postcode": "", "contactName": "Recruitment", "jobTitle": "HR", "email": "careers@dunelm.com", "phone": "", "folderCreated": "No", "notes": "Retail and distribution"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Steelite International", "address": "Staffordshire", "postcode": "", "contactName": "Supply Chain Manager", "jobTitle": "Procurement", "email": "careers@steelite.com", "phone": "", "folderCreated": "No", "notes": "13+ years procurement experience represented here"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Core-Electric", "address": "Nantwich", "postcode": "", "contactName": "Procurement Manager", "jobTitle": "Buying", "email": "careers@core-electric.com", "phone": "", "folderCreated": "No", "notes": "Electrical components and engineering"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Listers Central Ltd", "address": "Various", "postcode": "", "contactName": "Purchasing Manager", "jobTitle": "Materials Planning", "email": "careers@listerscentral.com", "phone": "", "folderCreated": "No", "notes": "PVC windows and doors manufacturer - 99% OTIF history"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "UK Safety Management", "address": "North West", "postcode": "", "contactName": "Operations", "jobTitle": "Fire Safety", "email": "careers@uksafety.com", "phone": "", "folderCreated": "No", "notes": "Fire extinguisher services - BS 5306 accredited"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "ERS Medical", "address": "Multiple UK locations", "postcode": "", "contactName": "Operations", "jobTitle": "Patient Transport", "email": "careers@ersmedical.com", "phone": "", "folderCreated": "No", "notes": "National ambulance and patient transport service"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Bibendum Westwood", "address": "Various", "postcode": "", "contactName": "Operations", "jobTitle": "Management", "email": "careers@bibendum.com", "phone": "", "folderCreated": "No", "notes": "Fire safety equipment and services"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Porsche", "address": "Various", "postcode": "", "contactName": "Facilities", "jobTitle": "Management", "email": "careers@porsche.com", "phone": "", "folderCreated": "No", "notes": "Automotive - fire safety compliance"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "easyJet", "address": "Manchester Airport", "postcode": "", "contactName": "Ground Services", "jobTitle": "Operations", "email": "careers@easyjet.com", "phone": "", "folderCreated": "No", "notes": "Aviation - ground handling partner"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Slough Manufacturing", "address": "Slough", "postcode": "", "contactName": "Operations", "jobTitle": "Facilities", "email": "careers@slough-mfg.com", "phone": "", "folderCreated": "No", "notes": "Fire safety site visits through ERS Medical"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Banbury Industrial", "address": "Banbury", "postcode": "", "contactName": "Operations", "jobTitle": "Facilities", "email": "careers@banbury-ind.com", "phone": "", "folderCreated": "No", "notes": "Fire safety site visits through ERS Medical"},
  {"timestamp": "2026-09-24T00:00:00Z", "company": "Cambridge Manufacturing", "address": "Cambridge", "postcode": "", "contactName": "Operations", "jobTitle": "Facilities", "email": "careers@cambridge-mfg.com", "phone": "", "folderCreated": "No", "notes": "Fire safety site visits through ERS Medical"}
];

/* ======================================================================
   Screening answers & CV management - form application data & file storage.
   
   Screening answers come from Applications tabs - we retrieve them as structured
   answers mapped to form field labels for display in the dashboard.
   
   CV files are stored in Drive next to submission docs for easy reference.
   ====================================================================== */

const SCREENING_FORM_FIELDS = [
  { key: 'name', label: 'Candidate Name', col: 2 },
  { key: 'email', label: 'Email', col: 3 },
  { key: 'phone', label: 'Phone', col: 4 },
  { key: 'employment_status', label: 'Current Employment Status', col: 5 },
  { key: 'notice_period', label: 'Notice Period', col: 6 },
  { key: 'transport_background', label: 'Transport Background', col: 7 },
  { key: 'recent_role', label: 'Recent Role Description', col: 8 },
  { key: 'customer_liaison', label: 'Customer/Haulier Liaison', col: 9 },
  { key: 'kpi_comfort', label: 'KPI/OTIF Comfort', col: 10 },
  { key: 'excel_skill', label: 'Excel Skill Level', col: 11 },
  { key: 'multi_priority', label: 'Multi-priority Rating', col: 12 },
  { key: 'work_environment', label: 'Ideal Work Environment', col: 13 },
  { key: 'location_commute', label: 'Location/Trentham Commute', col: 14 },
  { key: 'salary_expectation', label: 'Salary Expectation', col: 15 },
  { key: 'additional_info', label: 'Additional Info', col: 16 },
];

// Helper: find screening answers row for a candidate by name
// Tries full name first, then first-name-initial fallback
async function findApplicationRow(candidateName, role) {
  const sheets = getSheetsClient();
  const tabName = `Applications - ${await formRoleFor(candidateName, role)}`;
  try {
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A2:AJ`,
    });
    const rows = result.data.values || [];
    
    // Try exact full name match first (case-insensitive, trim spaces)
    const nameNormalized = candidateName.toLowerCase().trim();
    let rowIndex = rows.findIndex(r => 
      (r[2] || '').toLowerCase().trim() === nameNormalized
    );
    
    if (rowIndex !== -1) {
      return { row: rows[rowIndex], matchType: 'full', index: rowIndex };
    }
    
    // Fallback to first-name-initial match (e.g. "Kelly B" matches "Kelly Brammer")
    const parts = candidateName.split(' ');
    if (parts.length >= 2) {
      const firstName = parts[0].toLowerCase();
      const initial = parts[1].charAt(0).toLowerCase();
      rowIndex = rows.findIndex(r => {
        const fullName = (r[2] || '').toLowerCase().trim();
        const nameParts = fullName.split(' ');
        return nameParts[0] === firstName && nameParts[1] && nameParts[1].charAt(0) === initial;
      });
      if (rowIndex !== -1) {
        return { row: rows[rowIndex], matchType: 'initial', index: rowIndex };
      }
    }
    
    // No match found - return all rows for manual picker
    return { row: null, matchType: 'none', allRows: rows };
  } catch (e) {
    console.error(`Error finding application row for ${candidateName} in ${tabName}:`, e.message);
    return { row: null, matchType: 'error' };
  }
}

// Helper: find or create a candidate folder in a company Drive folder
async function getOrCreateCandidateFolder(companyFolderId, candidateName) {
  const drive = getUploadDriveClient();
  try {
    // Look for existing folder
    const query = `'${companyFolderId}' in parents and name='${escDriveQuery(candidateName)}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;
    const list = await drive.files.list({
      q: query,
      spaces: 'drive',
      pageSize: 1,
      fields: 'files(id, name)',
    });
    if (list.data.files.length > 0) {
      return list.data.files[0].id;
    }
    // Create new folder
    const folder = await drive.files.create({
      resource: {
        name: candidateName,
        mimeType: 'application/vnd.google-apps.folder',
        parents: [companyFolderId],
      },
      fields: 'id',
    });
    return folder.data.id;
  } catch (e) {
    console.error(`Error getting/creating candidate folder:`, e.message);
    return null;
  }
}

// GET screening form answers for a candidate
// Pass candidateName in query: ?name=Kelly+Brammer&role=Transport+Coordinator
app.get('/api/candidates/:id/screening-answers', async (req, res) => {
  try {
    const { name, role } = req.query;
    if (!name || !role) {
      return res.status(400).json({ error: 'name and role query parameters required' });
    }
    
    const result = await findApplicationRow(name, role);
    
    if (!result.row) {
      // No match found - return all candidates for manual picker
      if (result.allRows) {
        const allApplicants = result.allRows.map(r => ({
          name: r[2] || '',
          email: r[3] || '',
          dateApplied: r[1] || ''
        })).filter(a => a.name); // Only rows with names
        
        return res.status(404).json({ 
          error: 'No exact match found',
          needsManualPick: true,
          applicants: allApplicants,
          matchType: result.matchType
        });
      }
      return res.status(404).json({ error: 'Screening answers not found' });
    }
    
    const row = result.row;
    const answers = {};
    const smFields = await getScreeningFieldsForRole(await formRoleFor(name, role));
    (smFields || SCREENING_FORM_FIELDS).forEach(field => {
      answers[field.key] = {
        label: field.label,
        value: row[field.col] || ''
      };
    });
    
    res.json({ 
      data: answers,
      fullName: row[2] || '',
      matchType: result.matchType
    });
  } catch (e) {
    console.error('GET /api/candidates/:id/screening-answers error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- Shared CV save (pipeline card upload AND Candidate Pool upload) ----
// Same folder logic as the application form: reuse the candidate's existing
// folder (company folder first, then Unassigned - New Applications), otherwise
// create Unassigned - New Applications / [Candidate Name]. File is named
// "[Candidate Name] - CV.ext" so every route finds it the same way.
function cleanCandidateName(name) {
  return String(name || '').trim().replace(/\s+/g, ' ').replace(/['"\\]/g, '');
}

function validateCvUpload(fileName, fileData) {
  if (!fileName || !fileData) return 'A CV file is required';
  if (!/\.(pdf|docx?)$/i.test(String(fileName))) return 'CV must be a PDF, DOC or DOCX file';
  if (String(fileData).length > MAX_CV_BASE64_LENGTH) return 'CV is larger than 5MB';
  return null;
}

async function resolveCandidateCvFolder(company, name) {
  const drive = getUploadDriveClient();
  const isFolder = f => f.mimeType === 'application/vnd.google-apps.folder';
  const cleanName = cleanCandidateName(name);
  const top = await listFolderContents(SUBMISSIONS_FOLDER_ID);
  const parents = [company, UNASSIGNED_LABEL]
    .filter((v, i, a) => v && a.indexOf(v) === i)
    .map(n => top.find(f => f.name === n && isFolder(f)))
    .filter(Boolean);
  const variants = [cleanName, String(name || '').trim()].filter((v, i, a) => v && a.indexOf(v) === i);
  for (const parent of parents) {
    for (const v of variants) {
      const list = await drive.files.list({
        q: `'${parent.id}' in parents and name='${escDriveQuery(v)}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
        spaces: 'drive',
        pageSize: 1,
        fields: 'files(id)',
      });
      if (list.data.files && list.data.files.length) return list.data.files[0].id;
    }
  }
  const unassignedId = await getOrCreateCandidateFolder(SUBMISSIONS_FOLDER_ID, UNASSIGNED_LABEL);
  if (!unassignedId) throw new Error('Could not open the "Unassigned - New Applications" folder in Drive');
  const candidateFolderId = await getOrCreateCandidateFolder(unassignedId, cleanName);
  if (!candidateFolderId) throw new Error('Could not create the candidate folder in Drive');
  return candidateFolderId;
}

async function saveCandidateCv({ company, name, fileName, fileData }) {
  const folderId = await resolveCandidateCvFolder(company, name);
  const ext = (String(fileName).match(/\.[A-Za-z0-9]+$/) || ['.pdf'])[0].toLowerCase();
  const driveName = `${cleanCandidateName(name)} - CV${ext}`;
  const drive = getUploadDriveClient();
  let file;
  try {
    file = await drive.files.create({
      resource: { name: driveName, parents: [folderId] },
      media: { mimeType: mimeFromName(fileName), body: Readable.from([Buffer.from(fileData, 'base64')]) },
      fields: 'id, name, webViewLink',
    });
  } catch (e) {
    throw new Error(friendlyDriveError(e));
  }
  return { fileId: file.data.id, fileName: driveName, link: file.data.webViewLink || '' };
}

// POST CV file upload for a candidate (pipeline card)
app.post('/api/candidates/:id/cv', async (req, res) => {
  try {
    const { company, name, fileData, fileName, role } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Candidate name is required' });
    const problem = validateCvUpload(fileName, fileData);
    if (problem) return res.status(400).json({ error: problem });

    const saved = await saveCandidateCv({ company, name, fileName, fileData });

    if (role) {
      try {
        await upsertPoolEntry({ name, role, company, stage: 'applied', source: 'application' }, true, { createOnly: true });
        await attachCvToPool(poolIdFor(name, role), saved);
      } catch (poolErr) {
        console.error('Could not link uploaded CV to pool:', poolErr.message);
      }
    }
    res.json({ ok: true, fileId: saved.fileId, fileName: saved.fileName, link: saved.link });
  } catch (e) {
    console.error('POST /api/candidates/:id/cv error:', e.message);
    res.status(500).json({ error: 'Drive upload failed: ' + e.message });
  }
});

// GET CV file for a candidate (returns file data or link)
app.get('/api/candidates/:id/cv', async (req, res) => {
  try {
    const { id } = req.params;
    const { company, name } = req.query;
    if (!company || !name) {
      return res.status(400).json({ error: 'company and name query params required' });
    }
    const drive = google.drive({ version: 'v3', auth: getAuthClient() });
    const companyFolders = await listFolderContents(SUBMISSIONS_FOLDER_ID);
    const isFolder = f => f.mimeType === 'application/vnd.google-apps.folder';
    // Look in the assigned company folder first, then where form applicants land
    const tryFolders = [company, UNASSIGNED_LABEL]
      .filter((v, i, a) => a.indexOf(v) === i)
      .map(n => companyFolders.find(f => f.name === n && isFolder(f)))
      .filter(Boolean);
    if (!tryFolders.length) {
      return res.status(404).json({ error: `Company folder not found: ${company}` });
    }
    const cleanedName = String(name).trim().replace(/\s+/g, ' ').replace(/['"\\]/g, '');
    for (const folder of tryFolders) {
      const folderName = folder.name === UNASSIGNED_LABEL ? cleanedName : name;
      const list = await drive.files.list({
        q: `'${folder.id}' in parents and name='${escDriveQuery(folderName)}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
        spaces: 'drive',
        pageSize: 1,
        fields: 'files(id)',
      });
      if (list.data.files.length === 0) continue;
      const cvList = await drive.files.list({
        q: `'${list.data.files[0].id}' in parents and (mimeType='application/pdf' or name contains 'CV' or name contains 'cv') and trashed=false`,
        spaces: 'drive',
        pageSize: 1,
        fields: 'files(id, name, webViewLink, mimeType)',
      });
      if (cvList.data.files.length === 0) continue;
      const cvFile = cvList.data.files[0];
      return res.json({
        data: { fileId: cvFile.id, fileName: cvFile.name, link: cvFile.webViewLink, mimeType: cvFile.mimeType }
      });
    }
    return res.status(404).json({ error: 'No CV found for this candidate' });
  } catch (e) {
    console.error('GET /api/candidates/:id/cv error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/init-bulk-clients', async (req, res) => {
  try {
    const sheets = getSheetsClient();
    const rows = INITIAL_CLIENTS.map(c => clientToRow(c));

    const result = await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: CLIENT_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: rows },
    });

    res.json({ 
      ok: true, 
      message: `Imported ${INITIAL_CLIENTS.length} client records`,
      updatesAppended: result.data.updates.updatedRows 
    });
  } catch (e) {
    console.error('GET /api/init-bulk-clients error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* Tasks - stored in "Tasks" sheet of SHEET_ID */
const TASKS_TAB = 'Tasks';
const TASKS_RANGE = `${TASKS_TAB}!A2:I`;

async function getTasksSheet() {
  const sheets = getSheetsClient();
  try {
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: TASKS_RANGE,
    });
    return result.data.values || [];
  } catch (e) {
    return [];
  }
}

function rowToTask(row) {
  // Safely get archived value - default to false if missing
  let archivedValue = row[8];
  const isArchived = archivedValue && archivedValue.toString().toLowerCase().trim() === 'true';
  
  return {
    id: row[0],
    user: row[1],
    title: row[2],
    priority: row[3],
    dueDate: row[4],
    context: row[5],
    status: row[6],
    recurring: row[7] || 'none',
    archived: isArchived
  };
}

function taskToRow(task) {
  return [
    task.id,
    task.user,
    task.title,
    task.priority,
    task.dueDate,
    task.context,
    task.status,
    task.recurring,
    task.archived ? 'true' : 'false'
  ];
}

app.get('/api/tasks', async (req, res) => {
  try {
    const userRole = req.headers['x-user-role'] || 'dan';
    const rows = await getTasksSheet();
    
    const tasks = rows
      .map(rowToTask)
      .filter(t => {
        // Skip if explicitly archived (true)
        if (t.archived === true) return false;
        
        // Filter by user
        if (userRole === 'dan') return true;
        return String(t.user || '').toLowerCase() === String(userRole).toLowerCase();
      });
    
    res.json(tasks);
  } catch (e) {
    console.error('GET /api/tasks error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/tasks/archive', async (req, res) => {
  try {
    const userRole = req.headers['x-user-role'] || 'dan';
    const rows = await getTasksSheet();
    
    const tasks = rows
      .map(rowToTask)
      .filter(t => {
        // Only archived tasks
        if (t.archived !== true) return false;
        
        // Filter by user
        if (userRole === 'dan') return true;
        return String(t.user || '').toLowerCase() === String(userRole).toLowerCase();
      });
    
    res.json(tasks);
  } catch (e) {
    console.error('GET /api/tasks/archive error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/tasks', async (req, res) => {
  try {
    const userRole = req.headers['x-user-role'] || 'dan';
    const { title, priority, dueDate, context, recurring } = req.body;
    const taskId = `task-${Date.now()}`;
    
    const task = {
      id: taskId,
      user: userRole,
      title,
      priority,
      dueDate,
      context,
      status: 'Open',
      recurring: recurring || 'none',
      archived: false
    };
    
    const sheets = getSheetsClient();
    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: TASKS_RANGE,
      valueInputOption: 'RAW',
      requestBody: { values: [taskToRow(task)] }
    });
    
    res.json(task);
  } catch (e) {
    console.error('POST /api/tasks error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/tasks/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, priority, dueDate, context, status, recurring } = req.body;
    
    const rows = await getTasksSheet();
    const rowIndex = rows.findIndex(r => r[0] === id);
    
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    const task = {
      ...rowToTask(rows[rowIndex]),
      title: title || rows[rowIndex][2],
      priority: priority || rows[rowIndex][3],
      dueDate: dueDate || rows[rowIndex][4],
      context: context || rows[rowIndex][5],
      status: status || rows[rowIndex][6],
      recurring: recurring || rows[rowIndex][7]
    };
    if (req.body.user && isAdmin(req) && ['dan', 'ella'].includes(String(req.body.user).toLowerCase())) {
      task.user = String(req.body.user).toLowerCase();
    }
    
    const sheets = getSheetsClient();
    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `${TASKS_TAB}!A${rowIndex + 2}:I${rowIndex + 2}`,
      valueInputOption: 'RAW',
      requestBody: { values: [taskToRow(task)] }
    });
    
    res.json(task);
  } catch (e) {
    console.error('PUT /api/tasks/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/tasks/:id/complete', async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`[Tasks] Completing task: ${id}`);
    
    const rows = await getTasksSheet();
    const rowIndex = rows.findIndex(r => r[0] === id);
    console.log(`[Tasks] Found at row index: ${rowIndex}`);
    
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    const originalTask = rowToTask(rows[rowIndex]);
    console.log(`[Tasks] Original task:`, originalTask);
    
    const newTask = { ...originalTask, status: 'Complete', archived: true };
    console.log(`[Tasks] New task:`, newTask);
    console.log(`[Tasks] Task row to save:`, taskToRow(newTask));
    
    const sheets = getSheetsClient();
    
    // Archive the completed task
    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `${TASKS_TAB}!A${rowIndex + 2}:I${rowIndex + 2}`,
      valueInputOption: 'RAW',
      requestBody: { values: [taskToRow(newTask)] }
    });
    
    console.log(`[Tasks] Task archived successfully`);
    
    // If recurring, create next instance
    if (originalTask.recurring !== 'none') {
      const nextDate = calculateNextDate(originalTask.dueDate, originalTask.recurring);
      const nextTask = {
        id: `task-${Date.now()}`,
        user: originalTask.user,
        title: originalTask.title,
        priority: originalTask.priority,
        dueDate: nextDate,
        context: originalTask.context,
        status: 'Open',
        recurring: originalTask.recurring,
        archived: false
      };
      
      await sheets.spreadsheets.values.append({
        spreadsheetId: SHEET_ID,
        range: TASKS_RANGE,
        valueInputOption: 'RAW',
        requestBody: { values: [taskToRow(nextTask)] }
      });
      
      console.log(`[Tasks] Next recurring task created`);
      res.json({ completed: newTask, next: nextTask });
    } else {
      res.json({ completed: newTask });
    }
  } catch (e) {
    console.error('POST /api/tasks/:id/complete error:', e.message);
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/tasks/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const rows = await getTasksSheet();
    const rowIndex = rows.findIndex(r => r[0] === id);
    
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    const sheets = getSheetsClient();
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SHEET_ID,
      requestBody: {
        requests: [{
          deleteRange: {
            range: {
              sheetId: 0,
              startRowIndex: rowIndex + 1,
              endRowIndex: rowIndex + 2
            },
            shiftDimension: 'ROWS'
          }
        }]
      }
    });
    
    res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /api/tasks/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

function calculateNextDate(dateStr, recurring) {
  const [year, month, day] = dateStr.split('-').map(Number);
  const date = new Date(year, month - 1, day);
  
  if (recurring === 'daily') {
    date.setDate(date.getDate() + 1);
  } else if (recurring === 'weekly') {
    date.setDate(date.getDate() + 7);
  } else if (recurring === 'biweekly') {
    date.setDate(date.getDate() + 14);
  } else if (recurring === 'monthly') {
    date.setMonth(date.getMonth() + 1);
  }
  
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/* Cold Call Tracker API */

const COLD_CALLS_TAB = 'ColdCalls';
const COLD_CALLS_RANGE = `${COLD_CALLS_TAB}!A2:I`;

async function getColdCallsSheet() {
  if (!CLIENT_SHEET_ID) throw new Error('CLIENT_SHEET_ID is not set');
  const sheets = getSheetsClient();
  try {
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: CLIENT_SHEET_ID,
      range: COLD_CALLS_RANGE
    });
    
    const rows = result.data.values || [];
    return rows.map((row, idx) => ({
      id: `cc-${idx}`,
      company: row[0] || '',
      contactNames: row[1] || '',
      contactType: row[2] || 'call',
      dateCalled: row[3] || '',
      notes: row[4] || '',
      followupDate: row[5] || '',
      status: row[6] || 'active',
      outcome: row[7] || 'attempt',
      createdAt: row[8] || new Date().toISOString()
    }));
  } catch (e) {
    if (e.message.includes('not found')) {
      return [];
    }
    throw e;
  }
}

app.get('/api/cold-calls', async (req, res) => {
  try {
    const coldCalls = await getColdCallsSheet();
    res.json(coldCalls);
  } catch (e) {
    console.error('GET /api/cold-calls error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/cold-calls', async (req, res) => {
  try {
    const { company, contactNames, contactType, dateCalled, notes, followupDate, status, outcome } = req.body;
    
    if (!company || !contactNames || !dateCalled) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const sheets = getSheetsClient();
    const newRow = [
      company,
      contactNames,
      contactType || 'call',
      dateCalled,
      notes || '',
      followupDate || '',
      status || 'active',
      outcome || 'attempt',
      new Date().toISOString()
    ];
    
    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: COLD_CALLS_RANGE,
      valueInputOption: 'USER_ENTERED',
      requestBody: {
        values: [newRow]
      }
    });
    
    res.json({ ok: true, company, contactNames });
  } catch (e) {
    console.error('POST /api/cold-calls error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/cold-calls/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const idx = parseInt(id.split('-')[1], 10);
    
    if (isNaN(idx)) {
      return res.status(400).json({ error: 'Invalid ID' });
    }
    
    const sheets = getSheetsClient();
    const coldCalls = await getColdCallsSheet();
    
    if (idx >= coldCalls.length) {
      return res.status(404).json({ error: 'Cold call not found' });
    }
    
    const call = coldCalls[idx];
    const updated = { ...call, ...updates };
    
    const updateRow = [
      updated.company,
      updated.contactNames,
      updated.contactType,
      updated.dateCalled,
      updated.notes,
      updated.followupDate,
      updated.status,
      updated.outcome,
      updated.createdAt
    ];
    
    await sheets.spreadsheets.values.update({
      spreadsheetId: CLIENT_SHEET_ID,
      range: `${COLD_CALLS_TAB}!A${idx + 2}:I${idx + 2}`,
      valueInputOption: 'USER_ENTERED',
      requestBody: {
        values: [updateRow]
      }
    });
    
    res.json({ ok: true });
  } catch (e) {
    console.error('PATCH /api/cold-calls/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/cold-calls/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const idx = parseInt(id.split('-')[1], 10);
    
    if (isNaN(idx)) {
      return res.status(400).json({ error: 'Invalid ID' });
    }
    
    const sheets = getSheetsClient();
    const coldCalls = await getColdCallsSheet();
    
    if (idx >= coldCalls.length) {
      return res.status(404).json({ error: 'Cold call not found' });
    }
    
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: CLIENT_SHEET_ID,
      requestBody: {
        requests: [{
          deleteRange: {
            range: {
              sheetId: 0,
              startRowIndex: idx + 1,
              endRowIndex: idx + 2
            },
            shiftDimension: 'ROWS'
          }
        }]
      }
    });
    
    res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /api/cold-calls/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ======================================================================
   Candidate Pool - permanent database of every candidate who has applied
   or been submitted, kept in a "Candidate Pool" tab of the tracker sheet.

   Columns (A:O):
   id | name | email | phone | company | role | furthest_stage | current_stage |
   date_added | last_updated | notes | cv_file_id | cv_file_name | cv_link | in_pipeline

   - One row per candidate per role. id is a slug of name + role.
   - Rows are never deleted. If a candidate is removed from the pipeline the
     row stays and in_pipeline flips to "No".
   - furthest_stage only ever moves forward through the pipeline.
   - CVs live in Drive; the row stores the file id, name and link.
   ====================================================================== */

const RETENTION_MONTHS = parseInt(process.env.RETENTION_MONTHS, 10) || 12;
const POOL_TAB = 'Candidate Pool';
const POOL_HEADER = [
  'id', 'name', 'email', 'phone', 'company', 'role', 'furthest_stage', 'current_stage',
  'date_added', 'last_updated', 'notes', 'cv_file_id', 'cv_file_name', 'cv_link', 'in_pipeline', 'tags',
  'source', 'consent_date', 'consent_basis', 'review_date', 'erased',
];
const POOL_WIDTH = POOL_HEADER.length;
const POOL_LAST_COL = 'U';
const POOL_CV_FOLDER_NAME = 'Candidate Pool CVs';

// Forward progression only. "rejected" is deliberately not ranked - a rejection
// never changes how far someone got.
const STAGE_RANK = {
  applied: 0,
  ready_to_submit: 0.5,
  submitted: 1,
  interview_requested: 2,
  interview_scheduled: 3,
  interviewed: 4,
  offer: 5,
  start_date: 6,
  day1: 7,
  week1: 8,
  month1: 9,
};

function normStage(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, '_') || 'applied';
}

function stageRank(s) {
  const r = STAGE_RANK[normStage(s)];
  return r === undefined ? -1 : r;
}

function poolIdFor(name, role) {
  const clean = `${String(name || '').trim().replace(/\s+/g, ' ')}|${String(role || '').trim().replace(/\s+/g, ' ')}`;
  return clean.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function reviewDueFor(r) {
  const added = String(r[8] || '').slice(0, 10);
  const touched = String(r[9] || '').slice(0, 10);
  const lastActive = touched > added ? touched : added;
  const auto = lastActive ? addMonthsISO(lastActive, RETENTION_MONTHS) : '';
  const manual = String(r[19] || '');
  return manual > auto ? manual : auto;
}

function padPoolRow(r) {
  const a = (r || []).slice(0, POOL_WIDTH).map(v => (v == null ? '' : String(v)));
  while (a.length < POOL_WIDTH) a.push('');
  return a;
}

function poolRowChanged(a, b) {
  // last_updated (index 9) is ignored when deciding whether anything changed
  for (let i = 0; i < POOL_WIDTH; i++) {
    if (i === 9) continue;
    if ((a[i] || '') !== (b[i] || '')) return true;
  }
  return false;
}

function rowToPoolEntry(row) {
  const r = padPoolRow(row);
  return {
    id: r[0],
    name: r[1],
    email: r[2],
    phone: r[3],
    company: r[4],
    role: r[5],
    furthestStage: r[6] || 'applied',
    currentStage: r[7] || 'applied',
    dateAdded: r[8],
    lastUpdated: r[9],
    notes: r[10],
    cvFileName: r[12],
    hasCv: !!r[11],
    inPipeline: r[14] !== 'No',
    tags: r[15],
    source: r[16],
    consentDate: r[17],
    consentBasis: r[18],
    reviewDate: r[19],
    reviewDue: reviewDueFor(r),
    erased: r[20],
  };
}

function mimeFromName(name) {
  const n = String(name || '').toLowerCase();
  if (n.endsWith('.pdf')) return 'application/pdf';
  if (n.endsWith('.docx')) return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  if (n.endsWith('.doc')) return 'application/msword';
  return 'application/octet-stream';
}

function escDriveQuery(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

// ---- Tab bootstrap -----------------------------------------------------

let poolTabReady = false;

async function ensurePoolTab() {
  if (poolTabReady) return;
  const sheets = getSheetsClient();
  const ss = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties.title' });
  const exists = (ss.data.sheets || []).some(s => s.properties.title === POOL_TAB);
  if (!exists) {
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SHEET_ID,
      requestBody: { requests: [{ addSheet: { properties: { title: POOL_TAB } } }] },
    });
  }
  const head = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `'${POOL_TAB}'!A1:${POOL_LAST_COL}1`,
  });
  const first = head.data.values && head.data.values[0];
  if (!first || first[0] !== 'id' || first.length < POOL_WIDTH) {
    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `'${POOL_TAB}'!A1:${POOL_LAST_COL}1`,
      valueInputOption: 'RAW',
      requestBody: { values: [POOL_HEADER] },
    });
  }
  poolTabReady = true;
}

// Short-lived cache so busy screens do not exhaust Google's per-minute read quota.
// Cleared after every locked pool write, so edits are always visible straight away.
let poolRowsCache = null;
let poolRowsCacheAt = 0;
const POOL_CACHE_MS = 10000;

async function readPoolRows() {
  if (poolRowsCache && Date.now() - poolRowsCacheAt < POOL_CACHE_MS) return poolRowsCache;
  await ensurePoolTab();
  const sheets = getSheetsClient();
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `'${POOL_TAB}'!A2:${POOL_LAST_COL}`,
  });
  poolRowsCache = result.data.values || [];
  poolRowsCacheAt = Date.now();
  return poolRowsCache;
}

// ---- Serialised access so concurrent saves never create duplicate rows --

let poolChain = Promise.resolve();
function withPoolLock(fn) {
  const run = poolChain.then(async () => {
    try { return await fn(); }
    finally { poolRowsCache = null; }
  });
  poolChain = run.catch(() => {});
  return run;
}

// ---- Merge logic -------------------------------------------------------

// live: { name, role, company, stage, notes, email, phone, dateAdded, source }
// opts.createOnly: if the row already exists, only fill blank contact/company fields
function mergeLiveIntoPoolRow(existingRow, live, inPipeline, opts = {}) {
  const today = new Date().toISOString().slice(0, 10);
  const row = padPoolRow(existingRow);
  const isNew = !existingRow;
  const stage = normStage(live.stage);
  const liveRank = stageRank(stage);

  if (isNew) {
    row[0] = poolIdFor(live.name, live.role);
    row[1] = String(live.name).trim().replace(/\s+/g, ' ');
    row[5] = String(live.role).trim();
    row[6] = liveRank >= 0 ? stage : (live.source === 'application' ? 'applied' : 'submitted');
    row[7] = stage;
    row[8] = /^\d{4}-\d{2}-\d{2}/.test(live.dateAdded || '') ? live.dateAdded.slice(0, 10) : today;
    row[10] = live.notes || '';
    row[14] = inPipeline ? 'Yes' : 'No';
    if (live.consentDate) { row[17] = live.consentDate; row[18] = live.consentBasis || 'Application form'; }
    else if (opts.autoConsent && live.source === 'application') { row[17] = row[8]; row[18] = 'Application form'; }
  } else if (!opts.createOnly) {
    if (liveRank > stageRank(row[6])) row[6] = stage;
    row[7] = stage;
    if (inPipeline && live.notes !== undefined) row[10] = live.notes || '';
    row[14] = inPipeline ? 'Yes' : 'No';
  }

  if (!isNew && !row[17] && live.consentDate) { row[17] = live.consentDate; row[18] = live.consentBasis || 'Application form'; }
  if (!row[2] && live.email) row[2] = live.email;
  if (!row[3] && live.phone) row[3] = live.phone;
  if (!opts.createOnly || !row[4]) {
    if (live.company) row[4] = live.company;
  }
  if (!opts.createOnly && live.email) row[2] = live.email;
  if (!opts.createOnly && live.phone) row[3] = live.phone;
  return row;
}

// ---- Live pipeline snapshot -------------------------------------------

async function collectLiveCandidates() {
  const dashRows = await readAllRows();
  const apps = await readApplicationsRows(true);
  const map = new Map();

  for (const a of apps) {
    if (!a.name || !a.role) continue;
    map.set(poolIdFor(a.name, a.role), {
      name: a.name, role: a.role, company: a.company, stage: a.stage, notes: a.notes,
      email: a.email, phone: a.phone, dateAdded: a.date, source: 'application',
      consentDate: a.consentApp === 'Yes' ? (a.consentDate || String(a.date).slice(0, 10)) : '',
      consentBasis: a.consentApp === 'Yes'
        ? (a.consentPool === 'Yes' ? 'Application form - talent pool' : 'Application form - this role only')
        : '',
    });
  }

  for (const r of dashRows) {
    if (!r || !r[0]) continue;
    const c = rowToCandidate(r);
    if (!c.name || !c.role) continue;
    const id = poolIdFor(c.name, c.role);
    const prev = map.get(id);
    map.set(id, {
      name: c.name, role: c.role, company: c.company, stage: c.stage, notes: c.notes,
      email: c.email || (prev && prev.email) || '',
      phone: c.phone || (prev && prev.phone) || '',
      dateAdded: (prev && prev.dateAdded) || c.date,
      source: (prev && prev.source === 'application') ? 'application' : 'dashboard',
      consentDate: (prev && prev.consentDate) || '',
      consentBasis: (prev && prev.consentBasis) || '',
    });
  }
  return map;
}

async function doReconcile() {
  const sheets = getSheetsClient();
  const poolRows = await readPoolRows();
  const live = await collectLiveCandidates();
  const now = new Date().toISOString();
  const autoConsent = await formConsentOn();

  const byId = new Map();
  poolRows.forEach((r, i) => { if (r && r[0]) byId.set(r[0], { row: r, index: i }); });

  const updates = [];
  const appends = [];
  const seen = new Set();
  let added = 0;
  let updated = 0;

  for (const l of live.values()) {
    const id = poolIdFor(l.name, l.role);
    seen.add(id);
    const ex = byId.get(id);
    const merged = mergeLiveIntoPoolRow(ex ? ex.row : null, l, true, { autoConsent });
    if (!ex) {
      merged[9] = now;
      appends.push(merged);
      added++;
    } else if (poolRowChanged(padPoolRow(ex.row), merged)) {
      merged[9] = now;
      const rowNum = ex.index + 2;
      updates.push({ range: `'${POOL_TAB}'!A${rowNum}:${POOL_LAST_COL}${rowNum}`, values: [merged] });
      updated++;
    }
  }

  // Candidates no longer in the pipeline stay in the pool, flagged accordingly
  for (const [id, ex] of byId) {
    if (seen.has(id)) continue;
    if ((ex.row[14] || '') === 'No' || (ex.row[20] || '')) continue;
    const r = padPoolRow(ex.row);
    r[14] = 'No';
    const rowNum = ex.index + 2;
    updates.push({ range: `'${POOL_TAB}'!A${rowNum}:${POOL_LAST_COL}${rowNum}`, values: [r] });
    updated++;
  }

  if (updates.length) {
    await sheets.spreadsheets.values.batchUpdate({
      spreadsheetId: SHEET_ID,
      requestBody: { valueInputOption: 'RAW', data: updates },
    });
  }
  if (appends.length) {
    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: `'${POOL_TAB}'!A:${POOL_LAST_COL}`,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: appends },
    });
  }
  return { added, updated, total: byId.size + added };
}

function reconcilePool() {
  return withPoolLock(doReconcile);
}

let reconcileQueued = false;
function scheduleReconcile() {
  if (reconcileQueued) return;
  reconcileQueued = true;
  withPoolLock(async () => {
    reconcileQueued = false;
    return doReconcile();
  }).catch(e => console.error('Pool reconcile failed:', e.message));
}

// Insert or update a single candidate. Used by the "ensure" endpoint, the
// delete snapshot and the CV attach helper.
function upsertPoolEntry(live, inPipeline = true, opts = {}) {
  return withPoolLock(async () => {
    const sheets = getSheetsClient();
    const rows = await readPoolRows();
    const id = poolIdFor(live.name, live.role);
    const idx = rows.findIndex(r => r && r[0] === id);
    const ex = idx >= 0 ? rows[idx] : null;
    const merged = mergeLiveIntoPoolRow(ex, live, inPipeline, opts);
    if (!ex) {
      merged[9] = new Date().toISOString();
      await sheets.spreadsheets.values.append({
        spreadsheetId: SHEET_ID,
        range: `'${POOL_TAB}'!A:${POOL_LAST_COL}`,
        valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS',
        requestBody: { values: [merged] },
      });
    } else if (poolRowChanged(padPoolRow(ex), merged)) {
      merged[9] = new Date().toISOString();
      const rowNum = idx + 2;
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID,
        range: `'${POOL_TAB}'!A${rowNum}:${POOL_LAST_COL}${rowNum}`,
        valueInputOption: 'RAW',
        requestBody: { values: [merged] },
      });
    }
    return merged;
  });
}

// Edit selected columns of one pool row by id
function patchPoolRow(id, patch) {
  return withPoolLock(async () => {
    const sheets = getSheetsClient();
    const rows = await readPoolRows();
    const idx = rows.findIndex(r => r && r[0] === id);
    if (idx === -1) return null;
    const row = padPoolRow(rows[idx]);
    Object.keys(patch).forEach(k => { row[Number(k)] = patch[k]; });
    row[9] = new Date().toISOString();
    const rowNum = idx + 2;
    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `'${POOL_TAB}'!A${rowNum}:${POOL_LAST_COL}${rowNum}`,
      valueInputOption: 'RAW',
      requestBody: { values: [row] },
    });
    return row;
  });
}

// ---- Drive helpers -----------------------------------------------------

async function findLegacyCv(company, name, companyFoldersCache) {
  if (!company || !name) return null;
  const drive = getDriveClient();
  const companyFolders = companyFoldersCache || await listFolderContents(SUBMISSIONS_FOLDER_ID);
  const isFolder = f => f.mimeType === 'application/vnd.google-apps.folder';
  const parents = [company, UNASSIGNED_LABEL]
    .filter((v, i, a) => v && a.indexOf(v) === i)
    .map(n => companyFolders.find(f => f.name === n && isFolder(f)))
    .filter(Boolean);
  if (!parents.length) return null;

  const parts = String(name).trim().split(/\s+/);
  const variants = [String(name).trim(), cleanCandidateName(name)];
  if (parts.length >= 2) variants.push(`${parts[0]} ${parts[parts.length - 1][0]}`);
  const uniqueVariants = variants.filter((v, i, a) => v && a.indexOf(v) === i);

  for (const cf of parents) {
    for (const v of uniqueVariants) {
      const list = await drive.files.list({
        q: `'${cf.id}' in parents and name='${escDriveQuery(v)}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
        spaces: 'drive',
        pageSize: 1,
        fields: 'files(id)',
      });
      if (!list.data.files || list.data.files.length === 0) continue;
      const inside = await drive.files.list({
        q: `'${list.data.files[0].id}' in parents and mimeType!='application/vnd.google-apps.folder' and trashed=false`,
        spaces: 'drive',
        pageSize: 20,
        fields: 'files(id, name, webViewLink, mimeType)',
      });
      const files = inside.data.files || [];
      if (!files.length) continue;
      const pick = files.find(f => /cv/i.test(f.name)) || files.find(f => f.mimeType === 'application/pdf') || files[0];
      return { fileId: pick.id, fileName: pick.name, link: pick.webViewLink || '' };
    }
  }
  return null;
}

async function findPoolRowById(id) {
  const rows = await readPoolRows();
  const idx = rows.findIndex(r => r && r[0] === id);
  return idx === -1 ? null : { row: padPoolRow(rows[idx]), index: idx };
}

async function attachCvToPool(id, info) {
  return patchPoolRow(id, { 11: info.fileId, 12: info.fileName, 13: info.link || '' });
}

// ---- Endpoints ---------------------------------------------------------

// List the whole pool (reconciles with the live pipeline first)
app.get('/api/candidate-pool', async (req, res) => {
  try {
    await reconcilePool();
    const rows = await readPoolRows();
    res.json({ data: rows.filter(r => r && r[0]).map(rowToPoolEntry) });
  } catch (e) {
    console.error('GET /api/candidate-pool error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Reconcile, then look for CVs already uploaded through the older pipeline
// modal (company/candidate Drive folders) and link them to the pool.
app.post('/api/candidate-pool/backfill', async (req, res) => {
  try {
    const result = await reconcilePool();
    const rows = await readPoolRows();
    const companyFolders = await listFolderContents(SUBMISSIONS_FOLDER_ID);
    let cvLinked = 0;

    for (const raw of rows) {
      const row = padPoolRow(raw);
      if (!row[0] || row[11]) continue;
      try {
        const found = await findLegacyCv(row[4], row[1], companyFolders);
        if (found) {
          await attachCvToPool(row[0], found);
          cvLinked++;
        }
      } catch (e) {
        console.error(`Backfill CV lookup failed for ${row[1]}:`, e.message);
      }
    }

    const finalRows = (await readPoolRows()).map(rowToPoolEntry).filter(e => e.id);
    const missingCv = finalRows
      .filter(e => !e.hasCv && stageRank(e.furthestStage) >= 1)
      .map(e => ({ name: e.name, role: e.role, company: e.company }));

    res.json({ ok: true, added: result.added, updated: result.updated, cvLinked, missingCv });
  } catch (e) {
    console.error('POST /api/candidate-pool/backfill error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Make sure one candidate exists in the pool and report whether they have a CV.
// Called by the dashboard right after a candidate is moved to Submitted, so the
// CV reminder can be shown. Never changes stage or notes of an existing row.
app.post('/api/candidate-pool/ensure', async (req, res) => {
  try {
    const { name, role, company, email, phone, stage, notes } = req.body || {};
    if (!name || !role) return res.status(400).json({ error: 'name and role are required' });
    const merged = await upsertPoolEntry(
      { name, role, company: company || '', email: email || '', phone: phone || '', stage: stage || 'submitted', notes: notes || '', source: 'dashboard' },
      true,
      { createOnly: true }
    );
    let row = merged;
    if (!row[11] && row[4]) {
      try {
        const found = await findLegacyCv(row[4], row[1]);
        if (found) row = (await attachCvToPool(row[0], found)) || row;
      } catch (e) {
        console.error('ensure: legacy CV lookup failed:', e.message);
      }
    }
    res.json({ data: rowToPoolEntry(row) });
  } catch (e) {
    console.error('POST /api/candidate-pool/ensure error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Update notes on a pool record
app.put('/api/candidate-pool/:id/notes', async (req, res) => {
  try {
    const row = await patchPoolRow(req.params.id, { 10: String((req.body || {}).notes || '') });
    if (!row) return res.status(404).json({ error: 'Pool record not found' });
    res.json({ ok: true, data: rowToPoolEntry(row) });
  } catch (e) {
    console.error('PUT /api/candidate-pool/:id/notes error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Upload (or replace) the CV for a pool record - same save route as the pipeline card
app.post('/api/candidate-pool/:id/cv', async (req, res) => {
  try {
    const { fileData, fileName } = req.body || {};
    const problem = validateCvUpload(fileName, fileData);
    if (problem) return res.status(400).json({ error: problem });
    const found = await findPoolRowById(req.params.id);
    if (!found) return res.status(404).json({ error: 'Pool record not found' });

    const saved = await saveCandidateCv({
      company: found.row[4],
      name: found.row[1],
      fileName,
      fileData,
    });
    const row = await attachCvToPool(req.params.id, saved);
    auditLog(auditActorOf(req), 'cv_uploaded', 'pool', `${found.row[1]} - ${found.row[5]}`, saved.fileName);
    res.json({ ok: true, data: rowToPoolEntry(row) });
  } catch (e) {
    console.error('POST /api/candidate-pool/:id/cv error:', e.message);
    res.status(500).json({ error: 'Drive upload failed: ' + e.message });
  }
});

// View or download the CV. Streams through the API so it works whether or not
// the person opening it has Drive access to the file.
app.get('/api/candidate-pool/:id/cv/file', async (req, res) => {
  try {
    const found = await findPoolRowById(req.params.id);
    if (!found) return res.status(404).json({ error: 'Pool record not found' });
    let fileId = found.row[11];

    if (!fileId && found.row[4]) {
      const legacy = await findLegacyCv(found.row[4], found.row[1]);
      if (legacy) {
        await attachCvToPool(req.params.id, legacy);
        fileId = legacy.fileId;
      }
    }
    if (!fileId) return res.status(404).json({ error: 'No CV on file for this candidate' });

    const drive = getDriveClient();
    const meta = await drive.files.get({ fileId, fields: 'name, mimeType, webViewLink' });
    const mime = meta.data.mimeType || 'application/octet-stream';

    if (mime.startsWith('application/vnd.google-apps.')) {
      return res.redirect(meta.data.webViewLink);
    }

    const wantsView = req.query.mode !== 'download';
    const inlineOk = mime === 'application/pdf' || mime.startsWith('image/');
    if (wantsView && !inlineOk && meta.data.webViewLink) {
      return res.redirect(meta.data.webViewLink);
    }

    const stream = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'stream' });
    res.setHeader('Content-Type', mime);
    res.setHeader(
      'Content-Disposition',
      `${wantsView && inlineOk ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(meta.data.name || 'CV')}`
    );
    stream.data.on('error', err => {
      console.error('CV stream error:', err.message);
      if (!res.headersSent) res.status(500).end();
      else res.end();
    });
    stream.data.pipe(res);
  } catch (e) {
    console.error('GET /api/candidate-pool/:id/cv/file error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});


/* ======================================================================
   Batch 1 additions: Roles, Placements (guarantee tracker), User-aware tasks.

   Generic "simple table" helper: each table is one tab in the tracker sheet
   (SHEET_ID) that is created on first use, with full list / upsert / delete.
   ====================================================================== */

function makeSimpleTable({ tab, header, path, label, seed, guard, auditType, auditName, beforeList }) {
  const width = header.length;
  const lastCol = String.fromCharCode(64 + width);
  let ready = false;
  let chain = Promise.resolve();
  const lock = fn => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };

  async function ensure() {
    if (ready) return;
    const sheets = getSheetsClient();
    const ss = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties.title' });
    let created = false;
    if (!(ss.data.sheets || []).some(s => s.properties.title === tab)) {
      created = true;
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId: SHEET_ID,
        requestBody: { requests: [{ addSheet: { properties: { title: tab } } }] },
      });
    }
    const head = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tab}'!A1:${lastCol}1` });
    const first = head.data.values && head.data.values[0];
    if (!first || first[0] !== header[0] || first.length < width) {
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID,
        range: `'${tab}'!A1:${lastCol}1`,
        valueInputOption: 'RAW',
        requestBody: { values: [header] },
      });
    }
    if (created && seed && seed.length) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: SHEET_ID, range: `'${tab}'!A:${lastCol}`, valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS', requestBody: { values: seed.map(o => header.map(h => (o[h] == null ? '' : String(o[h])))) },
      });
    }
    ready = true;
  }

  async function readRows() {
    await ensure();
    const sheets = getSheetsClient();
    const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tab}'!A2:${lastCol}` });
    return r.data.values || [];
  }

  const pad = row => {
    const a = (row || []).slice(0, width).map(v => (v == null ? '' : String(v)));
    while (a.length < width) a.push('');
    return a;
  };
  const toObj = row => { const r = pad(row); const o = {}; header.forEach((h, i) => { o[h] = r[i]; }); return o; };
  const toRow = o => header.map(h => (o[h] == null ? '' : String(o[h])));

  async function listAll() { return (await readRows()).filter(r => r && r[0]).map(toObj); }
  async function list() { return (await listAll()).filter(o => !String(o.id).startsWith('__')); }

  function upsert(obj) {
    return lock(async () => {
      const sheets = getSheetsClient();
      const rows = await readRows();
      const idx = rows.findIndex(r => r && r[0] === obj.id);
      const row = toRow(obj);
      if (idx === -1) {
        await sheets.spreadsheets.values.append({
          spreadsheetId: SHEET_ID, range: `'${tab}'!A:${lastCol}`, valueInputOption: 'RAW',
          insertDataOption: 'INSERT_ROWS', requestBody: { values: [row] },
        });
      } else {
        const n = idx + 2;
        await sheets.spreadsheets.values.update({
          spreadsheetId: SHEET_ID, range: `'${tab}'!A${n}:${lastCol}${n}`, valueInputOption: 'RAW',
          requestBody: { values: [row] },
        });
      }
      return toObj(row);
    });
  }

  function append(obj) {
    return lock(async () => {
      await ensure();
      const sheets = getSheetsClient();
      await sheets.spreadsheets.values.append({
        spreadsheetId: SHEET_ID, range: `'${tab}'!A:${lastCol}`, valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS', requestBody: { values: [toRow(obj)] },
      });
      return toObj(toRow(obj));
    });
  }

  function remove(id) {
    return lock(async () => {
      const sheets = getSheetsClient();
      const rows = await readRows();
      const idx = rows.findIndex(r => r && r[0] === id);
      if (idx === -1) return false;
      const n = idx + 2;
      await sheets.spreadsheets.values.clear({ spreadsheetId: SHEET_ID, range: `'${tab}'!A${n}:${lastCol}${n}` });
      return true;
    });
  }

  function updateWhere(pred, mutate) {
    return lock(async () => {
      const sheets = getSheetsClient();
      const rows = await readRows();
      const data = [];
      rows.forEach((r, i) => {
        if (!r || !r[0]) return;
        const o = toObj(r);
        if (pred(o)) {
          const m = mutate({ ...o }) || o;
          data.push({ range: `'${tab}'!A${i + 2}:${lastCol}${i + 2}`, values: [toRow(m)] });
        }
      });
      if (data.length) {
        await sheets.spreadsheets.values.batchUpdate({ spreadsheetId: SHEET_ID, requestBody: { valueInputOption: 'RAW', data } });
      }
      return data.length;
    });
  }

  if (path) {
    const g = guard ? [guard] : [];
    app.get(path, ...g, async (req, res) => {
      try {
        if (beforeList) await beforeList();
        res.json({ data: await list() });
      } catch (e) { console.error(`GET ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
    app.post(path, ...g, async (req, res) => {
      try {
        const b = req.body || {};
        if (!b.id) return res.status(400).json({ error: 'id is required' });
        const clean = {};
        header.forEach(h => { if (b[h] !== undefined) clean[h] = b[h]; });
        const existing = (await list()).find(o => o.id === b.id);
        const saved = await upsert({ ...(existing || {}), ...clean });
        if (path === '/api/roles') { publicRolesCache = { at: 0, list: null }; }
        if (auditType) auditLog(auditActorOf(req), existing ? 'updated' : 'created', auditType, auditName ? auditName(saved) : saved.id, '');
        res.json({ ok: true, data: saved });
      } catch (e) { console.error(`POST ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
    app.delete(`${path}/:id`, ...g, async (req, res) => {
      try {
        const existing = (await listAll()).find(o => o.id === req.params.id);
        const ok = await remove(req.params.id);
        if (!ok) return res.status(404).json({ error: `${label || 'Record'} not found` });
        if (auditType) auditLog(auditActorOf(req), 'deleted', auditType, existing && auditName ? auditName(existing) : req.params.id, '');
        res.json({ ok: true });
      } catch (e) { console.error(`DELETE ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
  }
  return { list, listAll, upsert, append, remove, updateWhere, ensure };
}

/* ---------- Users (personal passwords, stored as hashes only) ---------- */

usersTable = makeSimpleTable({
  tab: 'Users',
  header: ['id', 'password_hash', 'must_change', 'updated_at', 'updated_by'],
  path: null,
  label: 'User',
});

/* ---------- Roles / Vacancies ---------- */

const rolesTable = makeSimpleTable({
  tab: 'Roles',
  header: ['id', 'company', 'role', 'contact', 'salary_band', 'fee_percent', 'status', 'date_opened', 'date_closed', 'notes', 'positions', 'requirements', 'public_title', 'form_slug', 'show_on_careers', 'location', 'public_content'],
  path: '/api/roles',
  label: 'Role',
  auditType: 'role',
  auditName: o => `${o.role} - ${o.company}`,
});

/* ---------- Placements and guarantee tracker ----------
   A placement is any Dashboard candidate at Start Date or later. The Placements
   tab only stores what the team edits (guarantee length, status, notes); the
   rest is derived from the live Dashboard rows so nothing is entered twice. */

const PLACEMENT_STAGES = ['start_date', 'day1', 'week1', 'month1'];
const DEFAULT_GUARANTEE_WEEKS = 12;

const placementsTable = makeSimpleTable({
  tab: 'Placements',
  header: ['id', 'guarantee_weeks', 'status', 'left_date', 'left_reason', 'notes'],
  path: null,
  label: 'Placement',
});

function placementKey(company, name, role) {
  return `${company}|${name}|${role}`.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function addDaysISO(iso, days) {
  const d = new Date(iso + 'T00:00:00Z');
  if (isNaN(d.getTime())) return '';
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

app.get('/api/placements', async (req, res) => {
  try {
    const dashRows = await readAllRows();
    const overrides = new Map((await placementsTable.list()).map(o => [o.id, o]));
    const today = new Date().toISOString().slice(0, 10);

    const data = dashRows
      .filter(r => r && r[0])
      .map(rowToCandidate)
      .filter(c => PLACEMENT_STAGES.includes(normStage(c.stage)))
      .map(c => {
        const id = placementKey(c.company, c.name, c.role);
        const o = overrides.get(id) || {};
        const weeks = parseInt(o.guarantee_weeks, 10) || DEFAULT_GUARANTEE_WEEKS;
        const startDate = /^\d{4}-\d{2}-\d{2}/.test(c.startDate || '') ? c.startDate.slice(0, 10) : '';
        const guaranteeEnd = startDate ? addDaysISO(startDate, weeks * 7) : '';
        const status = o.status || 'active';
        let daysLeft = null;
        if (guaranteeEnd) daysLeft = Math.round((new Date(guaranteeEnd + 'T00:00:00Z') - new Date(today + 'T00:00:00Z')) / 86400000);
        return {
          id, name: c.name, company: c.company, role: c.role, salary: c.salary,
          stage: normStage(c.stage), startDate, invoiceNumber: c.invoiceNumber || '',
          guaranteeWeeks: weeks, guaranteeEnd, daysLeft,
          status, leftDate: o.left_date || '', leftReason: o.left_reason || '', notes: o.notes || '',
        };
      })
      .sort((a, b) => String(b.startDate).localeCompare(String(a.startDate)));

    res.json({ data, defaultWeeks: DEFAULT_GUARANTEE_WEEKS });
  } catch (e) {
    console.error('GET /api/placements error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/placements/:id', async (req, res) => {
  try {
    const b = req.body || {};
    const allowed = ['active', 'completed', 'left'];
    const status = b.status && allowed.includes(b.status) ? b.status : 'active';
    const weeks = parseInt(b.guaranteeWeeks, 10);
    const saved = await placementsTable.upsert({
      id: req.params.id,
      guarantee_weeks: Number.isFinite(weeks) && weeks > 0 ? weeks : DEFAULT_GUARANTEE_WEEKS,
      status,
      left_date: status === 'left' ? (b.leftDate || new Date().toISOString().slice(0, 10)) : '',
      left_reason: status === 'left' ? (b.leftReason || '') : '',
      notes: b.notes || '',
    });
    auditLog(auditActorOf(req), 'placement_updated', 'placement', req.params.id, `${status}, ${saved.guarantee_weeks} weeks`);
    res.json({ ok: true, data: saved });
  } catch (e) {
    console.error('PUT /api/placements/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


/* ======================================================================
   Batch 2 additions: Interviews, Comms log, Email templates, Client feedback,
   Activity log (feeds Team performance) and talent pool tags.
   ====================================================================== */

const interviewsTable = makeSimpleTable({
  tab: 'Interviews',
  header: ['id', 'candidate_id', 'candidate_name', 'role', 'company', 'date', 'time', 'type', 'location', 'interviewer', 'status', 'notes', 'created_by', 'duration', 'candidate_email', 'interviewer_email', 'round_no', 'round_label', 'final'],
  path: '/api/interviews',
  label: 'Interview',
  auditType: 'interview',
  auditName: o => `${o.candidate_name} - ${o.date}`,
});

const commsTable = makeSimpleTable({
  tab: 'Comms Log',
  header: ['id', 'timestamp', 'user', 'entity_type', 'entity_name', 'company', 'role', 'channel', 'direction', 'summary', 'follow_up_date', 'follow_up_done'],
  path: '/api/comms',
  label: 'Contact',
});

const feedbackTable = makeSimpleTable({
  tab: 'Client Feedback',
  header: ['id', 'date', 'company', 'role', 'candidate_name', 'outcome', 'reason', 'detail', 'logged_by'],
  path: '/api/client-feedback',
  label: 'Feedback',
  auditType: 'client_feedback',
  auditName: o => `${o.candidate_name} - ${o.company}`,
});

const DEFAULT_TEMPLATES = [
  {
    "id": "tpl-interview-confirmation",
    "name": "Interview confirmation",
    "category": "Candidate",
    "subject": "Your Interview Confirmed - {{company}}, {{role}} - {{interview_date}}",
    "body": "Hi {{first_name}},\n\nGreat news - your interview with {{company}} has been confirmed. Please see the details below.\n\nInterview Details:\nDate: {{interview_date}}\nTime: {{interview_time}}\nLocation: {{interview_location}}\nFormat: {{interview_format}}\nYou will be meeting: {{interviewer}}\n\nImportant Information:\n- Please arrive 5-10 minutes early\n- I have attached your interview preparation pack - please read it in full before the day. It covers everything you need to know about the company, the interviewer, the likely questions, and how to structure your answers\n- If anything changes or you need to reschedule, please contact me immediately on {{sender_phone}} - do not leave it until the last minute\n- Bring a notepad and pen with you\n\nWe are confident you will make a strong impression. You have prepared well for this and you have earned this opportunity - go and show them what you are made of.\n\nIf you have any questions before your interview, please do not hesitate to get in touch.\n\nBest regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-offer-cover",
    "name": "Offer letter cover email",
    "category": "Candidate",
    "subject": "Your offer from {{company}} - {{role}}",
    "body": "Dear {{first_name}},\n\nWe are delighted to offer you the position of {{role}} at {{company}}.\n\nYour formal offer letter is attached. Please review the key details confirmed below:\n\nStart Date: {{start_date}}\nAnnual Salary: {{salary}}\nReporting To: {{contact_name}}\n\nNEXT STEPS\nPlease sign and return the attached offer letter by {{offer_return_date}}. Once we receive your signed acceptance, we will arrange the following:\n- Pre-start onboarding pack and site information\n- Confirmation of any compliance documentation needed (ID, references, proof of right to work)\n- First day briefing and induction overview\n\nIf you have any questions or need further information before your start date, please do not hesitate to reach out. I am here to help make this transition as smooth as possible for you.\n\nCongratulations again - we look forward to welcoming you to the team.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-information-request",
    "name": "Information request (after offer accepted)",
    "category": "Candidate",
    "subject": "Next Steps - A Few Things We Need From You",
    "body": "Hi {{first_name}},\n\nCongratulations again on accepting your offer - we are delighted for you and cannot wait to see you get started at {{company}}.\n\nTo make sure everything runs smoothly before your first day, we just need a few bits of information from you. This will not take long and will help us and {{company}} get everything in place ahead of your start.\n\nPlease respond to this email with the information below within 24 hours.\n\n1. YOUR DETAILS\n- Full legal name (as it appears on your passport or driving licence)\n- Home address (including postcode)\n- Personal email address\n- Personal mobile number\n- Emergency contact name, relationship, and phone number\n- Confirmed start date (we have noted {{start_date}} - please confirm this works for you)\n\n2. RIGHT TO WORK\nWe are required to confirm your Right to Work in the UK before your start date. Please provide one of the following:\n- A copy of your valid passport (photo page), or\n- A copy of your UK birth certificate and proof of National Insurance number, or\n- Your share code if you hold a Biometric Residence Permit or EU Settlement Scheme status\n\nYou can email a clear photo or scan to {{sender_email}}. This information is handled securely and in line with our Data Protection Policy.\n\n3. REFERENCES\nWe require two professional references before your start date. Please provide the details below for each referee. These should ideally be line managers or supervisors from your two most recent employers.\n\nReference 1\nFull Name:\nJob Title:\nCompany:\nRelationship to You:\nEmail Address:\nPhone Number:\n\nReference 2\nFull Name:\nJob Title:\nCompany:\nRelationship to You:\nEmail Address:\nPhone Number:\n\n4. ANYTHING ELSE WE SHOULD KNOW?\nIf there is anything you need us to be aware of before your start - for example, any reasonable adjustments, specific requirements for your first day, or anything that may affect your start date - please let us know here and we will make sure it is taken care of.\n\nThat is everything from us for now. Once we have received the above, we will be in touch with your pre-start onboarding information and details on what to expect before day one.\n\nIf you have any questions at all in the meantime, please do not hesitate to call or email me directly.\n\nBest regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-references-request",
    "name": "References request",
    "category": "Candidate",
    "subject": "Two References Needed - {{first_name}} for {{company}}",
    "body": "Hi {{first_name}},\n\nAs we move forward with your placement at {{company}}, we need to collect two professional references from you. This is a standard part of the recruitment process and will allow the company to gain additional insight into your professional background and work ethic.\n\nPlease provide the following information for two referees. These should ideally be line managers or supervisors from your two most recent employers.\n\nReference 1:\nFull Name:\nJob Title:\nCompany:\nRelationship to You:\nEmail Address:\nPhone Number:\n\nReference 2:\nFull Name:\nJob Title:\nCompany:\nRelationship to You:\nEmail Address:\nPhone Number:\n\nPlease reply to this email with the above details filled in. Once we receive them, we will contact your referees directly to seek their feedback before your start date.\n\nA Note on Confidentiality:\nWe handle all reference requests professionally and in confidence. Your referees will be contacted only with your permission and will be assured of discretion throughout the process.\n\nOne More Thing:\nAt Live 2 Help, we pride ourselves on working with talent acquisition at all levels across organisations. If you know of anyone else in your current or former teams who might be interested in exploring new opportunities - whether they are looking to move now or simply open to conversations - please do send their contact details our way. We work with businesses across the UK and are always keen to build relationships with individuals who are actively progressing their careers.\n\nPlease reply with your references at your earliest convenience.\n\nBest regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-start-reminder",
    "name": "Candidate start date reminder",
    "category": "Candidate",
    "subject": "Your first day at {{company}} - {{start_date}}",
    "body": "Dear {{first_name}},\n\nJust a few days to go! We wanted to confirm that your start date is {{start_date}} and you will be reporting to {{contact_name}} at {{company}}. Here is everything you need to know before Day One.\n\nARRIVAL DETAILS\nArrival Time: {{start_time}}\nWhere to Go: {{arrival_instructions}}\nWho to Ask For: {{contact_name}}\n\nPARKING AND TRANSPORT\n{{parking}}\n{{public_transport}}\n{{site_quirks}}\n\nWHAT TO BRING\n- Photo ID (driving licence or passport)\n- Proof of right to work if not already submitted\n- Any signed documentation previously sent to you\n\nDress Code: {{dress_code}}\n\nYOUR FIRST DAY\nYour induction will typically include a welcome from {{contact_name}}, a tour of the site, introductions to your immediate team, and an overview of key systems and processes. Allow a full day for onboarding - it will be busy but positive.\n\nA detailed Site Onboarding Pack is attached to this email. Please review it before you arrive - it covers everything specific to this location that you will want to know in advance.\n\nIF YOU ARE RUNNING LATE\nContact {{contact_name}} directly on {{late_contact_phone}}. Do not leave it until you are already late - a quick call goes a long way.\n\nWe are genuinely excited for you to start this next chapter. If you have any questions at all before then, you know where to find me.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-candidate-rejection",
    "name": "Candidate rejection",
    "category": "Candidate",
    "subject": "Your application for {{role}} at {{company}}",
    "body": "Dear {{first_name}},\n\nThank you for investing your time in the process and for the genuine effort you put into your preparation. It was a pleasure getting to know you and we appreciated the quality of your engagement throughout.\n\nWe wanted to let you know that we have decided to move forward with another candidate for this particular role. This was not a reflection of your capabilities - you demonstrated real strengths in [SPECIFIC STRENGTH], and we were genuinely impressed by [SPECIFIC EXAMPLE]. The decision came down to a very close match of specific experience within [DETAIL].\n\nWe would very much like to stay in touch. Your background in [SECTOR/SPECIALISM] puts you in a strong position for future opportunities, particularly in [RELEVANT AREA]. If your situation changes or you update your CV, please do let us know - we check profiles regularly and if something lands that fits, we will reach out directly.\n\nIf you would like to chat about next steps or explore other possibilities in your field, I am always happy to have that conversation. Please feel free to reach out at any time.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-client-submission",
    "name": "Client submission (candidate attached)",
    "category": "Client",
    "subject": "{{role}} - {{candidate_names}} for your review",
    "body": "Hi {{contact_first_name}},\n\nI have {{submission_intro}} for your {{role}} vacancy, attached for your review.\n\n{{candidate_summaries}}\n\nEach attachment includes the full submission and an anonymised CV.\n\nCould you let me know whether you would like to interview {{interview_target}}? If so, I will confirm availability straight away.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-client-placement",
    "name": "Client placement confirmation",
    "category": "Client",
    "subject": "Placement confirmed - {{candidate_name}} joining {{company}}",
    "body": "Dear {{contact_name}},\n\nWe are delighted to confirm that {{candidate_name}} will be joining {{company}} as {{role}}, commencing {{start_date}}.\n\nCANDIDATE PROFILE SNAPSHOT\n{{first_name}} brings [KEY STRENGTH 1] and [KEY STRENGTH 2] to this role. During the process, [he/she/they] demonstrated particular capability in [SPECIFIC EVIDENCE], which aligns directly with your team's requirements. [His/Her/Their] background in [RELEVANT AREA] positions [him/her/them] well for immediate impact on [SPECIFIC PROJECT OR RESPONSIBILITY].\n\nA full Candidate Handover Pack is attached, containing the candidate's full record, employment details, right to work confirmation and reference contacts for your records.\n\nINVOICE AND PAYMENT\nInvoice Reference: {{invoice_ref}}\nAmount Due: {{fee_amount}}\nPayment Terms: {{payment_terms}} from invoice date\n\nYour invoice will follow separately. Please direct any billing queries to office@live2helprecruitment.co.uk.\n\nPOST-PLACEMENT SUPPORT\nWe will be in touch for our standard post-placement check-ins at Week 1 and Month 1 to ensure everything is progressing well on both sides. If anything requires attention before then, please contact me directly and I will respond the same day.\n\nA MESSAGE FROM OUR TEAM\nIf you have had a positive experience working with Live 2 Help Recruitment, we would be really grateful if you could take two minutes to leave us a review. It makes a genuine difference to a growing business and helps other organisations understand what we do.\n\nLeave a review here: https://g.page/r/CU5L4ObMovbGEBM/review\n\nThank you for partnering with us on this placement. We hope {{first_name}} makes a real difference to your team and we look forward to supporting you on future hires.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-client-rejection",
    "name": "Client rejection (soft close)",
    "category": "Client",
    "subject": "{{candidate_name}} for {{role}} - thank you and next steps",
    "body": "Dear {{contact_name}},\n\nThank you for meeting with {{candidate_name}} for the {{role}} role and for the time you took to provide feedback throughout the process. We genuinely appreciate it.\n\nWe understand that you have decided to move forward with a different candidate on this occasion. We respect that decision entirely and appreciate you letting us know promptly.\n\n{{candidate_name}} was a strong submission and came very close. [He/She/They] demonstrated genuine capability in [AREA OF STRENGTH], and we were pleased with the quality of the conversation [he/she/they] had with your team. The decision ultimately reflected a very specific match of experience rather than any shortfall on the candidate's part.\n\nHOW WE MOVE FORWARD\nYour feedback is valuable and helps us sharpen the brief. If there are particular attributes, experience levels, or specific skills that would have made this a clear yes, even a brief conversation would allow us to recalibrate our search. Sometimes a small clarification changes everything in terms of who we target.\n\nWe are actively sourcing across [SECTOR/SPECIALISM] and have a strong read on the available talent market. Should the right profile become available, or should another opportunity open within your business that may suit {{first_name}}'s skillset, we will be in touch without delay.\n\nIn the meantime, please do not hesitate to reach out if you would like to discuss the brief further or if there is anything else we can do to support your recruitment plans.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-client-follow-up",
    "name": "Client follow-up after submission (starter)",
    "category": "Client",
    "subject": "Following up: {{candidate_name}} for {{role}}",
    "body": "Hi {{contact_name}},\n\nI hope you are well. I wanted to follow up on the profile I sent over for {{candidate_name}} for your {{role}} vacancy.\n\nHave you had a chance to review it? {{first_name}} is keen and available to speak at your convenience, so if you would like to move forward I can arrange an interview at a time that suits you.\n\nKind regards,\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-day-one",
    "name": "Day 1 welcome message (starter)",
    "category": "Candidate",
    "subject": "Good luck today at {{company}}",
    "body": "Hi {{first_name}},\n\nJust a quick message to wish you the very best on your first day as {{role}} at {{company}}. You have earned it.\n\nIf anything comes up today, call me any time.\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-week-one",
    "name": "Week 1 check-in (starter)",
    "category": "Candidate",
    "subject": "How was your first week?",
    "body": "Hi {{first_name}},\n\nHow was your first week at {{company}}? I would love to hear how you are settling in, and whether there is anything I can help with.\n\nI will give you a quick call to catch up.\n\n{{signature}}",
    "updated_by": "system"
  },
  {
    "id": "tpl-month-one",
    "name": "Month 1 check-in (starter)",
    "category": "Candidate",
    "subject": "One month in",
    "body": "Hi {{first_name}},\n\nYou have now been at {{company}} for a month. How are things going with the {{role}} role, and does it feel like the right fit?\n\nI will also check in with {{contact_name}} to make sure everything is going well from their side.\n\n{{signature}}",
    "updated_by": "system"
  }
];

let tplMigrated = false;
async function migrateTemplates() {
  if (tplMigrated) return;
  const all = await templatesTable.listAll();
  if (all.some(t => t.id === '__templates_v4')) { tplMigrated = true; return; }
  for (const d of DEFAULT_TEMPLATES) {
    const ex = all.find(t => t.id === d.id);
    if (!ex || ex.updated_by === 'system') await templatesTable.upsert(d);
  }
  for (const oldId of ['tpl-offer']) {
    const ex = all.find(t => t.id === oldId);
    if (ex && ex.updated_by === 'system') await templatesTable.remove(oldId);
  }
  await templatesTable.upsert({ id: '__templates_v4', name: 'migration marker', category: '', subject: '', body: '', updated_by: 'system' });
  tplMigrated = true;
}

const templatesTable = makeSimpleTable({
  tab: 'Templates',
  header: ['id', 'name', 'category', 'subject', 'body', 'updated_by'],
  path: '/api/templates',
  label: 'Template',
  beforeList: migrateTemplates,
  auditType: 'template',
  auditName: o => o.name,
});

const activityTable = makeSimpleTable({
  tab: 'Activity',
  header: ['id', 'timestamp', 'user', 'action', 'candidate', 'role', 'company', 'detail'],
  path: null,
  label: 'Activity',
});

app.get('/api/activity', requireAdmin, async (req, res) => {
  try {
    const since = String(req.query.since || '');
    let rows = await activityTable.list();
    if (since) rows = rows.filter(r => String(r.timestamp) >= since);
    res.json({ data: rows });
  } catch (e) {
    console.error('GET /api/activity error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/activity', async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.action || !b.user) return res.status(400).json({ error: 'user and action are required' });
    const entry = {
      id: b.id || `act-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: b.timestamp || new Date().toISOString(),
      user: String(b.user).toLowerCase(),
      action: b.action,
      candidate: b.candidate || '',
      role: b.role || '',
      company: b.company || '',
      detail: String(b.detail || '').slice(0, 300),
    };
    await activityTable.append(entry);
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/activity error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Talent pool tags (comma separated, stored on the Candidate Pool row)
app.put('/api/candidate-pool/:id/tags', async (req, res) => {
  try {
    const tags = String((req.body || {}).tags || '')
      .split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      .filter((t, i, a) => a.indexOf(t) === i).slice(0, 20).join(', ');
    const row = await patchPoolRow(req.params.id, { 15: tags });
    if (!row) return res.status(404).json({ error: 'Pool record not found' });
    res.json({ ok: true, data: rowToPoolEntry(row) });
  } catch (e) {
    console.error('PUT /api/candidate-pool/:id/tags error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


/* ======================================================================
   Batch 3 additions: Audit trail, GDPR (consent, retention, export, erase),
   Sourcing spend, Referrals, pool source/consent fields.
   ====================================================================== */

const auditTable = makeSimpleTable({
  tab: 'Audit Log',
  header: ['id', 'timestamp', 'user', 'action', 'entity_type', 'entity', 'detail'],
  path: null,
  label: 'Audit',
});

function auditLog(actor, action, entityType, entity, detail) {
  try {
    const entry = {
      id: `aud-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      user: String(actor || 'unknown').toLowerCase(),
      action,
      entity_type: entityType || '',
      entity: String(entity || '').slice(0, 200),
      detail: String(detail || '').slice(0, 300),
    };
    auditTable.append(entry).catch(e => console.error('Audit write failed:', e.message));
  } catch (e) {
    console.error('Audit error:', e.message);
  }
}

function auditOnFinish(req, res, build) {
  res.on('finish', () => {
    if (res.statusCode >= 400) return;
    try {
      const a = build();
      if (a) auditLog(auditActorOf(req), a.action, a.type, a.entity, a.detail || '');
    } catch (e) { /* audit is best effort */ }
  });
}

async function snapshotCandidate(c) {
  try {
    if (!c || !c.name || !c.role) return null;
    if (c.sourceTab === 'application') {
      const sheets = getSheetsClient();
      const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'Applications - ${c.formRole || c.role}'!A2:U` });
      const row = (r.data.values || []).find(x => String(x[2] || '').trim().toLowerCase() === String(c.name).trim().toLowerCase());
      if (!row) return null;
      return { stage: row[19] || 'applied', notes: row[20] || '', salary: row[15] || '', company: row[17] || '' };
    }
    const rows = await readAllRows();
    const r = rows.find(x => x && x[0] === c.id);
    if (!r) return null;
    const o = rowToCandidate(r);
    return { stage: o.stage, notes: o.notes, salary: o.salary, company: o.company };
  } catch (e) {
    return null;
  }
}

function auditCandidateChange(req, c, before) {
  const who = actorOf(req);
  const label = `${c.name} - ${c.role}`;
  if (!before) { auditLog(who, 'candidate_created', 'candidate', label, `stage ${c.stage || 'submitted'}`); if (c.stage) stageAutomation(c, c.stage); return; }
  if (c.stage && normStage(c.stage) !== normStage(before.stage)) {
    auditLog(who, 'stage_changed', 'candidate', label, `${before.stage} to ${c.stage}`);
    stageAutomation(c, c.stage);
  }
  if (c.notes !== undefined && String(c.notes) !== String(before.notes)) {
    auditLog(who, 'notes_edited', 'candidate', label, String(c.notes).slice(0, 120));
  }
  if (c.salary !== undefined && String(c.salary) !== String(before.salary)) {
    auditLog(who, 'salary_changed', 'candidate', label, `${before.salary || 'blank'} to ${c.salary || 'blank'}`);
  }
  if (c.company !== undefined && String(c.company) !== String(before.company)) {
    auditLog(who, 'company_assigned', 'candidate', label, `${before.company || 'none'} to ${c.company || 'none'}`);
  }
}

app.get('/api/audit', requireAdmin, async (req, res) => {
  try {
    let rows = await auditTable.list();
    const since = String(req.query.since || '');
    if (since) rows = rows.filter(r => String(r.timestamp) >= since);
    rows.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
    res.json({ data: rows.slice(0, Math.min(parseInt(req.query.limit, 10) || 500, 2000)) });
  } catch (e) {
    console.error('GET /api/audit error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


makeSimpleTable({
  tab: 'Site Details',
  header: ['id', 'company', 'arrival_instructions', 'parking', 'public_transport', 'site_quirks', 'dress_code', 'late_contact_phone', 'security_reception', 'updated_by'],
  path: '/api/site-details',
  label: 'Site details',
  auditType: 'site_details',
  auditName: o => o.company,
});

const candidateDetailsTable = makeSimpleTable({
  tab: 'Candidate Details',
  header: ['id', 'candidate_name', 'role', 'company', 'start_time', 'reporting_to', 'updated_by'],
  path: '/api/candidate-details',
  label: 'Candidate details',
});

const settingsTable = makeSimpleTable({
  tab: 'Settings',
  header: ['id', 'value', 'updated_by'],
  path: '/api/settings',
  label: 'Setting',
  guard: requireAdmin,
  auditType: 'setting',
  auditName: o => `${o.id} = ${o.value}`,
});

let formConsentCache = { v: false, t: 0 };
async function formConsentOn() {
  if (Date.now() - formConsentCache.t < 60000) return formConsentCache.v;
  try {
    const all = await settingsTable.list();
    formConsentCache = { v: (all.find(x => x.id === 'form_consent') || {}).value === 'yes', t: Date.now() };
  } catch (e) { formConsentCache.t = Date.now(); }
  return formConsentCache.v;
}

// Per-person activity counts. Admin sees everyone, everyone else sees only themselves.
app.get('/api/activity/summary', async (req, res) => {
  try {
    const since = String(req.query.since || '');
    let rows = await activityTable.list();
    if (since) rows = rows.filter(r => String(r.timestamp) >= since);
    const me = actorOf(req);
    const users = {};
    rows.forEach(r => {
      const u = String(r.user || '').toLowerCase();
      if (!isAdmin(req) && u !== me) return;
      users[u] = users[u] || {};
      users[u][r.action] = (users[u][r.action] || 0) + 1;
    });
    res.json({ users });
  } catch (e) {
    console.error('GET /api/activity/summary error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ---------- Sourcing spend and referrals ---------- */

makeSimpleTable({
  tab: 'Ad Spend',
  header: ['id', 'date', 'channel', 'role', 'company', 'amount', 'notes', 'logged_by', 'frequency', 'end_date', 'applies_to'],
  path: '/api/ad-spend',
  label: 'Spend entry',
  guard: requireAdmin,
  auditType: 'ad_spend',
  auditName: o => `${o.channel} - ${o.amount}`,
});

makeSimpleTable({
  tab: 'Referrals',
  header: ['id', 'date', 'type', 'referred_name', 'referred_company', 'referrer_name', 'referrer_type', 'role', 'status', 'reward_amount', 'reward_status', 'reward_paid_date', 'notes', 'created_by'],
  path: '/api/referrals',
  label: 'Referral',
  auditType: 'referral',
  auditName: o => `${o.referred_name} referred by ${o.referrer_name}`,
});

/* ---------- GDPR: consent, retention review, export and erase ---------- */

function addMonthsISO(iso, months) {
  const d = new Date(String(iso || '').slice(0, 10) + 'T00:00:00Z');
  if (isNaN(d.getTime())) return '';
  d.setUTCMonth(d.getUTCMonth() + months);
  return d.toISOString().slice(0, 10);
}

function nameVariantSet(name) {
  const n = String(name || '').trim().toLowerCase().replace(/\s+/g, ' ');
  return new Set(n ? [n] : []);
}

const POOL_META_FIELDS = { source: 16, consentDate: 17, consentBasis: 18, reviewDate: 19 };

app.put('/api/candidate-pool/:id/meta', async (req, res) => {
  try {
    const b = req.body || {};
    const patch = {};
    if (b.source !== undefined) patch[POOL_META_FIELDS.source] = String(b.source).slice(0, 60);
    if (b.consentDate !== undefined) patch[POOL_META_FIELDS.consentDate] = /^\d{4}-\d{2}-\d{2}$/.test(b.consentDate) ? b.consentDate : '';
    if (b.consentBasis !== undefined) patch[POOL_META_FIELDS.consentBasis] = String(b.consentBasis).slice(0, 80);
    if (b.reviewDate !== undefined) patch[POOL_META_FIELDS.reviewDate] = /^\d{4}-\d{2}-\d{2}$/.test(b.reviewDate) ? b.reviewDate : '';
    if (b.extendReview) patch[POOL_META_FIELDS.reviewDate] = addMonthsISO(new Date().toISOString().slice(0, 10), RETENTION_MONTHS);
    const row = await patchPoolRow(req.params.id, patch);
    if (!row) return res.status(404).json({ error: 'Pool record not found' });
    const entry = rowToPoolEntry(row);
    if (b.extendReview) auditLog(auditActorOf(req), 'retention_extended', 'pool', `${entry.name} - ${entry.role}`, `review ${entry.reviewDate}`);
    else if (b.consentDate !== undefined || b.consentBasis !== undefined) auditLog(auditActorOf(req), 'consent_recorded', 'pool', `${entry.name} - ${entry.role}`, entry.consentBasis);
    res.json({ ok: true, data: entry });
  } catch (e) {
    console.error('PUT /api/candidate-pool/:id/meta error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/gdpr/bulk-consent', requireAdmin, async (req, res) => {
  try {
    const basis = String((req.body || {}).basis || 'Application form').slice(0, 80);
    const rows = await readPoolRows();
    const sheets = getSheetsClient();
    const data = [];
    rows.forEach((raw, i) => {
      const r = padPoolRow(raw);
      if (!r[0] || r[20] || r[17]) return;
      r[17] = (r[8] || new Date().toISOString()).slice(0, 10);
      r[18] = basis;
      data.push({ range: `'${POOL_TAB}'!A${i + 2}:${POOL_LAST_COL}${i + 2}`, values: [r] });
    });
    if (data.length) await sheets.spreadsheets.values.batchUpdate({ spreadsheetId: SHEET_ID, requestBody: { valueInputOption: 'RAW', data } });
    auditLog(auditActorOf(req), 'bulk_consent_recorded', 'pool', `${data.length} candidates`, basis);
    res.json({ ok: true, updated: data.length });
  } catch (e) {
    console.error('POST /api/gdpr/bulk-consent error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/gdpr/export/:id', requireAdmin, async (req, res) => {
  try {
    const found = await findPoolRowById(req.params.id);
    if (!found) return res.status(404).json({ error: 'Pool record not found' });
    const row = found.row;
    if (row[20]) return res.status(400).json({ error: 'This record has already been erased' });
    const name = row[1];
    const variants = nameVariantSet(name);
    const match = v => variants.has(String(v || '').trim().toLowerCase());
    const entry = rowToPoolEntry(row);

    let application = null;
    try {
      const sheets = getSheetsClient();
      const formTab = await formRoleFor(name, row[5]);
      const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'Applications - ${formTab}'!A2:AJ` });
      const ar = (r.data.values || []).find(x => match(x[2]));
      if (ar) {
        application = {};
        const smFields = await getScreeningFieldsForRole(formTab);
        (smFields || SCREENING_FORM_FIELDS).forEach(f => { application[f.label] = ar[f.col] || ''; });
        application['Company'] = ar[17] || '';
        application['Status'] = ar[19] || '';
        application['Notes'] = ar[20] || '';
      }
    } catch (e) { /* no application tab for this role */ }

    const dash = (await readAllRows()).filter(r => r && r[0]).map(rowToCandidate).filter(c => match(c.name) && c.role === row[5]);
    const [ivs, cms, fbs, acts] = await Promise.all([
      interviewsTable.list(), commsTable.list(), feedbackTable.list(), activityTable.list(),
    ]);

    const bundle = {
      exportedAt: new Date().toISOString(),
      exportedBy: actorOf(req),
      candidate: entry.name,
      poolRecord: { ...entry, cvLink: row[13] || '' },
      application,
      pipelineRecords: dash,
      interviews: ivs.filter(i => match(i.candidate_name)),
      contactLog: cms.filter(c => match(c.entity_name)),
      clientFeedback: fbs.filter(f => match(f.candidate_name)),
      candidateDetails: (await candidateDetailsTable.list()).filter(d => match(d.candidate_name)),
      activity: acts.filter(a => match(a.candidate)),
    };
    auditLog(auditActorOf(req), 'data_exported', 'pool', `${entry.name} - ${entry.role}`, '');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(bundle, null, 2));
  } catch (e) {
    console.error('GET /api/gdpr/export error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

async function deleteApplicationRows(role, variants) {
  const sheets = getSheetsClient();
  let formTab = role;
  for (const v of variants) { const x = await formRoleFor(v, role); if (x !== role) { formTab = x; break; } }
  await purgeApplicantRoles(variants);
  const ss = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties(sheetId,title)' });
  const tab = (ss.data.sheets || []).find(s => s.properties.title === `Applications - ${formTab}`);
  if (!tab) return 0;
  const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tab.properties.title}'!A2:U` });
  const idx = [];
  (r.data.values || []).forEach((row, i) => { if (variants.has(String(row[2] || '').trim().toLowerCase())) idx.push(i); });
  if (!idx.length) return 0;
  const requests = idx.sort((a, b) => b - a).map(i => ({
    deleteDimension: { range: { sheetId: tab.properties.sheetId, dimension: 'ROWS', startIndex: i + 1, endIndex: i + 2 } },
  }));
  await sheets.spreadsheets.batchUpdate({ spreadsheetId: SHEET_ID, requestBody: { requests } });
  return idx.length;
}

app.post('/api/gdpr/erase/:id', requireAdmin, async (req, res) => {
  try {
    const found = await findPoolRowById(req.params.id);
    if (!found) return res.status(404).json({ error: 'Pool record not found' });
    const row = found.row;
    if (row[20]) return res.status(400).json({ error: 'Already erased' });
    if (String((req.body || {}).confirm || '') !== 'ERASE') return res.status(400).json({ error: 'Type ERASE to confirm' });

    const name = row[1], role = row[5], company = row[4];
    const variants = nameVariantSet(name);
    const match = v => variants.has(String(v || '').trim().toLowerCase());
    const cleared = { cv: 0, application: 0, pipeline: 0, interviews: 0, contactLog: 0, feedback: 0, activity: 0, audit: 0 };

    // CV files in Drive
    try {
      const drive = getDriveClient();
      const ids = new Set();
      if (row[11]) ids.add(row[11]);
      const legacy = await findLegacyCv(company, name).catch(() => null);
      if (legacy && legacy.fileId) ids.add(legacy.fileId);
      for (const fileId of ids) {
        await drive.files.update({ fileId, requestBody: { trashed: true } });
        cleared.cv++;
      }
    } catch (e) { console.error('Erase: CV removal failed:', e.message); }

    // Application form row and pipeline row
    try { cleared.application = await deleteApplicationRows(role, variants); } catch (e) { console.error('Erase: application rows:', e.message); }
    try {
      const sheets = getSheetsClient();
      const dashRows = await readAllRows();
      for (let i = 0; i < dashRows.length; i++) {
        const r = dashRows[i];
        if (!r || !r[0]) continue;
        const c = rowToCandidate(r);
        if (match(c.name) && c.role === role) {
          await sheets.spreadsheets.values.clear({ spreadsheetId: SHEET_ID, range: `${TAB}!A${i + 2}:L${i + 2}` });
          cleared.pipeline++;
        }
      }
    } catch (e) { console.error('Erase: pipeline rows:', e.message); }

    // Scrub the other tables so the person cannot be identified
    const ERASED = 'Erased candidate';
    cleared.interviews = await interviewsTable.updateWhere(o => match(o.candidate_name), o => ({ ...o, candidate_name: ERASED, candidate_email: '', notes: '' }));
    cleared.contactLog = await commsTable.updateWhere(o => match(o.entity_name), o => ({ ...o, entity_name: ERASED, summary: '[erased]' }));
    await candidateDetailsTable.updateWhere(o => match(o.candidate_name), o => ({ ...o, candidate_name: ERASED, start_time: '', reporting_to: '' }));
    await submissionDraftsTable.updateWhere(o => match(o.candidate_name), o => ({ ...o, candidate_name: ERASED, call_notes: '', submission_json: '', cv_json: '', contact_email: '' }));
    cleared.feedback = await feedbackTable.updateWhere(o => match(o.candidate_name), o => ({ ...o, candidate_name: ERASED, detail: '' }));
    cleared.activity = await activityTable.updateWhere(o => match(o.candidate), o => ({ ...o, candidate: ERASED, detail: '' }));
    cleared.audit = await auditTable.updateWhere(
      o => [...variants].some(v => String(o.entity || '').toLowerCase().includes(v)) || [...variants].some(v => String(o.detail || '').toLowerCase().includes(v)),
      o => ({ ...o, entity: ERASED, detail: '' })
    );

    // CV search profile and AI match scores for this person (every pool row under their name)
    try {
      const ids = (await readPoolRows()).filter(r => r && r[0] && match(r[1])).map(r => r[0]);
      ids.push(req.params.id);
      cleared.matchData = await purgeMatchData([...new Set(ids)]);
    } catch (e) { console.error('Erase: match data:', e.message); }

    // Pool tombstone: keeps role, company, stage and source for statistics only
    const tomb = padPoolRow(row);
    const tombId = `erased-${crypto.randomBytes(5).toString('hex')}`;
    tomb[0] = tombId; tomb[1] = ERASED; tomb[2] = ''; tomb[3] = ''; tomb[10] = '';
    tomb[11] = ''; tomb[12] = ''; tomb[13] = ''; tomb[14] = 'No'; tomb[15] = '';
    tomb[17] = ''; tomb[18] = ''; tomb[19] = '';
    tomb[20] = new Date().toISOString().slice(0, 10);
    tomb[9] = new Date().toISOString();
    await withPoolLock(async () => {
      const sheets = getSheetsClient();
      const rows = await readPoolRows();
      const idx = rows.findIndex(r => r && r[0] === req.params.id);
      if (idx === -1) return;
      const n = idx + 2;
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID, range: `'${POOL_TAB}'!A${n}:${POOL_LAST_COL}${n}`,
        valueInputOption: 'RAW', requestBody: { values: [tomb] },
      });
    });

    auditLog(auditActorOf(req), 'candidate_erased', 'pool', `Erased candidate (ref ${tombId})`, `role ${role}`);
    res.json({
      ok: true, cleared,
      manual: [
        'Submission pack documents saved in Drive under the candidate name are not removed automatically - delete those files by hand.',
        'Anything held outside this dashboard (email, Wispr transcripts, the Google Forms response sheet if separate) also needs removing by hand.',
      ],
    });
  } catch (e) {
    console.error('POST /api/gdpr/erase error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


/* ======================================================================
   Automated candidate submissions

   Flow: Applied -> Ready to submit -> AI draft (submission + anonymised CV)
   -> Ella reviews and approves -> client email built as an .eml with the
   attachments -> Ella confirms it was sent -> card moves to Submitted.

   Needs one extra npm dependency for the Word files: "docx".
   The API key stays on this server (ANTHROPIC_API_KEY). Nothing here ever
   sends an email - it only prepares drafts for a person to review and send.
   ====================================================================== */

const SUBMISSION_MODEL = process.env.SUBMISSION_MODEL || 'claude-sonnet-4-6';
const SUBMISSION_CONTACT_LINE = 'dan.brown@live2helprecruitment.co.uk  |  07424 087576  |  www.live2helprecruitment.co.uk';
const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

const submissionDraftsTable = makeSimpleTable({
  tab: 'Submission Drafts',
  header: [
    'id', 'candidate_id', 'candidate_name', 'role', 'company', 'status', 'call_notes',
    'submission_json', 'cv_json', 'contact_name', 'contact_email', 'batch_id',
    'created_by', 'created_at', 'approved_at', 'sent_at',
  ],
  path: null,
  label: 'Submission draft',
});

// One brief per role title: the job description and key requirements every candidate
// submission for that role is matched against. Entered once, used by every candidate.
function briefIdFor(role) {
  return String(role || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

const roleBriefsTable = makeSimpleTable({
  tab: 'Role Briefs',
  header: ['id', 'role', 'requirements', 'job_description', 'updated_by', 'updated_at'],
  path: '/api/role-briefs',
  label: 'Role brief',
  auditType: 'role_brief',
  auditName: o => o.role,
});

async function loadRoleBrief(role) {
  const id = briefIdFor(role);
  let brief = null;
  try { brief = (await roleBriefsTable.list()).find(b => b.id === id) || null; } catch (e) { /* fall through */ }
  let requirements = brief ? String(brief.requirements || '').trim() : '';
  const jobDescription = brief ? String(brief.job_description || '').trim() : '';
  if (!requirements && !jobDescription) {
    // Older builds kept requirements on the Roles tab, so still honour those
    try {
      const legacy = (await rolesTable.list()).find(r => briefIdFor(r.role) === id && String(r.requirements || '').trim());
      if (legacy) requirements = String(legacy.requirements).trim();
    } catch (e) { /* no legacy record */ }
  }
  return { requirements, jobDescription };
}

const DRAFT_STATUSES = ['draft', 'approved', 'email_built', 'sent'];
const SHEET_CELL_LIMIT = 45000;

// ---- Text helpers --------------------------------------------------------

// No em dashes or en dashes anywhere in generated documents
function cleanDashes(s) {
  return String(s == null ? '' : s)
    .replace(/[ \t]*\u2014[ \t]*/g, ' - ')
    .replace(/[ \t]*\u2015[ \t]*/g, ' - ')
    .replace(/[ \t]*\u2013[ \t]*/g, m => (/[ \t]/.test(m) ? ' - ' : '-'));
}

function cleanDeep(v) {
  if (typeof v === 'string') return cleanDashes(v);
  if (Array.isArray(v)) return v.map(cleanDeep);
  if (v && typeof v === 'object') {
    const o = {};
    Object.keys(v).forEach(k => { o[k] = cleanDeep(v[k]); });
    return o;
  }
  return v;
}

function candidateRef(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return 'Candidate';
  if (parts.length === 1) return parts[0];
  return `${parts[0]} ${parts[parts.length - 1][0].toUpperCase()}`;
}

function safeFileName(s) {
  return String(s || '').replace(/[\\/:*?"<>|]+/g, ' ').replace(/\s+/g, ' ').trim();
}

function submissionFileNames(name, role) {
  const ref = candidateRef(name);
  const r = safeFileName(role);
  return {
    submission: safeFileName(`Candidate Submission ${ref} ${r}`) + '.docx',
    cv: safeFileName(`Anonymised CV ${ref} ${r}`) + '.docx',
  };
}

// Mini markup used inside body fields so drafts are easy to edit:
//   plain line = paragraph, "- " = bullet, "## " = sub-heading, **text** = bold
function parseMarkup(text) {
  const blocks = [];
  String(text || '').split(/\r?\n/).forEach(raw => {
    const line = raw.trim();
    if (!line) return;
    if (/^##\s+/.test(line)) blocks.push({ type: 'sub', text: line.replace(/^##\s+/, '') });
    else if (/^[-*\u2022]\s+/.test(line)) blocks.push({ type: 'bullet', text: line.replace(/^[-*\u2022]\s+/, '') });
    else blocks.push({ type: 'p', text: line });
  });
  return blocks;
}

function splitBold(text) {
  const out = [];
  String(text || '').split(/(\*\*[^*]+\*\*)/g).forEach(part => {
    if (!part) return;
    if (/^\*\*[^*]+\*\*$/.test(part)) out.push({ text: part.slice(2, -2), bold: true });
    else out.push({ text: part.replace(/\*\*/g, ''), bold: false });
  });
  return out;
}

// Safety net: strip contact details and the candidate's full name from generated text.
// Lone name words are only flagged (never auto-removed) because a surname can also be an
// ordinary word such as "Price" or "Cook".
function scrubIdentifiers(value, { fullName, keepFirstName, emails, phones }) {
  const found = new Set();
  const check = new Set();
  const tokens = String(fullName || '').trim().split(/\s+/).filter(Boolean);
  const first = tokens[0] || '';
  const last = tokens.length > 1 ? tokens[tokens.length - 1] : '';
  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const phrases = [];
  if (tokens.length > 1) {
    phrases.push(tokens.map(escapeRe).join('\\s+'));
    if (tokens.length > 2) phrases.push(`${escapeRe(first)}\\s+${escapeRe(last)}`);
  }
  const replacement = keepFirstName && first ? `${first} ${last.charAt(0).toUpperCase()}` : 'the candidate';
  const scrub = str => {
    let s = String(str);
    s = s.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, () => { found.add('email address'); return '[removed]'; });
    s = s.replace(/(?:\+44\s?\(?0?\)?|\b0)\s?\d[\d\s()-]{8,}\d/g, () => { found.add('phone number'); return '[removed]'; });
    s = s.replace(/(?:https?:\/\/)?(?:www\.)?linkedin\.com\/[^\s)]*/gi, () => { found.add('LinkedIn link'); return '[removed]'; });
    (emails || []).filter(Boolean).forEach(e => {
      s = s.replace(new RegExp(escapeRe(e), 'gi'), () => { found.add('email address'); return '[removed]'; });
    });
    (phones || []).map(p => String(p || '').replace(/\D/g, '')).filter(p => p.length >= 9).forEach(p => {
      const loose = p.split('').join('\\s*');
      s = s.replace(new RegExp(loose, 'g'), () => { found.add('phone number'); return '[removed]'; });
    });
    phrases.forEach(ph => {
      s = s.replace(new RegExp(`\\b${ph}\\b`, 'gi'), () => { found.add('candidate name'); return replacement; });
    });
    const lone = [];
    if (last && last.length >= 3) lone.push(last);
    if (!keepFirstName && first && first.length >= 3) lone.push(first);
    lone.forEach(tok => {
      if (new RegExp(`\\b(?:${escapeRe(tok)}|${escapeRe(tok.toUpperCase())})\\b`).test(s)) check.add(tok);
    });
    return s;
  };
  const walk = v => {
    if (typeof v === 'string') return scrub(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = {};
      Object.keys(v).forEach(k => { o[k] = walk(v[k]); });
      return o;
    }
    return v;
  };
  return { value: walk(value), found: [...found], check: [...check] };
}

// ---- Reading CV files ----------------------------------------------------

function readZipEntry(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const total = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < total; n++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    if (name === wanted) {
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      const start = localOff + 30 + lNameLen + lExtraLen;
      const data = buf.subarray(start, start + compSize);
      return method === 0 ? Buffer.from(data) : zlib.inflateRawSync(data);
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

function xmlDecode(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

function docxToText(buf) {
  const xml = readZipEntry(buf, 'word/document.xml');
  if (!xml) throw new Error('This Word file could not be read. Ask for a PDF version of the CV.');
  let s = xml.toString('utf8');
  s = s.replace(/<w:tab\/>/g, '\t').replace(/<w:br[^>]*\/>/g, '\n')
    .replace(/<\/w:p>/g, '\n').replace(/<\/w:tc>/g, ' | ')
    .replace(/<[^>]+>/g, '');
  return xmlDecode(s).replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

async function findCvInfo(company, name, role) {
  let info = null;
  try {
    const found = await findPoolRowById(poolIdFor(name, role));
    if (found && found.row[11]) info = { fileId: found.row[11], fileName: found.row[12] || '' };
  } catch (e) { /* fall through to the folder search */ }
  if (!info) {
    const legacy = await findLegacyCv(company, name).catch(() => null);
    if (legacy && legacy.fileId) info = { fileId: legacy.fileId, fileName: legacy.fileName || '' };
  }
  return info;
}

function cvKind(fileName, mime) {
  const n = String(fileName || '').toLowerCase();
  if (n.endsWith('.pdf') || mime === 'application/pdf') return 'pdf';
  if (n.endsWith('.docx') || mime === DOCX_MIME) return 'docx';
  if (mime === 'application/vnd.google-apps.document') return 'gdoc';
  if (n.endsWith('.doc') || mime === 'application/msword') return 'doc';
  return 'other';
}

async function loadCvFile(company, name, role) {
  const info = await findCvInfo(company, name, role);
  if (!info) return null;
  const drive = getDriveClient();
  const meta = await drive.files.get({ fileId: info.fileId, fields: 'name, mimeType, size' });
  const fileName = meta.data.name || info.fileName || 'CV';
  const mime = meta.data.mimeType || '';
  const kind = cvKind(fileName, mime);
  return { fileId: info.fileId, fileName, mime, kind, size: Number(meta.data.size || 0) };
}

async function downloadCv(file) {
  const drive = getDriveClient();
  if (file.kind === 'gdoc') {
    const r = await drive.files.export({ fileId: file.fileId, mimeType: 'application/pdf' }, { responseType: 'arraybuffer' });
    return { buffer: Buffer.from(r.data), kind: 'pdf' };
  }
  const r = await drive.files.get({ fileId: file.fileId, alt: 'media' }, { responseType: 'arraybuffer' });
  return { buffer: Buffer.from(r.data), kind: file.kind };
}

// ---- Reading the screening answers --------------------------------------

async function loadScreening(name, role) {
  const sheets = getSheetsClient();
  const tabName = `Applications - ${await formRoleFor(name, role)}`;
  let all;
  try {
    const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tabName}'!A1:AJ` });
    all = r.data.values || [];
  } catch (e) {
    return { found: false, qa: [], reason: `No application form tab for ${role}` };
  }
  const header = all[0] || [];
  const rows = all.slice(1);
  const norm = s => String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const target = norm(name);
  let row = rows.find(r => norm(r[2]) === target);
  if (!row) {
    const parts = target.split(' ');
    if (parts.length >= 2) {
      const first = parts[0], initial = parts[parts.length - 1].charAt(0);
      row = rows.find(r => {
        const p = norm(r[2]).split(' ');
        return p[0] === first && p.length >= 2 && p[p.length - 1].charAt(0) === initial;
      });
    }
  }
  if (!row) return { found: false, qa: [], reason: 'No matching application form answers' };
  const qa = [];
  const qaCols = [];
  for (let i = 5; i <= 16; i++) qaCols.push(i);
  for (let i = 26; i < header.length; i++) qaCols.push(i); // overflow questions (Sales Manager forms)
  for (const i of qaCols) {
    const a = String(row[i] || '').trim();
    if (!a) continue;
    qa.push({ question: String(header[i] || `Question ${i - 4}`).trim(), answer: a });
  }
  return {
    found: true, qa, fullName: row[2] || name,
    email: row[3] || '', phone: row[4] || '', recruiterNotes: String(row[20] || '').trim(),
  };
}

// ---- Calling the model ---------------------------------------------------

async function callClaudeTool({ system, content, tool, maxTokens, model }) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: model || SUBMISSION_MODEL,
      max_tokens: maxTokens,
      temperature: 0.2,
      system,
      tools: [tool],
      tool_choice: { type: 'tool', name: tool.name },
      messages: [{ role: 'user', content }],
    }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error((data.error && data.error.message) || `AI service returned ${resp.status}`);
  if (data.stop_reason === 'max_tokens') throw new Error('The draft was cut off before it finished. Try again.');
  const block = (data.content || []).find(b => b.type === 'tool_use');
  if (!block || !block.input) throw new Error('The AI did not return a draft. Try again.');
  return block.input;
}

const MARKUP_HELP =
  'Body text uses a simple markup: each plain line is a paragraph; a line starting with "- " is a bullet point; ' +
  'a line starting with "## " is a bold sub-heading; **double asterisks** make text bold. Put each item on its own line.';

const SUBMISSION_SYSTEM = `You write client-facing candidate submissions for Live 2 Help Recruitment, a UK recruitment agency. The reader is a hiring manager deciding whether to interview.

HOUSE RULES
- British English. Confident and professional, persuasive without overselling. Be specific, never generic.
- Use ONLY facts in the material supplied (CV, screening answers, recruiter call notes). Never invent or assume employers, dates, figures, qualifications, salary, notice periods, availability or motivations.
- If something a client would expect is missing, write "To be confirmed" in that field and add a plain-English line to "gaps" so the recruiter can fill it in before sending.
- Read the screening answers precisely. Notice period, salary, employment status, location and any option ticked must be reproduced exactly as given. If the CV and the screening answers disagree, use the screening answers and note the difference in "gaps".
- Never mention a screener, form, questionnaire or "screening answers". Where that information is used, phrase it as coming from discussion with the candidate, for example "In discussion, Sam confirmed he is expert level in Excel".
- Call the candidate by first name in prose. In "candidate_ref" and details use first name plus surname initial only (for example "Yihsin C"). Never output a surname, email address, phone number or street address.
- Never include interview areas to explore, questions to ask, weaknesses, or anything that gives away unconfirmed details or the candidate's negotiating position.
- Never use em dashes or en dashes. Use a plain hyphen with spaces (" - ") for a break in a sentence and a plain hyphen in date ranges (for example "Nov 2022-Present").
- Match the candidate's evidence directly to the role's stated requirements. Strongest match first. Name the systems, figures, employers and outcomes given in the material.
- ${MARKUP_HELP}

STRUCTURE (mirror the agency's standard submission)
1. details: rows for the Candidate Details table, in this order: Candidate Name, Role Submitted For, Location, Current Salary (only if known), Salary Expectation, Notice Period, Availability for Interview, Current Employment. Add a "Commute to <site>" row only if commute information is given. Use "To be confirmed" for any of Location, Salary Expectation, Notice Period, Availability for Interview or Current Employment that is not in the material.
2. email_summary: one or two sentences (maximum 45 words) for the covering email, naming the candidate's strongest evidence against the role's main requirement. Use the first name.
3. profile: two or three paragraphs (Profile Overview) that sell the candidate against the role.
4. sections: two to four background sections with headings chosen to suit the role (for example "Supply Chain and Procurement Background"). Use sub-headings and bullets carrying concrete evidence.
5. fit: one row per role requirement: the requirement, and the candidate's specific evidence. Take the requirements from the ROLE REQUIREMENTS if supplied; otherwise from the requirements stated in the JOB DESCRIPTION. Use the client's own wording for each requirement. Only if neither is supplied, build the rows from the main themes of the role and add a gap saying no role brief was on file. Never invent a requirement the client did not state.
6. motivation: the candidate's reasons for moving and fit with the role, using only what was said.
7. employment: most recent first, with employer, a short role description with responsibilities, and dates.
8. gaps: every item marked "To be confirmed", every disagreement, and anything the recruiter should check. Empty array if none.`;

const SUBMISSION_TOOL = {
  name: 'submit_candidate_submission',
  description: 'Return the finished candidate submission.',
  input_schema: {
    type: 'object',
    properties: {
      candidate_ref: { type: 'string', description: 'First name and surname initial, e.g. "Yihsin C"' },
      details: {
        type: 'array',
        items: { type: 'object', properties: { label: { type: 'string' }, value: { type: 'string' } }, required: ['label', 'value'] },
      },
      email_summary: { type: 'string' },
      profile: { type: 'string', description: 'Profile Overview paragraphs (markup)' },
      sections: {
        type: 'array',
        items: { type: 'object', properties: { heading: { type: 'string' }, body: { type: 'string' } }, required: ['heading', 'body'] },
      },
      fit: {
        type: 'array',
        items: { type: 'object', properties: { requirement: { type: 'string' }, evidence: { type: 'string' } }, required: ['requirement', 'evidence'] },
      },
      motivation: { type: 'string' },
      employment: {
        type: 'array',
        items: {
          type: 'object',
          properties: { employer: { type: 'string' }, role: { type: 'string' }, dates: { type: 'string' } },
          required: ['employer', 'role', 'dates'],
        },
      },
      gaps: { type: 'array', items: { type: 'string' } },
    },
    required: ['candidate_ref', 'details', 'email_summary', 'profile', 'sections', 'fit', 'motivation', 'employment', 'gaps'],
  },
};

const CV_SYSTEM = `You prepare anonymised CVs for Live 2 Help Recruitment, a UK recruitment agency. The anonymised CV goes to a client alongside a submission, so the candidate cannot be contacted directly.

RULES
- Reproduce the candidate's CV faithfully. Do not add, embellish, infer or reword achievements beyond tidying layout and wording. Never invent anything.
- REMOVE all personal identifiers: full name (any part of it), postal address and postcode (a town or region may stay as a general location), phone numbers, email addresses, website and social media links, date of birth, age, photograph, nationality, visa or right-to-work status, marital status, driving licence details, referee names and contact details, and any hobby detail that names a person.
- Wherever the candidate's own name appears in the text, write "the candidate" or rewrite the sentence without it.
- KEEP employer names, job titles, dates, qualifications, awards, systems, skills and achievements exactly as given.
- Never use em dashes or en dashes. Use a plain hyphen with spaces (" - ") for a break in a sentence and a plain hyphen in date ranges (for example "Nov 2022-Present").
- British English.
- Sections, in this order and only where the CV has the content: Profile, Key Skills, Employment History, Education and Qualifications, Training and Certifications, Additional Information.
- In Employment History, start each job with a sub-heading line in this form: "## Employer | Job title | Dates" followed by "- " bullets for responsibilities and achievements.
- ${MARKUP_HELP}
- In "removed" list, in plain words, the kinds of detail you removed (for example "Email address", "Home address", "Referees").`;

const CV_TOOL = {
  name: 'submit_anonymised_cv',
  description: 'Return the anonymised CV.',
  input_schema: {
    type: 'object',
    properties: {
      sections: {
        type: 'array',
        items: { type: 'object', properties: { heading: { type: 'string' }, body: { type: 'string' } }, required: ['heading', 'body'] },
      },
      removed: { type: 'array', items: { type: 'string' } },
    },
    required: ['sections', 'removed'],
  },
};

function screeningText(screen) {
  if (!screen.found || !screen.qa.length) return 'None on file.';
  return screen.qa.map(x => `- ${x.question}: ${x.answer}`).join('\n');
}

function cvBlocks(cvDoc) {
  if (cvDoc.kind === 'pdf') {
    return [{ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: cvDoc.buffer.toString('base64') } }];
  }
  return [{ type: 'text', text: `CV TEXT:\n${cvDoc.text}` }];
}

app.get('/api/submissions/sources', async (req, res) => {
  try {
    const { name, role, company } = req.query;
    if (!name || !role) return res.status(400).json({ error: 'name and role are required' });
    const [cv, screen] = await Promise.all([
      loadCvFile(company, name, role).catch(() => null),
      loadScreening(name, role),
    ]);
    res.json({
      cv: cv ? { found: true, fileName: cv.fileName, kind: cv.kind, readable: ['pdf', 'docx', 'gdoc'].includes(cv.kind) } : { found: false },
      screener: { found: !!screen.found, answers: screen.qa.length, reason: screen.reason || '' },
    });
  } catch (e) {
    console.error('GET /api/submissions/sources error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/submissions/generate', async (req, res) => {
  try {
    const { name, role, company, callNotes, cardNotes } = req.body || {};
    if (!name || !role) return res.status(400).json({ error: 'name and role are required' });
    if (!API_KEY) return res.status(500).json({ error: 'The AI key is not set on the server' });

    const [cvFile, screen] = await Promise.all([
      loadCvFile(company, name, role),
      loadScreening(name, role),
    ]);
    if (!cvFile && !screen.found && !String(callNotes || '').trim()) {
      return res.status(422).json({ error: 'There is no CV, no application answers and no call notes to build a submission from.' });
    }

    let cvDoc = null;
    if (cvFile) {
      if (cvFile.kind === 'doc') {
        return res.status(422).json({ error: 'The CV on file is an old .doc file, which cannot be read. Upload a PDF or DOCX version and try again.' });
      }
      if (cvFile.kind === 'other') {
        return res.status(422).json({ error: 'The CV on file is not a PDF or Word document. Upload a PDF or DOCX version.' });
      }
      const dl = await downloadCv(cvFile);
      cvDoc = { kind: dl.kind, buffer: dl.buffer, text: dl.kind === 'docx' ? docxToText(dl.buffer) : '' };
    }

    const ref = candidateRef(name);
    const brief = await loadRoleBrief(role);
    const requirements = brief.requirements;
    const gapsFromSources = [];
    if (!cvFile) gapsFromSources.push('No CV was on file, so the employment history and background are based on the call notes only.');
    if (!screen.found) gapsFromSources.push('No application form answers were found for this candidate.');
    if (!brief.requirements && !brief.jobDescription) gapsFromSources.push('No role brief is on file for this role, so the fit table is based on the general themes of the role. Add the job description or key requirements to the role brief, then regenerate for a sharper match.');

    const context = [
      `ROLE: ${role}${company && company !== UNASSIGNED_LABEL ? ` at ${company}` : ''}`,
      `ROLE REQUIREMENTS (build the fit table from these):\n${brief.requirements || 'NONE PROVIDED'}`,
      `JOB DESCRIPTION (use for the requirements if none are listed above, and for context):\n${brief.jobDescription ? brief.jobDescription.slice(0, 14000) : 'NONE PROVIDED'}`,
      `CANDIDATE (for your reference only; output first name and initial "${ref}" and never a surname): ${screen.fullName || name}`,
      `APPLICATION ANSWERS:\n${screeningText(screen)}`,
      `RECRUITER NOTES ON THE CANDIDATE CARD:\n${[cardNotes, screen.recruiterNotes].map(s => String(s || '').trim()).filter(Boolean).join('\n') || 'None.'}`,
      `NOTES FROM THE RECRUITER'S CALL WITH THE CANDIDATE:\n${String(callNotes || '').trim() || 'None provided.'}`,
    ].join('\n\n');

    const content = [{ type: 'text', text: context }, ...(cvDoc ? cvBlocks(cvDoc) : [])];

    const jobs = [
      callClaudeTool({ system: SUBMISSION_SYSTEM, content, tool: SUBMISSION_TOOL, maxTokens: 6000 }),
    ];
    if (cvDoc) {
      const cvContent = [
        { type: 'text', text: `Anonymise this CV. The candidate's name is ${screen.fullName || name}.` },
        ...cvBlocks(cvDoc),
      ];
      jobs.push(callClaudeTool({ system: CV_SYSTEM, content: cvContent, tool: CV_TOOL, maxTokens: 6000 }));
    }
    const settled = await Promise.allSettled(jobs);

    const scrubOpts = { fullName: screen.fullName || name, emails: [screen.email], phones: [screen.phone] };
    const out = { warnings: [], errors: {} };

    if (settled[0].status === 'fulfilled') {
      const cleaned = scrubIdentifiers(cleanDeep(settled[0].value), { ...scrubOpts, keepFirstName: true });
      const sub = cleaned.value;
      sub.gaps = [...gapsFromSources, ...(Array.isArray(sub.gaps) ? sub.gaps : [])].filter(Boolean);
      sub.candidate_ref = ref;
      sub.role_title = role;
      out.submission = sub;
      if (cleaned.found.length) out.warnings.push(`Removed from the submission: ${cleaned.found.join(', ')}.`);
      if (cleaned.check.length) out.warnings.push(`Check the submission text - it still contains "${cleaned.check.join('", "')}", which may be the candidate's name.`);
    } else {
      out.errors.submission = settled[0].reason && settled[0].reason.message ? settled[0].reason.message : 'Submission draft failed';
    }

    if (!cvDoc) {
      out.errors.cv = 'There is no CV on file to anonymise.';
    } else if (settled[1] && settled[1].status === 'fulfilled') {
      const cleaned = scrubIdentifiers(cleanDeep(settled[1].value), { ...scrubOpts, keepFirstName: false });
      out.cv = { role_title: role, sections: cleaned.value.sections || [], removed: cleaned.value.removed || [] };
      if (cleaned.found.length) out.warnings.push(`Extra details removed from the anonymised CV: ${cleaned.found.join(', ')}.`);
      if (cleaned.check.length) out.warnings.push(`Check the anonymised CV - it still contains "${cleaned.check.join('", "')}", which may be the candidate's name.`);
    } else if (settled[1]) {
      out.errors.cv = settled[1].reason && settled[1].reason.message ? settled[1].reason.message : 'Anonymised CV failed';
    }

    if (out.errors.submission && !out.cv) return res.status(502).json({ error: out.errors.submission });
    auditLog(auditActorOf(req), 'submission_generated', 'submission', `${name} - ${role}`, out.errors.cv ? 'CV not produced' : '');
    res.json(out);
  } catch (e) {
    console.error('POST /api/submissions/generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- Word documents ------------------------------------------------------

let docxLib = null;
async function getDocx() {
  if (docxLib) return docxLib;
  try {
    docxLib = await import('docx');
  } catch (e) {
    throw new Error('The "docx" package is not installed on the server. Add "docx" to the dependencies in package.json and redeploy.');
  }
  return docxLib;
}

function imageInfo(buf) {
  if (!buf || buf.length < 24) return null;
  if (buf[0] === 0x89 && buf[1] === 0x50) return { type: 'png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    let i = 2;
    while (i + 9 < buf.length) {
      if (buf[i] !== 0xff) { i++; continue; }
      const marker = buf[i + 1];
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { type: 'jpg', height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
      }
      i += 2 + buf.readUInt16BE(i + 2);
    }
  }
  return null;
}

// Logo 3 (Live 2 Help), embedded so Word documents always carry it
const EMBEDDED_LOGO_B64 = '/9j/4AAQSkZJRgABAgAAAQABAAD/wAARCAJoAqADACIAAREBAhEB/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZEhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sAQwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMAAAERAhEAPwD5/ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvv8Ar4Ar7/oA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAC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';

const DX = { gold: 'C9A84C', dark: '1A1A1A', grey: '444444', light: 'F7F6F3', border: 'DDDDDD' };
const FONT = 'Gill Sans MT';

async function buildDocx(kind, data, meta) {
  const d = await getDocx();
  const {
    Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
    ImageRun, Header, Footer, AlignmentType, TableLayoutType, LevelFormat,
  } = d;

  const run = (text, o = {}) => new TextRun({ text, font: FONT, size: o.size || 20, bold: !!o.bold, italics: !!o.italics, color: o.color || DX.grey });
  const runsFrom = (text, o = {}) => splitBold(text).map(p => run(p.text, { ...o, bold: o.bold || p.bold }));

  const heading = text => new Paragraph({
    spacing: { before: 300, after: 120 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: DX.gold, space: 3 } },
    keepNext: true,
    children: [run(String(text).toUpperCase(), { bold: true, size: 22, color: DX.dark })],
  });
  const para = (text, o = {}) => new Paragraph({ spacing: { after: 110, line: 276 }, children: runsFrom(text, o) });
  const bullet = text => new Paragraph({ numbering: { reference: 'bullets', level: 0 }, spacing: { after: 70, line: 264 }, children: runsFrom(text) });
  const subHeading = text => {
    const parts = String(text).split(/\s\|\s/);
    const kids = [run(parts[0], { bold: true, color: DX.dark, size: 21 })];
    if (parts.length > 1) kids.push(run('  |  ' + parts.slice(1).join('  |  '), { color: DX.grey, italics: true }));
    return new Paragraph({ spacing: { before: 160, after: 80 }, keepNext: true, children: kids });
  };
  const blocksToParas = text => parseMarkup(text).map(b => (b.type === 'bullet' ? bullet(b.text) : b.type === 'sub' ? subHeading(b.text) : para(b.text)));

  const border = { style: BorderStyle.SINGLE, size: 4, color: DX.border };
  const borders = { top: border, bottom: border, left: border, right: border };
  const cell = (children, width, o = {}) => new TableCell({
    width: { size: width, type: WidthType.DXA },
    borders,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    shading: o.fill ? { type: ShadingType.CLEAR, color: 'auto', fill: o.fill } : undefined,
    children,
  });
  const cellText = (text, o = {}) => [new Paragraph({ spacing: { after: 0, line: 264 }, children: runsFrom(text || '', o) })];
  const table = (widths, rows) => new Table({
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    columnWidths: widths,
    layout: TableLayoutType.FIXED,
    rows,
  });
  const headRow = (labels, widths) => new TableRow({
    tableHeader: true,
    children: labels.map((l, i) => cell(cellText(l, { bold: true, color: 'FFFFFF' }), widths[i], { fill: DX.dark })),
  });

  // Header with logo and gold rule. Uses assets/Logo_3.png if present, otherwise the copy built into this file,
  // so the logo never depends on where the server was deployed from.
  let logoPara = null;
  try {
    const fs = await import('fs');
    let buf = null;
    try { buf = fs.readFileSync(path.join(__dirname, 'assets', 'Logo_3.png')); } catch (e) { buf = null; }
    if (!buf || !imageInfo(buf)) buf = Buffer.from(EMBEDDED_LOGO_B64, 'base64');
    const info = imageInfo(buf);
    if (info) {
      const w = 70, h = Math.round((70 * info.height) / info.width);
      logoPara = new Paragraph({
        spacing: { after: 60 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: DX.gold, space: 4 } },
        children: [new ImageRun({ type: info.type, data: buf, transformation: { width: w, height: h }, altText: { title: 'Live 2 Help', description: 'Live 2 Help Recruitment logo', name: 'logo' } })],
      });
    }
  } catch (e) { console.error('Logo could not be added to the document:', e.message); }
  if (!logoPara) {
    logoPara = new Paragraph({
      spacing: { after: 60 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: DX.gold, space: 4 } },
      children: [run('LIVE 2 HELP RECRUITMENT', { bold: true, size: 22, color: DX.dark })],
    });
  }

  const footer = new Footer({
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [run('Live 2 Help Recruitment Ltd \u00b7 Company No. 11731080 \u00b7 Anyone \u00b7 Anywhere \u00b7 Anytime', { italics: true, size: 16, color: '777777' })],
    })],
  });

  const body = [];
  const W = 9360;

  if (kind === 'submission') {
    body.push(new Paragraph({ spacing: { before: 200, after: 40 }, children: [run('Candidate Submission', { bold: true, size: 52, color: DX.dark })] }));
    body.push(new Paragraph({ spacing: { after: 160 }, children: [run('Live 2 Help Recruitment  \u00b7  For Exclusive Consideration', { size: 21, color: DX.gold })] }));

    body.push(heading('Candidate Details'));
    const detailRows = (data.details || []).filter(r => r && (r.label || r.value)).map(r => new TableRow({
      cantSplit: true,
      children: [cell(cellText(r.label, { bold: true, color: DX.dark }), 2800, { fill: DX.light }), cell(cellText(r.value), 6560)],
    }));
    if (detailRows.length) body.push(table([2800, 6560], detailRows));

    if (String(data.profile || '').trim()) { body.push(heading('Profile Overview')); body.push(...blocksToParas(data.profile)); }
    (data.sections || []).forEach(s => {
      if (!s || (!s.heading && !s.body)) return;
      if (s.heading) body.push(heading(s.heading));
      body.push(...blocksToParas(s.body));
    });

    const fitRows = (data.fit || []).filter(r => r && (r.requirement || r.evidence));
    if (fitRows.length) {
      body.push(heading(`Fit for the ${data.role_title || 'Role'}`));
      const fw = [4160, 5200];
      body.push(table(fw, [
        headRow(['Role Requirement', `${data.candidate_ref ? String(data.candidate_ref).split(' ')[0] + "'s" : 'Candidate'} Evidence`], fw),
        ...fitRows.map(r => new TableRow({
          cantSplit: true,
          children: [cell(cellText(r.requirement, { bold: true, color: DX.dark }), fw[0]), cell(cellText(r.evidence), fw[1])],
        })),
      ]));
    }

    if (String(data.motivation || '').trim()) { body.push(heading('Motivation and Role Fit')); body.push(...blocksToParas(data.motivation)); }

    const emp = (data.employment || []).filter(r => r && (r.employer || r.role));
    if (emp.length) {
      body.push(heading('Employment History'));
      const ew = [2800, 4560, 2000];
      body.push(table(ew, [
        headRow(['Employer', 'Role', 'Dates'], ew),
        ...emp.map(r => new TableRow({
          cantSplit: true,
          children: [cell(cellText(r.employer, { bold: true, color: DX.dark }), ew[0]), cell(cellText(r.role), ew[1]), cell(cellText(r.dates), ew[2])],
        })),
      ]));
    }

    body.push(new Paragraph({ spacing: { before: 320, after: 40 }, children: [run(`Submitted by Live 2 Help Recruitment \u00b7 For exclusive consideration for the ${data.role_title || meta.role || ''} role`, { italics: true, size: 18 })] }));
    body.push(new Paragraph({ spacing: { after: 0 }, children: [run((meta && meta.contactLine) || SUBMISSION_CONTACT_LINE, { size: 18 })] }));
  } else if (kind === 'interview_pack') {
    const cons = data.consultant || {};
    const consFirst = cons.first_name || String(cons.name || 'Your consultant').split(' ')[0];
    const firstName = data.first_name || String(data.candidate_ref || '').split(' ')[0] || 'there';
    const company = data.company || '';
    body.push(new Paragraph({ spacing: { before: 200, after: 40 }, children: [run('Interview Preparation Pack', { bold: true, size: 52, color: DX.dark })] }));
    body.push(new Paragraph({ spacing: { after: 40 }, children: [run([data.candidate_ref, data.role_title, company, (parseInt(data.round_no, 10) || 0) > 1 ? data.round_label : ''].filter(Boolean).join('  \u00b7  '), { size: 21, color: DX.gold })] }));
    body.push(new Paragraph({ spacing: { after: 160 }, children: [run('Prepared exclusively by Live 2 Help Recruitment', { italics: true, size: 19 })] }));

    const sched = (data.schedule || []).filter(r => r && r.label && String(r.value || '').trim());
    if (sched.length) {
      body.push(heading('Interview Schedule'));
      body.push(table([2800, 6560], sched.map(r => new TableRow({
        cantSplit: true,
        children: [cell(cellText(r.label, { bold: true, color: DX.dark }), 2800, { fill: DX.light }), cell(cellText(r.value), 6560)],
      }))));
    }
    body.push(new Paragraph({
      spacing: { before: 140, after: 80 },
      children: [run(`Important: contact ${consFirst}${cons.phone ? ' immediately on ' + cons.phone : ' immediately'} if anything changes - do not leave it until the last minute.`, { bold: true, italics: true, color: DX.dark })],
    }));
    if (data.has_site_pack) {
      body.push(para('Travel, parking, arrival, dress code and site details are in your separate Site Pack, attached to the same email.'));
    }

    if (String(data.about_company || '').trim()) { body.push(heading(`About ${company || 'the Company'}`)); body.push(...blocksToParas(data.about_company)); }
    if (String(data.meeting_summary || '').trim()) { body.push(heading('Who You Will Be Meeting')); body.push(...blocksToParas(data.meeting_summary)); }
    if (String(data.interview_format || '').trim()) { body.push(heading('Interview Format')); body.push(...blocksToParas(data.interview_format)); }

    const qs = (data.questions || []).filter(q => q && q.question);
    if (qs.length) {
      body.push(heading('Competency Questions - Prepared For You'));
      body.push(para('The questions below are tailored to your background and to what the role needs. Prepare a specific STAR answer for each one before the interview and know your examples in detail.'));
      qs.forEach((q, i) => {
        body.push(new Paragraph({ spacing: { before: 240, after: 80 }, keepNext: true, children: [run(`${i + 1}. ${q.question}`, { bold: true, size: 22, color: DX.dark })] }));
        body.push(...blocksToParas(q.points));
        if (String(q.tip || '').trim()) {
          body.push(new Paragraph({
            spacing: { before: 60, after: 100, line: 276 },
            indent: { left: 200 },
            border: { left: { style: BorderStyle.SINGLE, size: 18, color: DX.gold, space: 8 } },
            children: [run(`${consFirst}'s tip: `, { bold: true, color: DX.dark }), ...runsFrom(q.tip, { italics: true })],
          }));
        }
      });
    }

    body.push(heading('The STAR Technique - How to Answer Every Competency Question'));
    body.push(para('Structure every competency answer using the STAR method. It keeps your response focused, evidenced and compelling.'));
    const sw = [900, 1800, 6660];
    body.push(table(sw, [
      headRow(['Stage', 'What it means', 'What to include'], sw),
      ...[
        ['S', 'Situation', 'Set the scene briefly - where were you and what was happening? Keep this to two or three sentences.'],
        ['T', 'Task', 'What was your specific responsibility? What were you trying to achieve or resolve?'],
        ['A', 'Action', 'What did YOU do? Use "I", not "we". This is the most important part. Be specific about your decisions and your approach.'],
        ['R', 'Result', 'What was the measurable outcome? A number, a percentage, a clear business impact. Always finish here, and know your numbers.'],
      ].map(r => new TableRow({
        cantSplit: true,
        children: [cell(cellText(r[0], { bold: true, color: DX.dark }), sw[0], { fill: DX.light }), cell(cellText(r[1], { bold: true, color: DX.dark }), sw[1]), cell(cellText(r[2]), sw[2])],
      })),
    ]));
    body.push(para('If you cannot think of a strong example straight away, ask for a moment to gather your thoughts - that is far better than stumbling through a weak answer. Never invent experience; an experienced interviewer will spot it quickly.'));

    const ask = (data.questions_to_ask || []).filter(Boolean);
    if (ask.length) {
      body.push(heading('Questions You Could Ask'));
      body.push(para('Asking good questions shows genuine interest. Choose the ones that matter most to you.'));
      ask.forEach(a => body.push(bullet(a)));
    }

    body.push(new Paragraph({ spacing: { before: 320, after: 60 }, children: [run(`Good luck, ${firstName}. You are well prepared and we are right behind you.`, { bold: true, color: DX.dark })] }));
    body.push(new Paragraph({ spacing: { after: 0 }, children: [run([cons.name, cons.phone, cons.email].filter(Boolean).join('  |  ') || (meta && meta.contactLine) || SUBMISSION_CONTACT_LINE, { size: 18 })] }));
  } else if (kind === 'site_pack') {
    const cons = data.consultant || {};
    const site = data.site || {};
    const f = site.fields || {};
    const firstName = data.first_name || String(data.candidate_ref || '').split(' ')[0] || 'there';
    body.push(new Paragraph({ spacing: { before: 200, after: 40 }, children: [run('Interview Day Site Pack', { bold: true, size: 52, color: DX.dark })] }));
    body.push(new Paragraph({ spacing: { after: 160 }, children: [run([data.candidate_ref, data.role_title, data.company].filter(Boolean).join('  \u00b7  '), { size: 21, color: DX.gold })] }));
    body.push(para(`Hi ${firstName}, everything below is designed to take the guesswork out of the day, so that all your energy goes into the interview itself.`));

    const rowsFor = list => list.filter(x => String(x.value || '').trim()).map(x => new TableRow({
      cantSplit: true,
      children: [cell(cellText(x.label, { bold: true, color: DX.dark }), 2800, { fill: DX.light }), cell(cellText(x.value), 6560)],
    }));
    const sectionOrder = ['Getting There', 'On Arrival', 'What to Wear', 'Health, Safety and Accessibility', 'Good to Know'];
    sectionOrder.forEach((sec, idx) => {
      const list = SITE_FIELDS.filter(x => x.section === sec).map(x => ({ label: x.label, value: f[x.key] }));
      if (idx === 0) {
        const where = [/^main site$/i.test(String(site.site_name || '').trim()) ? '' : site.site_name, site.address, site.postcode].filter(Boolean).join(', ');
        list.unshift({ label: 'Address', value: where });
      }
      const rows = rowsFor(list);
      if (!rows.length) return;
      body.push(heading(sec));
      body.push(table([2800, 6560], rows));
    });

    const contacts = [];
    if (f.contact1_name || f.contact1_phone || f.contact1_email) contacts.push({ label: 'On the day', value: [f.contact1_name, f.contact1_phone, f.contact1_email].filter(Boolean).join('  |  ') });
    if (f.contact2_name || f.contact2_phone || f.contact2_email) contacts.push({ label: 'Second contact', value: [f.contact2_name, f.contact2_phone, f.contact2_email].filter(Boolean).join('  |  ') });
    if (cons.name) contacts.push({ label: 'Your consultant', value: [cons.name, cons.phone, cons.email].filter(Boolean).join('  |  ') });
    const crow = rowsFor(contacts);
    if (crow.length) { body.push(heading('If You Have Any Questions')); body.push(table([2800, 6560], crow)); }

    body.push(new Paragraph({ spacing: { before: 320, after: 0 }, children: [run(`You have done the preparation, ${firstName}. Arrive calm, be yourself, and let your experience do the talking.`, { bold: true, color: DX.dark })] }));
  } else if (kind === 'cv') {
    body.push(new Paragraph({ spacing: { before: 200, after: 40 }, children: [run('Anonymised CV', { bold: true, size: 52, color: DX.dark })] }));
    body.push(new Paragraph({ spacing: { after: 160 }, children: [run(`Live 2 Help Recruitment  \u00b7  ${data.role_title || meta.role || ''}`, { size: 21, color: DX.gold })] }));
    (data.sections || []).forEach(s => {
      if (!s || (!s.heading && !s.body)) return;
      if (s.heading) body.push(heading(s.heading));
      body.push(...blocksToParas(s.body));
    });
    body.push(new Paragraph({ spacing: { before: 320, after: 40 }, children: [run('Personal details have been removed by Live 2 Help Recruitment. Full details are available on request once you would like to proceed.', { italics: true, size: 18 })] }));
    body.push(new Paragraph({ spacing: { after: 0 }, children: [run((meta && meta.contactLine) || SUBMISSION_CONTACT_LINE, { size: 18 })] }));
  }

  const doc = new Document({
    creator: 'Live 2 Help Recruitment',
    title: ({ submission: 'Candidate Submission', cv: 'Anonymised CV', interview_pack: 'Interview Preparation Pack', site_pack: 'Interview Day Site Pack' })[kind] || 'Live 2 Help Recruitment',
    styles: { default: { document: { run: { font: FONT, size: 20, color: DX.grey } } } },
    numbering: {
      config: [{
        reference: 'bullets',
        levels: [{ level: 0, format: LevelFormat.BULLET, text: '\u2022', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }],
      }],
    },
    sections: [{
      properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, right: 1273, bottom: 1134, left: 1273, header: 500, footer: 500 } } },
      headers: { default: new Header({ children: [logoPara] }) },
      footers: { default: footer },
      children: body,
    }],
  });
  return Packer.toBuffer(doc);
}

// Who the document is from: the person who created the draft if sent, otherwise whoever is signed in
function creatorContactLine(req) {
  const asked = String(((req.body || {}).createdBy) || '').trim().toLowerCase();
  const known = asked && ((AUTH_USERS || []).some(u => u.key === asked || String(u.name || '').toLowerCase() === asked) || TEAM_DEFAULTS[asked]);
  return contactLineFor(known ? asked : actorOf(req));
}

app.post('/api/submissions/docx', async (req, res) => {
  try {
    const { kind, data, name, role } = req.body || {};
    if (!['submission', 'cv'].includes(kind) || !data) return res.status(400).json({ error: 'kind and data are required' });
    const buf = await buildDocx(kind, cleanDeep(data), { role, contactLine: creatorContactLine(req) });
    const names = submissionFileNames(name, role);
    res.json({ fileName: kind === 'submission' ? names.submission : names.cv, base64: buf.toString('base64') });
  } catch (e) {
    console.error('POST /api/submissions/docx error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Filed automatically once a person confirms the email was sent
app.post('/api/submissions/archive', async (req, res) => {
  try {
    const { name, role, company, submission, cv } = req.body || {};
    if (!name || !role || !submission) return res.status(400).json({ error: 'name, role and submission are required' });
    const folderId = await resolveCandidateCvFolder(company, name);
    const drive = getUploadDriveClient();
    const names = submissionFileNames(name, role);
    const saved = [];
    const put = async (fileName, buffer) => {
      const existing = await drive.files.list({
        q: `'${folderId}' in parents and name='${escDriveQuery(fileName)}' and trashed=false`,
        spaces: 'drive', pageSize: 1, fields: 'files(id)',
      });
      const media = { mimeType: DOCX_MIME, body: Readable.from([buffer]) };
      let file;
      try {
        if (existing.data.files && existing.data.files.length) {
          file = await drive.files.update({ fileId: existing.data.files[0].id, media, fields: 'id, name, webViewLink' });
        } else {
          file = await drive.files.create({ resource: { name: fileName, parents: [folderId] }, media, fields: 'id, name, webViewLink' });
        }
      } catch (e) { throw new Error(friendlyDriveError(e)); }
      saved.push({ name: fileName, link: file.data.webViewLink || '' });
    };
    const contactLine = creatorContactLine(req);
    await put(names.submission, await buildDocx('submission', cleanDeep(submission), { role, contactLine }));
    if (cv) await put(names.cv, await buildDocx('cv', cleanDeep(cv), { role, contactLine }));
    res.json({ ok: true, files: saved });
  } catch (e) {
    console.error('POST /api/submissions/archive error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- Draft records ---------------------------------------------------------

const DRAFT_LIGHT_FIELDS = [
  'id', 'candidate_id', 'candidate_name', 'role', 'company', 'status', 'contact_name', 'contact_email',
  'batch_id', 'created_by', 'created_at', 'approved_at', 'sent_at',
];

app.get('/api/submission-drafts', async (req, res) => {
  try {
    const all = await submissionDraftsTable.list();
    res.json({
      data: all.map(o => {
        const l = {};
        DRAFT_LIGHT_FIELDS.forEach(k => { l[k] = o[k]; });
        return l;
      }),
    });
  } catch (e) {
    console.error('GET /api/submission-drafts error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/submission-drafts/:id', async (req, res) => {
  try {
    const hit = (await submissionDraftsTable.list()).find(o => o.id === req.params.id);
    if (!hit) return res.status(404).json({ error: 'Draft not found' });
    res.json({ data: hit });
  } catch (e) {
    console.error('GET /api/submission-drafts/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/submission-drafts', async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.id) return res.status(400).json({ error: 'id is required' });
    if (b.status && !DRAFT_STATUSES.includes(b.status)) return res.status(400).json({ error: 'Unknown status' });
    ['submission_json', 'cv_json', 'call_notes'].forEach(k => {
      if (b[k] !== undefined && String(b[k]).length > SHEET_CELL_LIMIT) {
        throw new Error(`The ${k.replace('_json', '').replace('_', ' ')} is too long to store. Shorten it and save again.`);
      }
    });
    const existing = (await submissionDraftsTable.list()).find(o => o.id === b.id);
    const clean = {};
    Object.keys(b).forEach(k => {
      if (['id', 'candidate_id', 'candidate_name', 'role', 'company', 'status', 'call_notes', 'submission_json', 'cv_json',
        'contact_name', 'contact_email', 'batch_id', 'created_by', 'created_at', 'approved_at', 'sent_at'].includes(k)) clean[k] = b[k];
    });
    const saved = await submissionDraftsTable.upsert({ ...(existing || {}), ...clean });
    if (!existing || (clean.status && existing.status !== clean.status)) {
      auditLog(auditActorOf(req), existing ? `submission_${clean.status}` : 'submission_draft_created', 'submission', `${saved.candidate_name} - ${saved.role}`, '');
    }
    res.json({ ok: true, data: saved });
  } catch (e) {
    console.error('POST /api/submission-drafts error:', e.message);
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/submission-drafts/:id', async (req, res) => {
  try {
    const ok = await submissionDraftsTable.remove(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Draft not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /api/submission-drafts/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


/* ======================================================================
   Client sites, client Drive folders, email signatures and interview packs
   ====================================================================== */

// ---- Client folders in Drive ----------------------------------------------
// Adding a client creates:
//   1. a folder with the company name inside the Candidates Submissions folder, so new
//      submissions already have somewhere to go
//   2. Clients / [Company] / Site Info, Submissions, Invoices
// Set CLIENTS_FOLDER_ID on Render to use an existing Clients folder; otherwise a folder called
// "Clients" is found or created in the main Google Drive that the upload sign-in belongs to.

const CLIENTS_ROOT_NAME = 'Clients';
const CLIENT_SUBFOLDERS = ['Site Info', 'Submissions', 'Invoices'];
let clientsRootCache = process.env.CLIENTS_FOLDER_ID || null;
let clientsRootShared = false;
const clientFolderJobs = new Map();

function botEmail() {
  try { return JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON).client_email || ''; } catch (e) { return ''; }
}

async function findOrCreateDriveFolder(parentId, name) {
  const drive = getUploadDriveClient();
  let list;
  try {
    list = await drive.files.list({
      q: `'${parentId}' in parents and name='${escDriveQuery(name)}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
      spaces: 'drive', pageSize: 1, fields: 'files(id, name)',
    });
  } catch (e) { throw new Error(friendlyDriveError(e)); }
  if (list.data.files && list.data.files.length) return { id: list.data.files[0].id, created: false };
  try {
    const f = await drive.files.create({
      resource: { name, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] },
      fields: 'id',
    });
    return { id: f.data.id, created: true };
  } catch (e) { throw new Error(friendlyDriveError(e)); }
}

async function getClientsRootId() {
  if (clientsRootCache && clientsRootShared) return clientsRootCache;
  if (!clientsRootCache) {
    const r = await findOrCreateDriveFolder('root', CLIENTS_ROOT_NAME);
    clientsRootCache = r.id;
  }
  if (!clientsRootShared) {
    // The dashboard's service account needs to see this tree too
    const bot = botEmail();
    if (bot && oauthUploadsConfigured()) {
      try {
        await getUploadDriveClient().permissions.create({
          fileId: clientsRootCache,
          requestBody: { type: 'user', role: 'writer', emailAddress: bot },
          sendNotificationEmail: false,
        });
      } catch (e) { console.error('Could not share the Clients folder with the service account:', e.message); }
    }
    clientsRootShared = true;
  }
  return clientsRootCache;
}

function ensureClientFolders(company, opts = {}) {
  const name = String(company || '').trim();
  if (!name) return Promise.reject(new Error('A company name is required'));
  const key = name.toLowerCase() + (opts.skipSubmissions ? '|skip' : '');
  if (clientFolderJobs.has(key)) return clientFolderJobs.get(key);
  const job = (async () => {
    const submissions = opts.skipSubmissions ? { id: '', created: false } : await findOrCreateDriveFolder(SUBMISSIONS_FOLDER_ID, name);
    const root = await getClientsRootId();
    const clientFolder = await findOrCreateDriveFolder(root, name);
    const subs = {};
    let createdAny = submissions.created || clientFolder.created;
    for (const s of CLIENT_SUBFOLDERS) {
      const f = await findOrCreateDriveFolder(clientFolder.id, s);
      subs[s] = f.id;
      if (f.created) createdAny = true;
    }
    return {
      submissionsFolderId: submissions.id,
      clientFolderId: clientFolder.id,
      siteInfoId: subs['Site Info'],
      created: createdAny,
    };
  })().finally(() => clientFolderJobs.delete(key));
  clientFolderJobs.set(key, job);
  return job;
}

async function markClientFolders(company) {
  const sheets = getSheetsClient();
  const rows = await readClientRows();
  const data = [];
  rows.forEach((r, i) => {
    if (r[1] && r[1].trim() === String(company).trim() && (r[8] || '') !== 'Yes') {
      data.push({ range: `${CLIENT_TAB}!I${i + 2}`, values: [['Yes']] });
    }
  });
  if (data.length) {
    await sheets.spreadsheets.values.batchUpdate({
      spreadsheetId: CLIENT_SHEET_ID,
      requestBody: { valueInputOption: 'RAW', data },
    });
  }
}

// Words that differ between how a company is written on the client sheet and how its
// existing folder in Candidates Submissions was named
function folderNameKey(name) {
  const skip = new Set(['ltd', 'limited', 'uk', 'plc', 'the', 'and', 'group']);
  const words = String(name || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').split(/\s+/).filter(w => w && !skip.has(w));
  return words[0] || '';
}

// One-off (and safe to repeat): create the folders for every client already on the sheet.
// { preview: true } only reports what would happen. A client whose name looks like a folder that
// already exists in Candidates Submissions keeps that folder and does not get a second one.
app.post('/api/clients/ensure-folders', requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const only = body.company ? [String(body.company).trim()] : null;
    const rows = await readClientRows();
    const companies = only || [...new Set(rows.filter(r => r[1]).map(r => r[1].trim()))];
    const existing = (await listFolderContents(SUBMISSIONS_FOLDER_ID)).filter(f => f.mimeType === 'application/vnd.google-apps.folder');
    const results = [];
    for (const c of companies) {
      const exact = existing.find(f => f.name === c);
      const similar = exact ? null : existing.find(f => folderNameKey(f.name) && folderNameKey(f.name) === folderNameKey(c));
      const plan = exact ? 'exists' : similar ? 'similar' : 'create';
      if (body.preview) { results.push({ company: c, plan, similarTo: similar ? similar.name : '' }); continue; }
      try {
        const f = await ensureClientFolders(c, { skipSubmissions: plan === 'similar' });
        await markClientFolders(c);
        results.push({ company: c, ok: true, created: f.created, plan, similarTo: similar ? similar.name : '' });
      } catch (e) {
        results.push({ company: c, ok: false, error: e.message, plan });
      }
    }
    if (!body.preview) auditLog(auditActorOf(req), 'folders_created', 'client', `${results.filter(r => r.ok).length} clients`, '');
    res.json({ ok: true, preview: !!body.preview, results });
  } catch (e) {
    console.error('POST /api/clients/ensure-folders error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- Client sites -----------------------------------------------------------
// A client can have several sites. Each site has its own address and its own logistics,
// read from the client's completed Site Onboarding Information Form (PDF).

const SITE_FIELDS = [
  { key: 'parking', label: 'Parking', section: 'Getting There' },
  { key: 'transport', label: 'Public transport and walking distance', section: 'Getting There' },
  { key: 'access_notes', label: 'Access routes and anything unusual', section: 'Getting There' },
  { key: 'arrival_time', label: 'Arrive at', section: 'On Arrival' },
  { key: 'clearance_allowance', label: 'Time to allow for security', section: 'On Arrival' },
  { key: 'security', label: 'Gates and security', section: 'On Arrival' },
  { key: 'pre_registration', label: 'Pre-registration', section: 'On Arrival' },
  { key: 'reception', label: 'Reception', section: 'On Arrival' },
  { key: 'reception_contact', label: 'Who to ask for', section: 'On Arrival' },
  { key: 'badges', label: 'Badges or passes', section: 'On Arrival' },
  { key: 'building_floor', label: 'Building and floor', section: 'On Arrival' },
  { key: 'directions', label: 'Directions from reception', section: 'On Arrival' },
  { key: 'layout_notes', label: 'Layout notes', section: 'On Arrival' },
  { key: 'escort', label: 'Escort', section: 'On Arrival' },
  { key: 'dress_code', label: 'Dress code', section: 'What to Wear' },
  { key: 'safety_requirements', label: 'Site safety requirements', section: 'What to Wear' },
  { key: 'accessibility', label: 'Accessibility (lifts, toilets, access)', section: 'Health, Safety and Accessibility' },
  { key: 'refreshments', label: 'Refreshments', section: 'Health, Safety and Accessibility' },
  { key: 'dietary', label: 'Dietary needs', section: 'Health, Safety and Accessibility' },
  { key: 'induction', label: 'Health and safety induction', section: 'Health, Safety and Accessibility' },
  { key: 'interview_duration', label: 'Expected length of visit', section: 'Good to Know' },
  { key: 'late_contact', label: 'If you are running late', section: 'Good to Know' },
  { key: 'other_info', label: 'Anything else', section: 'Good to Know' },
  { key: 'contact1_name', label: 'Main contact name', section: 'Contacts' },
  { key: 'contact1_phone', label: 'Main contact phone', section: 'Contacts' },
  { key: 'contact1_email', label: 'Main contact email', section: 'Contacts' },
  { key: 'contact2_name', label: 'Second contact name', section: 'Contacts' },
  { key: 'contact2_phone', label: 'Second contact phone', section: 'Contacts' },
  { key: 'contact2_email', label: 'Second contact email', section: 'Contacts' },
];

const clientSitesTable = makeSimpleTable({
  tab: 'Client Sites',
  header: [
    'id', 'company', 'site_name', 'address', 'postcode', 'pdf_file_id', 'pdf_link', 'pdf_name',
    'logistics_json', 'checked', 'updated_by', 'updated_at',
  ],
  path: '/api/client-sites',
  label: 'Client site',
  auditType: 'client_site',
  auditName: o => `${o.company} - ${o.site_name}`,
});

const SITE_SYSTEM = `You read a completed Site Onboarding Information Form for Live 2 Help Recruitment, a UK recruitment agency. The form was filled in by a client (or by a recruiter on a call) and describes what a candidate needs to know to attend an interview at the client's site.

RULES
- Copy what has actually been filled in, using the client's own wording as far as possible. Tidy spelling and punctuation only.
- If a box is blank, unticked or still shows placeholder text, return an empty string for that field. Never guess, infer or invent access details, times, names or numbers.
- For tick boxes, write the option that was ticked (for example "Free on-site car park"). If several are ticked, list them.
- Keep phone numbers and email addresses exactly as written.
- British English. Never use em dashes or en dashes. Use a plain hyphen with spaces for a break in a sentence.
- In "missing", list in plain words the important things a candidate would need that the form does not answer (for example "Where to park", "Who to ask for at reception").`;

const SITE_TOOL = {
  name: 'submit_site_information',
  description: 'Return the site information found in the form.',
  input_schema: {
    type: 'object',
    properties: {
      address: { type: 'string', description: 'Street address of the site as written on the form' },
      postcode: { type: 'string' },
      ...Object.fromEntries(SITE_FIELDS.map(f => [f.key, { type: 'string', description: f.label }])),
      missing: { type: 'array', items: { type: 'string' } },
    },
    required: ['address', 'postcode', ...SITE_FIELDS.map(f => f.key), 'missing'],
  },
};

async function extractSiteInfo(pdfBuffer, company, siteName) {
  const content = [
    { type: 'text', text: `Read this completed Site Onboarding Information Form for ${company}${siteName ? ` (${siteName})` : ''}.` },
    { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBuffer.toString('base64') } },
  ];
  const out = await callClaudeTool({ system: SITE_SYSTEM, content, tool: SITE_TOOL, maxTokens: 4000 });
  return cleanDeep(out);
}


// ---- Reading the fillable fields inside the client's PDF -----------------------
// The Site Onboarding Information Form is a fillable PDF. What the client typed lives in the
// form fields, not in the page text, so the fields are read directly. That is exact, fast and does
// not depend on the AI. A flattened or scanned copy falls back to the AI reading the pages.

let pdfLibCache;
async function getPdfLib() {
  if (pdfLibCache !== undefined) return pdfLibCache;
  try { pdfLibCache = await import('pdf-lib'); } catch (e) { pdfLibCache = null; }
  return pdfLibCache;
}

async function readPdfFormValues(buf) {
  const lib = await getPdfLib();
  if (!lib) return { available: false, hasValues: false, values: {} };
  try {
    const doc = await lib.PDFDocument.load(buf, { ignoreEncryption: true, updateMetadata: false });
    const fields = doc.getForm().getFields();
    const values = {};
    for (const f of fields) {
      let v = '';
      try {
        if (f instanceof lib.PDFCheckBox) v = f.isChecked();
        else if (f instanceof lib.PDFTextField) v = String(f.getText() || '').replace(/\s+/g, ' ').trim();
        else if (f instanceof lib.PDFRadioGroup) v = String(f.getSelected() || '');
        else if (f instanceof lib.PDFDropdown || f instanceof lib.PDFOptionList) v = (f.getSelected() || []).join(', ');
      } catch (e) { v = ''; }
      values[f.getName()] = v;
    }
    const hasValues = Object.values(values).some(v => v === true || (typeof v === 'string' && v.trim()));
    return { available: true, hasValues, values, count: fields.length };
  } catch (e) {
    return { available: true, hasValues: false, values: {}, error: e.message };
  }
}

const UK_POSTCODE_RE = /\b([A-Z]{1,2}\d[A-Z\d]?)\s*(\d[A-Z]{2})\b/i;

// Turns the form's fields into the site details. Field names come from our own form template.
function mapSiteForm(v) {
  v = v || {};
  const t = k => (typeof v[k] === 'string' ? v[k].replace(/\s+/g, ' ').trim() : '');
  const on = k => v[k] === true;
  const ticked = pairs => pairs.filter(([k]) => on(k)).map(([, label]) => label);
  const sentence = s => { s = String(s || '').trim(); return s && !/[.!?]$/.test(s) ? s + '.' : s; };

  const out = {};
  SITE_FIELDS.forEach(f => { out[f.key] = ''; });

  let address = t('site_address'), postcode = '';
  const pm = UK_POSTCODE_RE.exec(address);
  if (pm) {
    postcode = (pm[1] + ' ' + pm[2]).toUpperCase();
    address = address.replace(UK_POSTCODE_RE, '').replace(/[\s,]+$/, '').trim();
  }
  out.address = address;
  out.postcode = postcode;

  const parkKinds = ticked([['park_onsite', 'On-site parking'], ['park_reserved', 'Reserved space'], ['park_nearby', 'Nearby car park'], ['park_street', 'Street parking'], ['park_none', 'Very limited parking']]);
  out.parking = [parkKinds.join(', '), t('parking_details')].filter(Boolean).map(sentence).join(' ');
  out.transport = t('transport');
  out.access_notes = t('access_routes');

  out.arrival_time = t('arrival_time');
  const buf = t('security_buffer');
  out.clearance_allowance = /^\d+$/.test(buf) ? `${buf} minutes` : buf;
  const gate = on('gate_yes') ? 'There is a gate house with a security check on arrival.' : on('gate_no') ? 'There is no gate house or security check on arrival.' : '';
  out.security = [gate, sentence(t('security_process'))].filter(Boolean).join(' ');
  out.pre_registration = ticked([['prereg_yes', 'Registration is required in advance.'], ['signin_yes', 'Sign in on arrival.'], ['noreg', 'No registration is needed.']]).join(' ');
  out.reception = t('reception_location');
  out.reception_contact = t('ask_for');
  out.badges = on('badge_yes') ? 'A visitor badge or pass is required.' : on('badge_no') ? 'No visitor badge or pass is needed.' : '';
  out.building_floor = t('building_floor');
  out.directions = t('directions');
  out.layout_notes = t('layout_quirks');
  out.escort = t('escort');

  out.dress_code = ticked([['dress_formal', 'Business formal'], ['dress_smart', 'Business smart'], ['dress_casual', 'Smart casual'], ['dress_hivis', 'Hi-vis / PPE required']]).join(', ');
  out.safety_requirements = t('dress_notes');

  out.accessibility = t('accessibility');
  out.induction = on('hs_yes')
    ? [ 'A health and safety induction is required before the interview.', sentence(t('hs_details')) ].filter(Boolean).join(' ')
    : on('hs_no') ? 'No health and safety induction is needed.' : t('hs_details');

  out.interview_duration = t('duration');
  out.late_contact = t('late_contact');
  out.other_info = t('other_notes');

  out.contact1_name = t('contact1_name');
  out.contact1_phone = t('contact1_phone');
  out.contact1_email = t('contact1_email');
  out.contact2_name = t('contact2_name');
  out.contact2_phone = t('contact2_phone');
  out.contact2_email = t('contact2_email');

  const important = [
    ['parking', 'Where to park'], ['reception', 'Where reception is'], ['reception_contact', 'Who to ask for at reception'],
    ['directions', 'Directions from reception to the interview room'], ['arrival_time', 'What time to arrive'],
    ['dress_code', 'The dress code'], ['contact1_name', 'A main contact for the day'],
  ];
  out.missing = important.filter(([k]) => !out[k]).map(([, label]) => label);
  out._company = t('client_company');
  return out;
}

function countSiteDetails(ex) {
  return SITE_FIELDS.filter(f => String((ex && ex[f.key]) || '').trim()).length;
}

app.post('/api/client-sites/:id/pdf', async (req, res) => {
  try {
    const { company, siteName, fileName, fileData } = req.body || {};
    if (!company) return res.status(400).json({ error: 'The company is required' });
    if (!fileName || !/\.pdf$/i.test(String(fileName)) || !fileData) {
      return res.status(400).json({ error: 'Upload the completed site onboarding form as a PDF file' });
    }
    if (String(fileData).length > 13 * 1024 * 1024) return res.status(400).json({ error: 'That PDF is larger than 9MB' });
    const buf = Buffer.from(String(fileData), 'base64');
    if (buf.subarray(0, 4).toString() !== '%PDF') return res.status(400).json({ error: 'That file is not a valid PDF' });

    let extracted = null;
    let warning = '';
    let readBy = '';
    // The dashboard reads the form's fields in the browser and sends them along. If they are not
    // there (or empty), try reading them here on the server.
    let form = null;
    const sent = req.body && req.body.formValues;
    if (sent && typeof sent === 'object' && !Array.isArray(sent)) {
      const vals = {};
      Object.keys(sent).slice(0, 300).forEach(k => {
        const v = sent[k];
        if (typeof v === 'boolean') vals[String(k).slice(0, 80)] = v;
        else if (typeof v === 'string') vals[String(k).slice(0, 80)] = v.slice(0, 2000);
      });
      const has = Object.values(vals).some(v => v === true || (typeof v === 'string' && v.trim()));
      if (has) form = { available: true, hasValues: true, values: vals, source: 'browser', count: Object.keys(vals).length };
    }
    if (!form) { form = await readPdfFormValues(buf); form.source = form.hasValues ? 'server' : 'none'; }
    if (form.hasValues) {
      const mapped = mapSiteForm(form.values);
      if (countSiteDetails(mapped) > 0 || mapped.address) { extracted = mapped; readBy = 'form'; }
      const formCo = mapped._company;
      if (formCo && folderNameKey(formCo) && folderNameKey(formCo) !== folderNameKey(company)) {
        warning = `This form is for "${formCo}" but you uploaded it to ${company}. Check it is the right client.`;
      }
    }
    if (!extracted) {
      if (!API_KEY) {
        warning = 'The form could not be read: it has no filled-in fields and the AI key is not set on the server. Enter the details by hand.';
      } else {
        try {
          extracted = await extractSiteInfo(buf, company, siteName);
          readBy = 'ai';
          warning = (warning ? warning + ' ' : '') + 'The typed-in answers could not be read from this PDF, so the AI read the pages instead and may have missed things. Check the details carefully.';
        } catch (e) {
          warning = `The form could not be read (${e.message}). Enter the details by hand.`;
        }
      }
    }
    if (extracted) delete extracted._company;

    let finalName = String(siteName || '').trim();
    if (!finalName && extracted && extracted.address) finalName = String(extracted.address).split(',')[0].trim().slice(0, 40);
    if (!finalName) finalName = 'Main site';

    let file = null;
    let fileError = '';
    try {
      const folders = await ensureClientFolders(company);
      const drive = getUploadDriveClient();
      const driveName = safeFileName(`Site Info ${company} ${finalName}`) + '.pdf';
      const existing = await drive.files.list({
        q: `'${folders.siteInfoId}' in parents and name='${escDriveQuery(driveName)}' and trashed=false`,
        spaces: 'drive', pageSize: 1, fields: 'files(id)',
      });
      const media = { mimeType: 'application/pdf', body: Readable.from([buf]) };
      let saved;
      try {
        if (existing.data.files && existing.data.files.length) {
          saved = await drive.files.update({ fileId: existing.data.files[0].id, media, fields: 'id, name, webViewLink' });
        } else {
          saved = await drive.files.create({ resource: { name: driveName, parents: [folders.siteInfoId] }, media, fields: 'id, name, webViewLink' });
        }
      } catch (e) { throw new Error(friendlyDriveError(e)); }
      file = { id: saved.data.id, name: saved.data.name || driveName, link: saved.data.webViewLink || '' };
      markClientFolders(company).catch(() => {});
    } catch (e) {
      fileError = e.message;
    }
    auditLog(auditActorOf(req), 'site_pdf_uploaded', 'client_site', `${company} - ${siteName || 'Main site'}`, fileError ? 'not saved to Drive' : '');
    res.json({ ok: true, file, fileError, extracted, warning, siteName: finalName, readBy, diag: { source: form.source, fields: form.count || 0, hasValues: !!form.hasValues, serverLib: !!form.available, error: form.error || '' } });
  } catch (e) {
    console.error('POST /api/client-sites/:id/pdf error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// Remove an uploaded site PDF (moves the file to the Drive bin and clears the link on the site)
app.delete('/api/client-sites/:id/pdf', async (req, res) => {
  try {
    const site = (await clientSitesTable.list()).find(o => o.id === req.params.id);
    const fileId = (site && site.pdf_file_id) || String(req.query.fileId || '');
    if (!fileId && !site) return res.status(404).json({ error: 'That site was not found' });
    let trashed = false;
    let driveNote = '';
    if (fileId) {
      try {
        await getUploadDriveClient().files.update({ fileId, requestBody: { trashed: true }, fields: 'id' });
        trashed = true;
      } catch (e) {
        const msg = friendlyDriveError(e);
        if (/not found|404/i.test(String(e && (e.code || e.message)))) trashed = true;
        else driveNote = msg;
      }
    }
    let saved = null;
    if (site) saved = await clientSitesTable.upsert({ ...site, pdf_file_id: '', pdf_link: '', pdf_name: '', updated_by: actorOf(req), updated_at: new Date().toISOString() });
    auditLog(auditActorOf(req), 'site_pdf_removed', 'client_site', site ? `${site.company} - ${site.site_name}` : fileId, driveNote);
    res.json({ ok: true, trashed, driveNote, data: saved });
  } catch (e) {
    console.error('DELETE /api/client-sites/:id/pdf error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// Delete a site completely: its record and its PDF (the PDF goes to the Drive bin)
async function deleteSiteCompletely(site) {
  let trashed = false;
  let note = '';
  if (site.pdf_file_id) {
    try {
      await getUploadDriveClient().files.update({ fileId: site.pdf_file_id, requestBody: { trashed: true }, fields: 'id' });
      trashed = true;
    } catch (e) {
      if (/404|not found/i.test(String((e && (e.code || e.message)) || ''))) trashed = true;
      else note = friendlyDriveError(e);
    }
  }
  await clientSitesTable.remove(site.id);
  return { trashed, note };
}

app.post('/api/client-sites/delete-all', async (req, res) => {
  try {
    const company = String((req.body && req.body.company) || '').trim().toLowerCase();
    if (!company) return res.status(400).json({ error: 'The company is required' });
    const all = (await clientSitesTable.list()).filter(o => String(o.company || '').trim().toLowerCase() === company);
    const notes = [];
    for (const site of all) {
      const r = await deleteSiteCompletely(site);
      if (r.note) notes.push(r.note);
    }
    const left = (await clientSitesTable.list()).filter(o => String(o.company || '').trim().toLowerCase() === company).length;
    auditLog(auditActorOf(req), 'sites_deleted', 'client_site', String((req.body && req.body.company) || ''), `${all.length} sites`);
    if (left) return res.status(500).json({ error: `${left} site(s) could not be removed from the sheet. Try again.` });
    res.json({ ok: true, deleted: all.length, driveNote: notes[0] || '' });
  } catch (e) {
    console.error('POST /api/client-sites/delete-all error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/client-sites/:id/delete', async (req, res) => {
  try {
    const id = req.params.id;
    const site = (await clientSitesTable.list()).find(o => o.id === id);
    if (!site) return res.json({ ok: true, deleted: 0 });
    const r = await deleteSiteCompletely(site);
    const still = (await clientSitesTable.list()).some(o => o.id === id);
    auditLog(auditActorOf(req), 'site_deleted', 'client_site', `${site.company} - ${site.site_name}`, r.note);
    if (still) return res.status(500).json({ error: 'The site could not be removed from the sheet. Try again.' });
    res.json({ ok: true, deleted: 1, trashed: r.trashed, driveNote: r.note });
  } catch (e) {
    console.error('POST /api/client-sites/:id/delete error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- Email signatures ---------------------------------------------------------
// Each person has one signature. The defaults live in assets/signatures/<user key>.html;
// anything saved from the dashboard replaces the default.

const signaturesTable = makeSimpleTable({
  tab: 'Signatures',
  header: ['id', 'html', 'updated_by', 'updated_at'],
  path: null,
  label: 'Signature',
});

function sniffImageMime(b64, declared) {
  const s = String(b64 || '').slice(0, 12);
  if (s.startsWith('/9j/')) return 'image/jpeg';
  if (s.startsWith('iVBOR')) return 'image/png';
  if (s.startsWith('R0lGOD')) return 'image/gif';
  return declared || 'image/png';
}

function parseSignatureHtml(raw) {
  let html = String(raw || '');
  const body = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  if (body) html = body[1];
  html = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/gi, '').trim();
  const images = [];
  html = html.replace(/(<img\b[^>]*?\bsrc=)(["'])data:([a-z]+\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+?)\2/gi, (m, pre, q, mime, data) => {
    const clean = data.replace(/\s+/g, '');
    const cid = `l2hsig${images.length + 1}@live2help`;
    images.push({ cid, mime: sniffImageMime(clean, mime), base64: clean });
    return `${pre}${q}cid:${cid}${q}`;
  });
  return { html, images };
}

function htmlToPlainText(html) {
  return String(html || '')
    .replace(/<img[^>]*>/gi, '')
    .replace(/<\s*br\s*\/?>/gi, '\n')
    .replace(/<\/(tr|p|div|table)>/gi, '\n')
    .replace(/<\/(td|th)>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ').replace(/&middot;/g, '-').replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function signatureKeyFor(req) {
  const asked = String((req.query && req.query.user) || (req.body && req.body.user) || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (asked && asked !== actorOf(req) && isAdmin(req)) return asked;
  return String(actorOf(req)).toLowerCase().replace(/[^a-z0-9-]/g, '');
}

async function loadSignature(key) {
  let raw = '';
  let source = 'none';
  try {
    const hit = (await signaturesTable.list()).find(o => o.id === key);
    if (hit && hit.html) { raw = hit.html; source = 'saved'; }
  } catch (e) { /* fall back to the default file */ }
  if (!raw && key) {
    try {
      raw = fs.readFileSync(path.join(__dirname, 'assets', 'signatures', `${key}.html`), 'utf8');
      source = 'default';
    } catch (e) { raw = ''; }
  }
  if (!raw) return { html: '', images: [], text: '', source: 'none' };
  const parsed = parseSignatureHtml(raw);
  return { ...parsed, text: htmlToPlainText(parsed.html), source };
}

app.get('/api/signature', async (req, res) => {
  try {
    res.json(await loadSignature(signatureKeyFor(req)));
  } catch (e) {
    console.error('GET /api/signature error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/signature', async (req, res) => {
  try {
    const key = signatureKeyFor(req);
    const html = String((req.body && req.body.html) || '').trim();
    if (!key) return res.status(400).json({ error: 'Could not tell whose signature this is' });
    if (!html) return res.status(400).json({ error: 'Paste the signature HTML first' });
    if (html.length > 45000) return res.status(400).json({ error: 'That signature is too large to store (over 45,000 characters). Use a smaller logo image.' });
    if (!/<(table|div|p|span|img|a|br)\b/i.test(html)) return res.status(400).json({ error: 'That does not look like signature HTML' });
    await signaturesTable.upsert({ id: key, html, updated_by: actorOf(req), updated_at: new Date().toISOString() });
    auditLog(auditActorOf(req), 'signature_saved', 'signature', key, '');
    res.json({ ok: true, ...(await loadSignature(key)) });
  } catch (e) {
    console.error('PUT /api/signature error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Go back to the default signature file
app.delete('/api/signature', async (req, res) => {
  try {
    const key = signatureKeyFor(req);
    await signaturesTable.remove(key);
    res.json({ ok: true, ...(await loadSignature(key)) });
  } catch (e) {
    console.error('DELETE /api/signature error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---- Interview packs -------------------------------------------------------------

const interviewPackDraftsTable = makeSimpleTable({
  tab: 'Interview Packs',
  header: [
    'id', 'interview_id', 'candidate_id', 'candidate_name', 'role', 'company', 'site_id',
    'status', 'pack_json', 'created_by', 'created_at', 'approved_at', 'sent_at',
  ],
  path: '/api/interview-pack-drafts',
  label: 'Interview pack',
  auditType: 'interview_pack',
  auditName: o => `${o.candidate_name} - ${o.role}`,
});

const PACK_SYSTEM = `You write interview preparation packs for Live 2 Help Recruitment, a UK recruitment agency. The pack goes to the CANDIDATE, so it speaks to them directly as "you". The tone is warm, encouraging and practical, like a consultant who has done the homework and is in their corner.

HOUSE RULES
- British English. Confident and supportive, never gushing. Be specific, never generic.
- Use ONLY facts in the material supplied (the candidate's CV, application answers, call notes, the submission the client has seen, the role brief and the company notes). Never invent employers, dates, figures, qualifications, projects, or anything about the company or the interviewer.
- If the company overview is thin, write a short "about_company" from what is supplied and add a plain-English line to "gaps" saying what the recruiter should add. Never write company facts from memory.
- Say nothing about the interviewer's personality or interview style unless it is in the material. If the interviewer is only a name and title, say who they are and what they are likely to want to see in this role, based on the role brief, and add a gap.
- Never mention salary negotiation, other applicants, or anything about the client's view of the candidate beyond what is in the submission.
- Never use em dashes or en dashes. Use a plain hyphen with spaces (" - ") for a break in a sentence.
- ${MARKUP_HELP}

STRUCTURE
1. about_company: two or three short paragraphs on the company and why the role exists, from the material only.
2. meeting_summary: who they will be meeting and what that person will want to see, in two short paragraphs.
3. interview_format: how the interview is likely to run (face to face, phone or video) and what to expect, in one or two short paragraphs. Only claim a competency-based format if the material says so.
4. questions: six to eight competency questions tailored to the role's stated requirements and this candidate's real background. For each: the question; "points" as three or four bullet lines telling the candidate which of THEIR real examples to use (name the employer, system or project from their CV or answers) and how to structure it, including the result to finish on; and "tip" as one or two sentences of practical coaching. Where the candidate has a genuine gap against a requirement, include an honest question on it and coach them to answer truthfully and confidently, never to overclaim.
5. questions_to_ask: four or five thoughtful questions the candidate could ask the interviewer, specific to the role.
6. gaps: anything the recruiter should check or add before sending. Empty array if none.

ROUNDS AND FORMAT
- The material states which interview round this is and its format (face to face, video or phone). Write interview_format for THAT format only: for video include joining and technology tips, for phone include call etiquette and preparing a quiet space, for face to face cover arrival and conduct on the day.
- For a second or later round, use the notes from earlier rounds (if supplied) to build on what has already happened. Do not repeat the basics the candidate already covered. Never invent what was said in an earlier round.`;

const PACK_TOOL = {
  name: 'submit_interview_pack',
  description: 'Return the finished interview preparation pack content.',
  input_schema: {
    type: 'object',
    properties: {
      about_company: { type: 'string' },
      meeting_summary: { type: 'string' },
      interview_format: { type: 'string' },
      questions: {
        type: 'array',
        items: {
          type: 'object',
          properties: { question: { type: 'string' }, points: { type: 'string', description: 'Bullet lines (markup)' }, tip: { type: 'string' } },
          required: ['question', 'points', 'tip'],
        },
      },
      questions_to_ask: { type: 'array', items: { type: 'string' } },
      gaps: { type: 'array', items: { type: 'string' } },
    },
    required: ['about_company', 'meeting_summary', 'interview_format', 'questions', 'questions_to_ask', 'gaps'],
  },
};

app.post('/api/interview-packs/generate', async (req, res) => {
  try {
    const b = req.body || {};
    const { name, role, company } = b;
    if (!name || !role) return res.status(400).json({ error: 'name and role are required' });
    if (!API_KEY) return res.status(500).json({ error: 'The AI key is not set on the server' });

    const [cvFile, screen, brief] = await Promise.all([
      loadCvFile(company, name, role).catch(() => null),
      loadScreening(name, role),
      loadRoleBrief(role),
    ]);
    let cvDoc = null;
    const gapsFromSources = [];
    if (cvFile && (cvFile.kind === 'pdf' || cvFile.kind === 'docx' || cvFile.kind === 'gdoc')) {
      const dl = await downloadCv(cvFile);
      cvDoc = { kind: dl.kind, buffer: dl.buffer, text: dl.kind === 'docx' ? docxToText(dl.buffer) : '' };
    } else {
      gapsFromSources.push('No readable CV was on file, so the pack is built from the application answers, the submission and any call notes.');
    }
    if (!screen.found) gapsFromSources.push('No application form answers were found for this candidate.');
    if (!brief.requirements && !brief.jobDescription) gapsFromSources.push('No role brief is on file for this role, so the questions are based on the general themes of the role.');

    let submissionText = '';
    try {
      const drafts = (await submissionDraftsTable.list())
        .filter(o => o.submission_json && String(o.role).toLowerCase() === String(role).toLowerCase() &&
          candidateRef(o.candidate_name).toLowerCase() === candidateRef(name).toLowerCase())
        .sort((a, c) => String(c.created_at).localeCompare(String(a.created_at)));
      if (drafts[0]) {
        const s = JSON.parse(drafts[0].submission_json);
        submissionText = [
          s.profile ? `Profile: ${s.profile}` : '',
          ...(s.fit || []).map(f => `Requirement: ${f.requirement} | Evidence: ${f.evidence}`),
          s.motivation ? `Motivation: ${s.motivation}` : '',
        ].filter(Boolean).join('\n').slice(0, 9000);
      }
    } catch (e) { /* the pack can be built without it */ }

    const context = [
      `ROLE: ${role}${company ? ` at ${company}` : ''}`,
      `CANDIDATE (address them as "you"; use their first name only in the closing): ${screen.fullName || name}`,
      `INTERVIEW ROUND: ${String(b.roundLabel || '').trim() || 'Not stated'}`,
      `NOTES FROM EARLIER INTERVIEW ROUNDS AND CLIENT FEEDBACK:\n${String(b.previousRounds || '').trim().slice(0, 6000) || 'None - this is the first round or nothing has been recorded.'}`,
      `INTERVIEW: ${[b.typeLabel, b.interviewer ? `with ${b.interviewer}${b.interviewerTitle ? `, ${b.interviewerTitle}` : ''}` : ''].filter(Boolean).join(' ') || 'Details to be confirmed'}`,
      `COMPANY NOTES FROM THE RECRUITER:\n${String(b.companyOverview || '').trim() || 'None provided.'}`,
      `ROLE REQUIREMENTS:\n${brief.requirements || 'NONE PROVIDED'}`,
      `JOB DESCRIPTION:\n${brief.jobDescription ? brief.jobDescription.slice(0, 14000) : 'NONE PROVIDED'}`,
      `APPLICATION ANSWERS:\n${screeningText(screen)}`,
      `THE SUBMISSION THE CLIENT HAS ALREADY SEEN:\n${submissionText || 'Not available.'}`,
      `RECRUITER NOTES ON THE CANDIDATE CARD:\n${[b.cardNotes, screen.recruiterNotes].map(s => String(s || '').trim()).filter(Boolean).join('\n') || 'None.'}`,
      `NOTES FROM THE RECRUITER'S CALLS WITH THE CANDIDATE:\n${String(b.callNotes || '').trim() || 'None provided.'}`,
    ].join('\n\n');

    const content = [{ type: 'text', text: context }, ...(cvDoc ? cvBlocks(cvDoc) : [])];
    const out = await callClaudeTool({ system: PACK_SYSTEM, content, tool: PACK_TOOL, maxTokens: 7000 });
    const cleaned = scrubIdentifiers(cleanDeep(out), { fullName: '', emails: [screen.email], phones: [screen.phone], keepFirstName: true }).value;
    cleaned.gaps = [...gapsFromSources, ...(Array.isArray(cleaned.gaps) ? cleaned.gaps : [])].filter(Boolean);
    auditLog(auditActorOf(req), 'interview_pack_generated', 'interview_pack', `${name} - ${role}`, '');
    res.json({ pack: cleaned });
  } catch (e) {
    console.error('POST /api/interview-packs/generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

function packFileNames(pack) {
  const ref = candidateRef(pack.candidate_name || pack.candidate_ref || '');
  return {
    interview: safeFileName(`${ref} Interview Prep ${pack.role_title || 'Role'}${(parseInt(pack.round_no, 10) || 0) > 1 ? ' ' + (pack.round_label || 'Round ' + pack.round_no) : ''}`) + '.docx',
    site: safeFileName(`${ref} Site Pack ${pack.company || 'Client'}`) + '.docx',
  };
}

function packHasSite(pack) {
  const s = pack && pack.site;
  if (!s) return false;
  return !!(s.address || Object.values(s.fields || {}).some(v => String(v || '').trim()));
}

app.post('/api/interview-packs/docx', async (req, res) => {
  try {
    const { pack } = req.body || {};
    if (!pack) return res.status(400).json({ error: 'pack is required' });
    const clean = cleanDeep(pack);
    const names = packFileNames(clean);
    const files = [{ kind: 'interview_pack', fileName: names.interview, base64: (await buildDocx('interview_pack', clean, { role: clean.role_title })).toString('base64') }];
    if (packHasSite(clean)) {
      files.push({ kind: 'site_pack', fileName: names.site, base64: (await buildDocx('site_pack', clean, { role: clean.role_title })).toString('base64') });
    }
    res.json({ files });
  } catch (e) {
    console.error('POST /api/interview-packs/docx error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Filed in the candidate's Drive folder once the email has been built
app.post('/api/interview-packs/archive', async (req, res) => {
  try {
    const { pack } = req.body || {};
    if (!pack) return res.status(400).json({ error: 'pack is required' });
    const clean = cleanDeep(pack);
    const folderId = await resolveCandidateCvFolder(clean.company, clean.candidate_name);
    const drive = getUploadDriveClient();
    const names = packFileNames(clean);
    const saved = [];
    const put = async (fileName, buffer) => {
      const existing = await drive.files.list({
        q: `'${folderId}' in parents and name='${escDriveQuery(fileName)}' and trashed=false`,
        spaces: 'drive', pageSize: 1, fields: 'files(id)',
      });
      const media = { mimeType: DOCX_MIME, body: Readable.from([buffer]) };
      let file;
      try {
        if (existing.data.files && existing.data.files.length) {
          file = await drive.files.update({ fileId: existing.data.files[0].id, media, fields: 'id, name, webViewLink' });
        } else {
          file = await drive.files.create({ resource: { name: fileName, parents: [folderId] }, media, fields: 'id, name, webViewLink' });
        }
      } catch (e) { throw new Error(friendlyDriveError(e)); }
      saved.push({ name: fileName, link: file.data.webViewLink || '' });
    };
    await put(names.interview, await buildDocx('interview_pack', clean, { role: clean.role_title }));
    if (packHasSite(clean)) await put(names.site, await buildDocx('site_pack', clean, { role: clean.role_title }));
    res.json({ ok: true, files: saved });
  } catch (e) {
    console.error('POST /api/interview-packs/archive error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;

/* ---------- Careers page: public roles, form check, careers text ----------
   Only roles that are Open AND ticked "Show on careers page" are ever returned, and only
   safe fields: no client name, fee, contact, notes or internal role name. */

const CAREERS_BASE = (process.env.CAREERS_BASE_URL || 'https://careers.live2helprecruitment.co.uk').replace(/\/+$/, '');

// Town or city used to group roles on the careers page: "Stoke-on-Trent, Staffordshire ST4" becomes "Stoke-on-Trent"
function careersLocationGroup(loc) {
  let t = String(loc || '').replace(/\([^)]*\)/g, ' ').replace(/\b[A-Z]{1,2}\d[A-Z\d]?\s*\d?[A-Z]{0,2}\b/g, ' ').trim();
  t = t.split(/[,\/|-]\s+|\s+-\s+|,/)[0].replace(/\b(uk|united kingdom|england)\b/ig, '').replace(/\s+/g, ' ').trim();
  if (!t) return '';
  if (/^(remote|work from home|wfh|home ?based)$/i.test(t)) return 'Remote';
  return t.split(' ').map(w => (w.includes('-') ? w.split('-').map(x => (['on', 'upon', 'under', 'le', 'de', 'the'].includes(x.toLowerCase()) ? x.toLowerCase() : titleCase(x.toLowerCase()))).join('-') : titleCase(w.toLowerCase()))).join(' ');
}

function slugifyRole(s) {
  return String(s || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

const formExistsCache = new Map();
async function careersFormExists(slug) {
  slug = String(slug || '').trim().toLowerCase();
  if (!/^[a-z0-9-]+$/.test(slug)) return false;
  const hit = formExistsCache.get(slug);
  if (hit && Date.now() - hit.at < (hit.ok ? 5 * 60 * 1000 : 60 * 1000)) return hit.ok;
  let ok = false;
  try {
    const r = await fetch(`${CAREERS_BASE}/apply/${slug}/`, { redirect: 'follow', signal: AbortSignal.timeout(6000) });
    if (r.ok) {
      const body = await r.text();
      ok = /<form[\s>]/i.test(body);
    }
  } catch (e) { ok = false; }
  formExistsCache.set(slug, { ok, at: Date.now() });
  return ok;
}

app.get('/api/forms/check', async (req, res) => {
  try {
    const slug = slugifyRole(req.query.slug || '');
    if (!slug) return res.json({ slug: '', exists: false });
    res.json({ slug, exists: await careersFormExists(slug) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Careers text is stored as simple markup so it is easy to edit in the dashboard:
//   SUMMARY: one or two sentences
//   ## Heading
//   a paragraph
//   - a bullet
function parseCareersText(text) {
  const out = { summary: '', sections: [] };
  let cur = null;
  String(text || '').split(/\r?\n/).forEach(raw => {
    const line = raw.trim();
    if (!line) return;
    const sm = line.match(/^SUMMARY:\s*(.*)$/i);
    if (sm) { out.summary = sm[1].trim(); return; }
    if (line.startsWith('## ')) { cur = { heading: line.slice(3).trim(), paragraphs: [], bullets: [] }; out.sections.push(cur); return; }
    if (!cur) { cur = { heading: '', paragraphs: [], bullets: [] }; out.sections.push(cur); }
    if (line.startsWith('- ')) cur.bullets.push(line.slice(2).trim());
    else cur.paragraphs.push(line);
  });
  return out;
}

let publicRolesCache = { at: 0, list: null };
async function buildPublicRoles() {
  if (publicRolesCache.list && Date.now() - publicRolesCache.at < 60 * 1000) return publicRolesCache.list;
  const roles = await rolesTable.list();
  const seen = new Set();
  const out = [];
  for (const r of roles) {
    const shown = ['yes', 'true', '1'].includes(String(r.show_on_careers || '').trim().toLowerCase());
    if (!shown || String(r.status || 'open').trim().toLowerCase() !== 'open') continue;
    const content = parseCareersText(r.public_content);
    if (!content.summary && !content.sections.length) continue; // not ready to publish
    const title = String(r.public_title || r.role || '').trim();
    if (!title) continue;
    const formSlug = slugifyRole(r.form_slug || title);
    const key = `${title.toLowerCase()}|${formSlug}`;
    if (seen.has(key)) continue; // two open vacancies with one public listing: show it once
    seen.add(key);
    const hasForm = await careersFormExists(formSlug);
    out.push({
      slug: slugifyRole(title),
      title,
      location: String(r.location || '').trim(),
      locationGroup: careersLocationGroup(r.location) || 'Other locations',
      salary: String(r.salary_band || '').trim(),
      summary: content.summary,
      sections: content.sections,
      posted: String(r.date_opened || '').slice(0, 10),
      applyUrl: hasForm ? `${CAREERS_BASE}/apply/${formSlug}/` : '',
    });
  }
  out.sort((a, b) => String(b.posted).localeCompare(String(a.posted)));
  publicRolesCache = { at: Date.now(), list: out };
  return out;
}

app.get('/api/public/roles', async (req, res) => {
  try {
    const list = await buildPublicRoles();
    res.set('Cache-Control', 'public, max-age=60');
    const roles = list.map(r => ({ ...r, sections: undefined }));
    const byLoc = new Map();
    roles.forEach(r => { if (!byLoc.has(r.locationGroup)) byLoc.set(r.locationGroup, []); byLoc.get(r.locationGroup).push(r); });
    const groups = [...byLoc.entries()]
      .sort((a, b) => (a[0] === 'Other locations') - (b[0] === 'Other locations') || a[0].localeCompare(b[0]))
      .map(([location, rs]) => ({ location, count: rs.length, roles: rs }));
    res.json({ updated_at: new Date().toISOString(), roles, groups, locations: groups.map(g => g.location) });
  } catch (e) { console.error('GET /api/public/roles error:', e.message); res.status(500).json({ error: 'Could not load roles' }); }
});

app.get('/api/public/roles/:slug', async (req, res) => {
  try {
    const hit = (await buildPublicRoles()).find(r => r.slug === req.params.slug);
    if (!hit) return res.status(404).json({ error: 'Role not found' });
    res.set('Cache-Control', 'public, max-age=60');
    res.json({ role: hit });
  } catch (e) { console.error('GET /api/public/roles/:slug error:', e.message); res.status(500).json({ error: 'Could not load role' }); }
});

// Draft the public careers text from the job description and requirements.
// Staff review and edit it in the dashboard before it goes live.
const CAREERS_TEXT_TOOL = {
  name: 'write_careers_page',
  description: 'Write the public careers page text for a vacancy.',
  input_schema: {
    type: 'object',
    properties: {
      summary: { type: 'string', description: 'One or two sentence teaser, 220 characters or fewer.' },
      overview: { type: 'string', description: 'Two to four sentence overview of the role.' },
      responsibilities: { type: 'array', items: { type: 'string' }, description: 'What the person will do. Short bullet points.' },
      requirements: { type: 'array', items: { type: 'string' }, description: 'What the employer is looking for. Short bullet points.' },
      offer: { type: 'array', items: { type: 'string' }, description: 'Package, training and benefits that are stated in the material. Leave empty if none are stated.' },
    },
    required: ['summary', 'overview', 'responsibilities', 'requirements', 'offer'],
  },
};

const CAREERS_TEXT_SYSTEM = `You write public job advert text for Live 2 Help Recruitment, a UK recruitment agency, for its careers page.
Rules:
- Use ONLY facts in the material supplied. Never invent duties, benefits, salary, locations or requirements.
- Do NOT name the client company, its group, its brands, its parent, or any person at the client. Refer to "our client" or "the business" instead. Remove internal notes, fees and anything confidential.
- UK English, professional and engaging, confident without overselling. Do not use em dashes; use a hyphen or rewrite the sentence.
- Do not repeat the salary figure in the text unless it is part of a stated incentive or bonus, as the salary is shown separately.
- Bullets are short and specific. Merge duplicates. Skip a bullet rather than guess.`;

app.post('/api/careers/generate', async (req, res) => {
  try {
    const b = req.body || {};
    const material = [
      `PUBLIC JOB TITLE: ${String(b.title || b.role || '').trim()}`,
      b.location ? `LOCATION: ${String(b.location).trim()}` : '',
      b.salary_band ? `SALARY (shown separately): ${String(b.salary_band).trim()}` : '',
      `KEY REQUIREMENTS:\n${String(b.requirements || '').trim() || 'None given.'}`,
      `JOB DESCRIPTION:\n${String(b.job_description || '').trim() || 'None given.'}`,
    ].filter(Boolean).join('\n\n').slice(0, 40000);
    if (!String(b.requirements || '').trim() && !String(b.job_description || '').trim()) {
      return res.status(400).json({ error: 'Add the job description or key requirements first' });
    }
    const out = await callClaudeTool({ system: CAREERS_TEXT_SYSTEM, content: material, tool: CAREERS_TEXT_TOOL, maxTokens: 2000 });
    const clean = v => String(v || '').replace(/[\u2014\u2013]/g, '-').trim();
    const list = a => (Array.isArray(a) ? a : []).map(clean).filter(Boolean);
    const lines = [`SUMMARY: ${clean(out.summary)}`];
    if (clean(out.overview)) lines.push('## About the role', clean(out.overview));
    if (list(out.responsibilities).length) lines.push('## What you will do', ...list(out.responsibilities).map(x => `- ${x}`));
    if (list(out.requirements).length) lines.push('## What we are looking for', ...list(out.requirements).map(x => `- ${x}`));
    if (list(out.offer).length) lines.push('## What is on offer', ...list(out.offer).map(x => `- ${x}`));
    res.json({ text: lines.join('\n') });
  } catch (e) {
    console.error('POST /api/careers/generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});



/* ======================================================================
   AUTOMATION BATCH A
   Health and keep-alive, nightly backups, accurate KPI engine, quarterly
   history, stage-driven tasks, invoice chasing, application acknowledgement,
   Monday digest and one daily cron that runs the lot.

   Scheduling uses a free GitHub Actions workflow (.github/workflows/l2h-automation.yml),
   which calls these with the CRON_SECRET environment variable on Render:
     /api/cron/daily?key=SECRET          once a day, early morning
     /api/check-invoice-reminders?key=SECRET  once a day
     /api/cron/weekly-digest?key=SECRET  Mondays
   The server pings its own /api/health every 10 minutes to stay awake on Render.
   ====================================================================== */

const FILLED_STAGES = ['offer', 'start_date', 'day1', 'week1', 'month1'];
const BACKUP_FOLDER_NAME = 'L2H Backups';
const BACKUP_KEEP = 14;

function slugKey(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''); }
function todayISO() { return toISODate(new Date()); }
function lc(s) { return String(s || '').trim().toLowerCase(); }
function isTestRecord(name, notes) {
  return /^\s*test\b/i.test(String(name || '')) || /\[test\]/i.test(String(notes || ''));
}
function parseISODate(s) {
  const m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  const m2 = String(s || '').match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m2) return new Date(Date.UTC(+m2[3], +m2[2] - 1, +m2[1]));
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}
function daysBetween(a, b) { return Math.round((b.getTime() - a.getTime()) / 86400000); }
function clampFuture(iso) { const t = todayISO(); return iso && iso > t ? iso : t; }

/* ---------- Alerts ---------- */
const alertSeen = new Map();
function dansInbox() { return process.env.REMINDER_EMAIL_TO || process.env.BREVO_SENDER_EMAIL; }
async function mailDan(subject, text) {
  try {
    await emailTransporter.sendMail({ from: process.env.BREVO_SENDER_EMAIL, to: dansInbox(), subject, text });
    return true;
  } catch (e) { console.error('mailDan failed:', e.message); return false; }
}
async function alertDan(kind, subject, text) {
  const last = alertSeen.get(kind) || 0;
  if (Date.now() - last < 6 * 3600 * 1000) return false;
  alertSeen.set(kind, Date.now());
  return mailDan(subject, text);
}

/* ---------- Health and keep-alive ---------- */
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

if (process.env.RENDER_EXTERNAL_URL) {
  setInterval(() => {
    fetch(process.env.RENDER_EXTERNAL_URL.replace(/\/$/, '') + '/api/health').catch(() => {});
  }, 10 * 60 * 1000);
}

function cronAuthorised(req) {
  const secret = process.env.CRON_SECRET;
  if (secret && cronKeyOf(req) === secret) return true;
  return isAdmin(req);
}
function cronOnly(req, res, next) {
  if (!cronAuthorised(req)) return res.status(403).json({ error: 'Not allowed' });
  next();
}

async function deepHealthCheck() {
  const out = {};
  const sheets = getSheetsClient();
  for (const [label, id] of [['candidateSheet', SHEET_ID], ['clientSheet', CLIENT_SHEET_ID]]) {
    try { await sheets.spreadsheets.get({ spreadsheetId: id, fields: 'properties.title' }); out[label] = 'ok'; }
    catch (e) { out[label] = 'FAIL: ' + e.message; }
  }
  try { await getDriveClient().files.list({ pageSize: 1, fields: 'files(id)' }); out.drive = 'ok'; }
  catch (e) { out.drive = 'FAIL: ' + e.message; }
  try { await getUploadDriveClient().about.get({ fields: 'user' }); out.driveUploads = 'ok'; }
  catch (e) { out.driveUploads = 'FAIL: ' + friendlyDriveError(e); }
  try { await emailTransporter.verify(); out.email = 'ok'; }
  catch (e) { out.email = 'FAIL: ' + e.message; }
  const fails = Object.entries(out).filter(([, v]) => String(v).startsWith('FAIL'));
  if (fails.length) {
    await alertDan('health:' + fails.map(f => f[0]).sort().join(','),
      'Live 2 Help dashboard: a connection needs attention',
      'The daily health check found a problem:\n\n' + fails.map(([k, v]) => `- ${k}: ${v}`).join('\n') +
      '\n\nUploads and CV saving depend on driveUploads. If that one fails the Google refresh token needs regenerating.\n\nLive 2 Help dashboard');
  }
  return out;
}

app.get('/api/cron/health-check', cronOnly, async (req, res) => {
  try { res.json(await deepHealthCheck()); } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- Backups ---------- */
async function findOrCreateBackupFolder(drive) {
  const q = `name='${BACKUP_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false and 'root' in parents`;
  const r = await drive.files.list({ q, fields: 'files(id,name)', pageSize: 1 });
  if (r.data.files && r.data.files[0]) return r.data.files[0].id;
  const c = await drive.files.create({ requestBody: { name: BACKUP_FOLDER_NAME, mimeType: 'application/vnd.google-apps.folder' }, fields: 'id' });
  return c.data.id;
}

async function exportBackupCopy(fileId, name, folderId, uploadDrive) {
  // Fallback: the service account (which can read both sheets) exports an .xlsx copy,
  // and the upload sign-in saves it. Needs no permission over the original sheet.
  const svc = getDriveClient();
  const xlsx = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  const r = await svc.files.export({ fileId, mimeType: xlsx }, { responseType: 'arraybuffer' });
  const buffer = Buffer.from(r.data);
  await uploadDrive.files.create({
    requestBody: { name: name + '.xlsx', parents: [folderId] },
    media: { mimeType: xlsx, body: Readable.from([buffer]) },
    fields: 'id',
  });
}

async function runBackup() {
  const drive = getUploadDriveClient();
  const folderId = await findOrCreateBackupFolder(drive);
  const date = todayISO();
  const targets = [['Candidate Tracking', SHEET_ID], ['Clients and Contacts', CLIENT_SHEET_ID]];
  const made = [];
  const methods = {};
  for (const [label, fileId] of targets) {
    const name = `${label} backup ${date}`;
    const existing = await drive.files.list({ q: `'${folderId}' in parents and (name='${name}' or name='${name}.xlsx') and trashed=false`, fields: 'files(id)', pageSize: 1 });
    if (!(existing.data.files && existing.data.files.length)) {
      try {
        await drive.files.copy({ fileId, requestBody: { name, parents: [folderId] }, fields: 'id' });
        methods[label] = 'copy';
      } catch (e) {
        console.warn('Backup copy failed for ' + label + ', trying export:', e.message);
        try {
          await exportBackupCopy(fileId, name, folderId, drive);
          methods[label] = 'export (copy failed: ' + String(e.message).slice(0, 120) + ')';
        } catch (e2) {
          throw new Error(`${label}: copy failed (${e.message}); export failed (${e2.message})`);
        }
      }
      made.push(name);
    }
    // Keep the newest BACKUP_KEEP copies of each sheet; older ones go to the Drive bin (not permanently deleted)
    const all = await drive.files.list({
      q: `'${folderId}' in parents and name contains '${label} backup' and trashed=false`,
      orderBy: 'createdTime desc', fields: 'files(id,name)', pageSize: 100,
    });
    for (const f of (all.data.files || []).slice(BACKUP_KEEP)) {
      await drive.files.update({ fileId: f.id, requestBody: { trashed: true } });
    }
  }
  const status = { at: new Date().toISOString(), ok: true, made, methods, folderId };
  await settingsTable.upsert({ id: 'backup_last', value: JSON.stringify(status), updated_by: 'system' });
  return status;
}

async function safeBackup() {
  try { return await runBackup(); }
  catch (e) {
    const status = { at: new Date().toISOString(), ok: false, error: friendlyDriveError(e), detail: String((e && e.message) || e).slice(0, 600) };
    try { await settingsTable.upsert({ id: 'backup_last', value: JSON.stringify(status), updated_by: 'system' }); } catch (x) { /* ignore */ }
    await alertDan('backup', 'Live 2 Help dashboard: backup failed', `The nightly backup did not complete.\n\nReason: ${status.error}\n\nDetail: ${status.detail || ''}\n\nLive 2 Help dashboard`);
    return status;
  }
}

// Background jobs: the call returns at once ("started") so a sleeping or slow server can never
// make the scheduler time out. The result is stored and read back from /api/cron/status.
const cronRunning = {};
async function runCronJob(name, fn) {
  if (cronRunning[name]) return { started: false, running: true };
  cronRunning[name] = true;
  const startedAt = new Date().toISOString();
  try { await settingsTable.upsert({ id: 'cron_' + name, value: JSON.stringify({ startedAt, running: true }), updated_by: 'system' }); } catch (e) { /* not essential */ }
  fn().then(async result => {
    const failed = result && typeof result === 'object' && (result.ok === false || Object.values(result).some(v => typeof v === 'string' && v.startsWith('FAIL')));
    try { await settingsTable.upsert({ id: 'cron_' + name, value: JSON.stringify({ startedAt, finishedAt: new Date().toISOString(), running: false, ok: !failed, result }).slice(0, 45000), updated_by: 'system' }); } catch (e) { /* not essential */ }
  }).catch(async e => {
    try { await settingsTable.upsert({ id: 'cron_' + name, value: JSON.stringify({ startedAt, finishedAt: new Date().toISOString(), running: false, ok: false, error: e.message }), updated_by: 'system' }); } catch (x) { /* not essential */ }
    await alertDan('cron:' + name, `Live 2 Help dashboard: ${name} job failed`, e.message);
  }).finally(() => { cronRunning[name] = false; });
  return { started: true, startedAt };
}

app.get('/api/cron/backup', cronOnly, async (req, res) => {
  if (req.query.wait === '1') return res.json(await safeBackup());
  res.json(await runCronJob('backup', safeBackup));
});
app.get('/api/cron/status', cronOnly, async (req, res) => {
  try {
    const rows = await settingsTable.list();
    const get = id => { const r = rows.find(o => o.id === id); if (!r) return null; try { return JSON.parse(r.value); } catch (e) { return null; } };
    res.json({ now: new Date().toISOString(), build: SERVER_BUILD, backup: get('backup_last'), backupJob: get('cron_backup'), daily: get('cron_daily') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/backup/run', requireAdmin, async (req, res) => {
  const s = await safeBackup();
  auditLog(auditActorOf(req), 'backup_run', 'backup', s.ok ? 'ok' : 'failed', s.error || '');
  res.status(s.ok ? 200 : 500).json(s);
});
app.get('/api/backup/status', requireAdmin, async (req, res) => {
  try {
    const row = (await settingsTable.list()).find(o => o.id === 'backup_last');
    res.json(row ? JSON.parse(row.value) : { ok: null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- KPI engine (replaces the old placeholder maths) ---------- */
function quarterBounds(label) {
  const m = String(label || '').match(/Q([1-4])\s*(\d{4})/i);
  if (!m) return null;
  const q = +m[1], y = +m[2];
  return { label: `Q${q} ${y}`, start: new Date(Date.UTC(y, (q - 1) * 3, 1)), end: new Date(Date.UTC(y, q * 3, 1)) };
}
function quarterLabelOf(d) { return `Q${Math.floor(d.getUTCMonth() / 3) + 1} ${d.getUTCFullYear()}`; }

async function loadKpiContext() {
  const [rows, roles, audit, clientRows] = await Promise.all([
    readAllRows(),
    rolesTable.list().catch(() => []),
    auditTable.list().catch(() => []),
    getSheetsClient().spreadsheets.values.get({ spreadsheetId: CLIENT_SHEET_ID, range: 'Dashboard!A2:J' }).then(r => r.data.values || []).catch(() => []),
  ]);
  // First time each candidate reached Offer, from the audit trail
  const offerAt = new Map();
  audit.filter(a => a.action === 'stage_changed' && /\sto\soffer$/i.test(a.detail || '')).forEach(a => {
    const k = lc(a.entity);
    const t = parseISODate(a.timestamp);
    if (t && (!offerAt.has(k) || t < offerAt.get(k))) offerAt.set(k, t);
  });
  const cands = rows.filter(r => r && r[0]).map(rowToCandidate).filter(c => !isTestRecord(c.name, c.notes));
  cands.forEach(c => {
    c.offerDate = offerAt.get(lc(`${c.name} - ${c.role}`)) || parseISODate(c.date);
    const role = roles.find(r => lc(r.company) === lc(c.company) && lc(r.role) === lc(c.role));
    c.roleOpened = role ? parseISODate(role.date_opened) : null;
  });
  const firstSeen = new Map();
  clientRows.forEach(r => {
    const co = lc(r[1]); const t = parseISODate(r[0]);
    if (co && t && (!firstSeen.has(co) || t < firstSeen.get(co).t)) firstSeen.set(co, { t, name: r[1] });
  });
  return { cands, roles, firstSeen };
}

function kpiForRange(ctx, start, end) {
  const filled = ctx.cands.filter(c => FILLED_STAGES.includes(normStage(c.stage)) && c.offerDate && c.offerDate >= start && c.offerDate < end);
  const speeds = filled.filter(c => c.roleOpened).map(c => Math.max(0, daysBetween(c.roleOpened, c.offerDate)));
  const newClients = [...ctx.firstSeen.values()].filter(v => v.t >= start && v.t < end).length;
  return {
    rolesFilled: filled.length,
    newClients,
    avgFillSpeedDays: speeds.length ? Math.round((speeds.reduce((a, b) => a + b, 0) / speeds.length) * 10) / 10 : 0,
    filledNames: filled.map(c => `${c.name} (${c.company})`),
  };
}

app.get('/api/metrics/progress', async (req, res) => {
  try {
    const ctx = await loadKpiContext();
    const b = quarterBounds(quarterLabelOf(new Date()));
    const k = kpiForRange(ctx, b.start, b.end);
    res.json({
      rolesFilledThisQuarter: k.rolesFilled,
      newClientsThisQuarter: k.newClients,
      avgFillSpeedDays: k.avgFillSpeedDays.toFixed(1),
    });
  } catch (e) {
    console.error('GET /api/metrics/progress error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/metrics/quarters', requireAdmin, async (req, res) => {
  try {
    const count = Math.min(Math.max(parseInt(req.query.count, 10) || 6, 1), 12);
    const ctx = await loadKpiContext();
    const targets = (await readKPITargetRows()).filter(r => r && r[0]).map(rowToKPITarget);
    const now = new Date();
    let y = now.getUTCFullYear(), q = Math.floor(now.getUTCMonth() / 3) + 1;
    const out = [];
    for (let i = 0; i < count; i++) {
      const b = quarterBounds(`Q${q} ${y}`);
      const k = kpiForRange(ctx, b.start, b.end);
      const t = targets.find(x => quarterBounds(x.quarter) && quarterBounds(x.quarter).label === b.label && !x.owner) || null;
      out.push({ quarter: b.label, current: i === 0, target: t, actual: k });
      q--; if (q === 0) { q = 4; y--; }
    }
    res.json({ data: out });
  } catch (e) {
    console.error('GET /api/metrics/quarters error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/metrics/business-health', async (req, res) => {
  try {
    const year = req.query.year ? parseInt(req.query.year, 10) : new Date().getFullYear();
    const yStart = new Date(Date.UTC(year, 0, 1)), yEnd = new Date(Date.UTC(year + 1, 0, 1));
    const now = new Date();
    const invoices = (await readInvoiceRows()).filter(r => r && r[0]).map(rowToInvoice);

    let ytdRevenue = 0, invoicePaid = 0, invoicePending = 0, invoiceOverdue = 0, invoiceCount = 0;
    const revenueBy = new Map();
    invoices.forEach(inv => {
      const d = parseISODate(inv.date);
      const inYear = d && d >= yStart && d < yEnd;
      if (inYear) {
        ytdRevenue += inv.amount; invoiceCount++;
        revenueBy.set(lc(inv.company), (revenueBy.get(lc(inv.company)) || 0) + inv.amount);
      }
      if (lc(inv.status) === 'paid') { if (inYear) invoicePaid += inv.amount; }
      else {
        invoicePending += inv.amount;
        const due = parseISODate(inv.dueDate) || (d ? new Date(d.getTime() + 14 * 86400000) : null);
        if (due && due < now) invoiceOverdue += inv.amount;
      }
    });

    const ctx = await loadKpiContext();
    const map = new Map();
    const get = (name) => { const k = lc(name); if (!k) return null; if (!map.has(k)) map.set(k, { company: name, revenue: 0, givenRoles: 0, filledRoles: 0 }); return map.get(k); };
    ctx.roles.forEach(r => {
      const g = get(r.company); if (!g) return;
      const opened = parseISODate(r.date_opened);
      const inYear = opened ? (opened >= yStart && opened < yEnd) : year === now.getUTCFullYear();
      if (inYear) g.givenRoles += parseInt(r.positions, 10) || 1;
    });
    ctx.cands.filter(c => FILLED_STAGES.includes(normStage(c.stage)) && c.offerDate && c.offerDate >= yStart && c.offerDate < yEnd)
      .forEach(c => { const g = get(c.company); if (g) g.filledRoles++; });
    revenueBy.forEach((rev, k) => { const g = get(k); if (g) { g.revenue = rev; if (g.company === k) g.company = k.replace(/\b\w/g, m => m.toUpperCase()); } });
    invoices.forEach(inv => { const g = get(inv.company); if (g && revenueBy.has(lc(inv.company))) g.revenue = revenueBy.get(lc(inv.company)); });

    res.json({
      ytdRevenue, invoicePaid, invoicePending, invoiceOverdue, invoiceCount,
      ellaROI: 0,
      clientPerformance: [...map.values()].sort((a, b) => b.revenue - a.revenue),
    });
  } catch (e) {
    console.error('GET /api/metrics/business-health error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ---------- Auto tasks ---------- */
async function addAutoTasks(list) {
  if (!list.length) return 0;
  const sheets = getSheetsClient();
  const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: TASKS_RANGE });
  const existing = new Set((r.data.values || []).map(x => x[0]));
  const seen = new Set();
  const rows = [];
  list.forEach(t => {
    const id = 'auto-' + t.key;
    if (existing.has(id) || seen.has(id)) return;
    seen.add(id);
    rows.push(taskToRow({ id, user: t.user || 'ella', title: t.title, priority: t.priority || 'Medium', dueDate: t.dueDate, context: t.context || '', status: 'Open', recurring: 'none', archived: false }));
  });
  if (rows.length) {
    await sheets.spreadsheets.values.append({ spreadsheetId: SHEET_ID, range: TASKS_RANGE, valueInputOption: 'RAW', insertDataOption: 'INSERT_ROWS', requestBody: { values: rows } });
  }
  return rows.length;
}

async function findInterviewFor(c) {
  try {
    const all = (await interviewsTable.list()).filter(i => lc(i.candidate_name) === lc(c.name) && !/cancel/i.test(i.status || ''));
    const byRole = all.filter(i => lc(i.role) === lc(c.role));
    const pool = byRole.length ? byRole : all;
    const todayStr = todayISO();
    const upcoming = pool.filter(i => (!i.status || /^scheduled$/i.test(i.status)) && String(i.date || '').slice(0, 10) >= todayStr)
      .sort((a, b) => String(a.date).localeCompare(String(b.date)));
    const pick = upcoming[0] || pool.slice().sort((a, b) => String(b.date).localeCompare(String(a.date)))[0];
    return pick || null;
  } catch (e) { return null; }
}

async function buildStageTasks(c, stage) {
  stage = normStage(stage);
  if (!c || isTestRecord(c.name, c.notes)) return [];
  const t = todayISO();
  const who = `${c.name} (${c.role}${c.company ? ' at ' + c.company : ''})`;
  const base = slugKey(`${c.name}-${c.role}`);
  const out = [];
  const add = (ev, title, due, context, priority, user) => out.push({ key: `${base}-${ev}`, user: user || 'ella', title, dueDate: due, context: context || '', priority: priority || 'Medium' });

  if (stage === 'submitted') {
    add('chase1', `Chase ${c.company || 'client'} for a response on ${c.name}`, toISODate(addDays(new Date(), 1)), `Submission sent for ${who}. Client response window is 24 hours. If nothing by 4pm, call and send a follow up email.`, 'High');
    add('chase3', `Day 3 on ${c.name}: try an alternate contact at ${c.company || 'the client'}`, toISODate(addDays(new Date(), 3)), `Still no response on ${who}? Tell the candidate they are still being considered, then try another contact. If still nothing, escalate to Dan.`, 'High');
  } else if (stage === 'interview_requested') {
    add('avail', `Call ${c.name} for interview availability`, t, `${c.company || 'Client'} wants to interview for ${c.role}. Note availability and move to Interview Scheduled once agreed with the client.`, 'High');
  } else if (stage === 'interview_scheduled') {
    const iv = await findInterviewFor(c);
    const d = iv && parseISODate(iv.date);
    if (!d) {
      add('ivmissing', `Add the interview date for ${c.name}`, t, `${who} is at Interview Scheduled but no interview is on the Interviews tab, so the reminder calls could not be dated.`, 'High');
    } else {
      const iso = toISODate(d);
      const rn = parseInt(iv.round_no, 10) || 0;
      const rs = rn > 1 ? `-r${rn}` : '';
      const rl = rn > 1 ? ` (${iv.round_label || 'round ' + rn})` : '';
      const when = `${formatDateUK(iso)}${iv.time ? ' at ' + iv.time : ''}${rl}`;
      add('ivday-before' + rs, `Confirm attendance call: ${c.name}`, clampFuture(toISODate(new Date(d.getTime() - 86400000))), `Interview ${when} for ${who}. Check they are still good to attend and have the pack and site details.`, 'High');
      add('iv-3h' + rs, `Reassurance call 3 hours before: ${c.name}`, iso, `Interview ${when}. Last minute questions, positive vibes. If no answer, tell the client straight away that contact was lost and keep trying.`, 'High');
      add('iv-after' + rs, `Call ${c.name} for interview feedback`, iso, `Immediately after the interview ${when}. Tell them client feedback is coming.`, 'High');
      add('iv-clientfb' + rs, `Chase ${c.company || 'client'} for interview feedback on ${c.name}`, toISODate(new Date(d.getTime() + 86400000)), `Day after the interview. Call or email the client and take notes. Log it in Client Feedback.`, 'High');
    }
  } else if (stage === 'interviewed') {
    add('fbchase', `Chase ${c.company || 'client'} for feedback on ${c.name}`, toISODate(addDays(new Date(), 1)), `Interviewed for ${who}. If no feedback by tomorrow, call or email and log the outcome.`, 'High');
  } else if (stage === 'offer') {
    add('offer-call', `Call ${c.name} with the offer`, t, `Offer for ${who}. Ask when they can start, then call the client back to confirm the start date.`, 'High');
    add('offer-letter', `Send offer letter to ${c.name}`, t, `Open the candidate card, then Documents and emails, then Offer letter and cover email. It fills the letter from the record and opens the email in Outlook.`, 'High');
    add('offer-info', `Send Information Request email to ${c.name}`, toISODate(addDays(new Date(), 1)), `Open the candidate card, then Documents and emails, then Information request email. Send once the offer is accepted.`);
    add('offer-handover', `Send Client Handover Pack to ${c.company || 'client'} for ${c.name}`, toISODate(addDays(new Date(), 2)), `Open the candidate card, then Documents and emails, then Client handover pack and placement email. Do it once the candidate has returned their information and references.`);
  } else if (['start_date', 'day1', 'week1'].includes(stage)) {
    const sd = parseISODate(c.startDate);
    if (!sd) {
      add('nostart', `Add a start date for ${c.name}`, t, `${who} is at ${stage.replace('_', ' ')} but has no start date, so pre-start, check-in and invoice reminders cannot run.`, 'High');
    } else {
      const s = toISODate(sd);
      add('prestart', `Send Pre-Start Onboarding Pack to ${c.name}`, clampFuture(toISODate(new Date(sd.getTime() - 3 * 86400000))), `Three days before the start on ${formatDateUK(s)} for ${who}. Open the candidate card, then Documents and emails, then Pre-start pack and email.`, 'High');
      add('day1', `Day 1 message to ${c.name}`, clampFuture(s), `Starting today at ${c.company || 'the client'}. Send the Day 1 message and check the client has what they need.`, 'High');
      add('week1', `Week 1 check-in: ${c.name}`, toISODate(new Date(sd.getTime() + 7 * 86400000)), `Check in with ${c.name} and with ${c.company || 'the client'}. Open the candidate card, then Documents and emails, then Week 1 client check-in. Move the card to Week 1 Check-in afterwards.`);
      add('month1', `Month 1 check-in: ${c.name}`, toISODate(new Date(sd.getTime() + 30 * 86400000)), `Check in with both sides. Open the candidate card, then Documents and emails, then Month 1 client feedback request, which also asks for new vacancies and a review.`);
    }
  } else if (stage === 'rejected') {
    add('reject-email', `Send rejection email to ${c.name}`, t, `Open the candidate card, then Documents and emails, then Rejection email, for ${who}. Log the reason in Client Feedback if it came from the client.`);
  }
  return out;
}

async function stageAutomation(c, toStage) {
  try { return await addAutoTasks(await buildStageTasks(c, toStage)); }
  catch (e) { console.error('stageAutomation failed:', e.message); return 0; }
}

async function reconcileTasks() {
  const rows = (await readAllRows()).filter(r => r && r[0]).map(rowToCandidate);
  const list = [];
  const t = todayISO();
  for (const c of rows) {
    const st = normStage(c.stage);
    if (['start_date', 'day1', 'week1'].includes(st)) list.push(...await buildStageTasks(c, st));
    if (['interview_requested', 'offer'].includes(st) && !isTestRecord(c.name, c.notes)) {
      const since = parseISODate(c.date);
      if (since && daysBetween(since, new Date()) >= 3) {
        list.push({ key: `${slugKey(c.name + '-' + c.role)}-stale-${st}`, user: 'ella', priority: 'High', dueDate: t,
          title: `${c.name} has sat at ${st.replace(/_/g, ' ')} since ${formatDateUK(toISODate(since))}`,
          context: `${c.name} (${c.role}, ${c.company}). Nudge the client or the candidate and update the card.` });
      }
    }
  }
  try { list.push(...await complianceTasks()); } catch (e) { console.error('complianceTasks failed:', e.message); }
  return addAutoTasks(list);
}

/* ---------- Invoice chasing ---------- */
function chaseDraft(inv, level) {
  const fee = `£${Number(inv.amount).toLocaleString('en-GB')}`;
  if (level === 1) return `Hi,\n\nA quick reminder that invoice ${inv.number} for ${fee} (${inv.candidateName}, ${inv.role}) was due on ${formatDateUK(inv.dueDate)} and we have not yet seen payment. If it has already gone out, please ignore this and let me know the date. If anything is holding it up, tell me and I will sort it.\n\nKind regards,\nDan`;
  if (level === 2) return `Hi,\n\nInvoice ${inv.number} for ${fee} is now a week overdue. Our terms are payment within 14 days, so I need a payment date from you today please. Could you confirm when this will be cleared?\n\nKind regards,\nDan`;
  return `Hi,\n\nInvoice ${inv.number} for ${fee} remains unpaid more than two weeks after the due date. Please arrange payment immediately. Unless we receive payment or a firm payment date within 3 working days we will have to apply the late payment provisions in our terms and in the Late Payment of Commercial Debts legislation.\n\nKind regards,\nDan`;
}

async function checkOverdueInvoices() {
  const invs = (await readInvoiceRows()).filter(r => r && r[0]).map(rowToInvoice).filter(i => lc(i.status) !== 'paid');
  const now = new Date();
  const list = [];
  invs.forEach(inv => {
    const d = parseISODate(inv.date);
    const due = parseISODate(inv.dueDate) || (d ? new Date(d.getTime() + 14 * 86400000) : null);
    if (!due) return;
    const over = daysBetween(due, now);
    const mk = (lvl, title, prio) => list.push({ key: `inv-${slugKey(inv.number)}-c${lvl}`, user: 'dan', priority: prio, dueDate: todayISO(), title, context: `${inv.company}, ${inv.candidateName}, £${inv.amount}. Draft:\n\n${chaseDraft({ ...inv, dueDate: toISODate(due) }, lvl)}` });
    if (over >= 1) mk(1, `Chase ${inv.company}: invoice ${inv.number} is overdue`, 'High');
    if (over >= 8) mk(2, `Second chase ${inv.company}: invoice ${inv.number} is a week overdue`, 'High');
    if (over >= 15) mk(3, `Final notice ${inv.company}: invoice ${inv.number} is two weeks overdue`, 'High');
  });
  const before = await getTasksSheet();
  const known = new Set(before.map(r => r[0]));
  const fresh = list.filter(l => !known.has('auto-' + l.key));
  const created = await addAutoTasks(list);
  if (created) await mailDan(`Invoice chase: ${created} new task${created > 1 ? 's' : ''}`, fresh.map(f => `- ${f.title}`).join('\n') + '\n\nThe draft message is in each task on the Tasks tab.\n\nLive 2 Help dashboard');
  return created;
}

/* ---------- Application acknowledgement ---------- */
async function sendApplicationAck({ name, email, roleName }) {
  try {
    if (process.env.AUTO_ACK_DISABLED === '1') return;
    if (!email || !/^\S+@\S+\.\S+$/.test(String(email))) return;
    const first = String(name || '').trim().split(/\s+/)[0] || 'there';
    await emailTransporter.sendMail({
      from: `"Live 2 Help Recruitment" <${process.env.BREVO_SENDER_EMAIL}>`,
      replyTo: process.env.BREVO_SENDER_EMAIL,
      to: email,
      subject: `We have received your application for ${roleName}`,
      text: `Hi ${first},\n\nThank you for applying for the ${roleName} position through Live 2 Help Recruitment. Your application and CV have arrived safely and we are reviewing them now.\n\nIf your experience matches what the client needs, one of our team will call you to talk it through. Your details are held securely and only used in line with the consent you gave on the application form.\n\nKind regards,\nThe Live 2 Help Recruitment team`,
    });
  } catch (e) { console.error('Application acknowledgement failed:', e.message); }
}

/* ---------- Monday digest ---------- */
async function buildDigest() {
  const rows = (await readAllRows()).filter(r => r && r[0]).map(rowToCandidate).filter(c => !isTestRecord(c.name, c.notes));
  const byStage = {};
  rows.forEach(c => { const s = normStage(c.stage); byStage[s] = (byStage[s] || 0) + 1; });
  const stageLine = Object.entries(byStage).map(([s, n]) => `${s.replace(/_/g, ' ')}: ${n}`).join(', ') || 'none';
  const t = todayISO(); const weekEnd = toISODate(addDays(new Date(), 7));
  const ivs = (await interviewsTable.list().catch(() => [])).filter(i => i.date >= t && i.date <= weekEnd && !/cancel/i.test(i.status || ''));
  const tasks = (await getTasksSheet()).map(rowToTask).filter(x => !x.archived && lc(x.status) !== 'done' && x.dueDate && x.dueDate < t);
  const invs = (await readInvoiceRows()).filter(r => r && r[0]).map(rowToInvoice);
  const unpaid = invs.filter(i => lc(i.status) !== 'paid');
  const overdue = unpaid.filter(i => { const d = parseISODate(i.dueDate) || (parseISODate(i.date) && new Date(parseISODate(i.date).getTime() + 14 * 86400000)); return d && d < new Date(); });
  const yr = new Date().getUTCFullYear();
  const rev = invs.filter(i => { const d = parseISODate(i.date); return d && d.getUTCFullYear() === yr; }).reduce((a, b) => a + b.amount, 0);
  const roles = (await rolesTable.list().catch(() => [])).filter(r => lc(r.status) === 'open');
  const bk = (await settingsTable.list().catch(() => [])).find(o => o.id === 'backup_last');
  let bkLine = 'no backup recorded yet';
  try { if (bk) { const v = JSON.parse(bk.value); bkLine = v.ok ? `last ok ${v.at.slice(0, 10)}` : `FAILED ${v.at.slice(0, 10)}: ${v.error}`; } } catch (e) { /* ignore */ }
  const money = n => `£${Math.round(n).toLocaleString('en-GB')}`;
  return `Good morning Dan,\n\nYour week at a glance.\n\nPIPELINE\n- Open roles: ${roles.length}\n- Candidates by stage: ${stageLine}\n- Interviews in the next 7 days: ${ivs.length}${ivs.length ? '\n' + ivs.map(i => `  ${formatDateUK(i.date)} ${i.time || ''} ${i.candidate_name} at ${i.company}`).join('\n') : ''}\n\nTASKS\n- Overdue tasks across the team: ${tasks.length}${tasks.length ? '\n' + tasks.slice(0, 8).map(x => `  ${x.user}: ${x.title} (due ${x.dueDate})`).join('\n') : ''}\n\nMONEY\n- Revenue invoiced this year: ${money(rev)}\n- Unpaid: ${money(unpaid.reduce((a, b) => a + b.amount, 0))} across ${unpaid.length} invoice${unpaid.length === 1 ? '' : 's'}\n- Overdue: ${money(overdue.reduce((a, b) => a + b.amount, 0))} across ${overdue.length}\n\nSYSTEM\n- Backups: ${bkLine}\n\nLive 2 Help dashboard`;
}

app.get('/api/cron/weekly-digest', cronOnly, async (req, res) => {
  try {
    const body = await buildDigest();
    const ok = await mailDan('Your Live 2 Help week at a glance', body);
    res.json({ sent: ok });
  } catch (e) {
    console.error('weekly digest failed:', e.message);
    await alertDan('digest', 'Live 2 Help dashboard: weekly digest failed', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ---------- One daily job ---------- */
async function runDailyJob(skipBackup) {
  const result = {};
  const step = async (name, fn) => {
    try { result[name] = await fn(); }
    catch (e) { result[name] = 'FAIL: ' + e.message; await alertDan('daily:' + name, `Live 2 Help dashboard: daily job step failed (${name})`, e.message); }
  };
  await step('health', deepHealthCheck);
  if (!skipBackup) await step('backup', safeBackup);
  await step('tasks', reconcileTasks);
  await step('invoiceChase', checkOverdueInvoices);
  return result;
}
app.get('/api/cron/daily', cronOnly, async (req, res) => {
  const skipBackup = req.query.skipBackup === '1';
  if (req.query.wait === '1') return res.json(await runDailyJob(skipBackup));
  res.json(await runCronJob('daily', () => runDailyJob(skipBackup)));
});


/* ======================================================================
   AUTOMATION BATCH B - Offer path documents
   Uses your own Word templates (built into this file). The
   [PLACEHOLDERS] in them were converted to {{tokens}} so the design is
   untouched. Needs "jszip" in package.json dependencies.
   Kinds: offer, info_request, placement, prestart, rejection
   ====================================================================== */

const offerDetailsTable = makeSimpleTable({
  tab: 'Offer Details',
  header: ['id', 'candidate_name', 'role', 'company', 'details_json', 'updated_by', 'updated_at'],
  path: '/api/offer-details',
  label: 'Offer details',
  auditType: 'offer_details',
  auditName: o => `${o.candidate_name} - ${o.role}`,
});

const OFFER_LABELS = {
  candidate_name: 'CANDIDATE FULL NAME', candidate_first: 'CANDIDATE FIRST NAME', candidate_last: 'CANDIDATE LAST NAME',
  candidate_email: 'CANDIDATE EMAIL', candidate_phone: 'CANDIDATE PHONE', company: 'COMPANY NAME', job_title: 'JOB TITLE',
  salary: 'SALARY', start_date_long: 'START DATE', start_time: 'REPORT TIME ON FIRST DAY', reporting_to: 'LINE MANAGER NAME AND TITLE',
  work_location: 'WORK LOCATION', employment_type: 'FULL TIME / PART TIME / CONTRACT', address_line1: 'ADDRESS LINE 1',
  address_line2: 'ADDRESS LINE 2', postcode: 'POSTCODE', home_address: 'HOME ADDRESS', dob: 'DATE OF BIRTH',
  emergency_contact: 'EMERGENCY CONTACT', rtw_doc_type: 'RIGHT TO WORK DOCUMENT', rtw_verified: 'RTW VERIFIED', rtw_original: 'ORIGINAL ON DAY 1',
  special_requirements: 'SPECIAL REQUIREMENTS', parking: 'PARKING', dress_code: 'DRESS CODE', client_contact: 'CLIENT CONTACT NAME',
  offer_reply_by: 'REPLY BY DATE', key_strength_1: 'KEY STRENGTH 1', key_strength_2: 'KEY STRENGTH 2', evidence: 'SPECIFIC EVIDENCE',
  relevant_area: 'RELEVANT AREA', impact_area: 'SPECIFIC PROJECT OR RESPONSIBILITY', specific_strength: 'SPECIFIC STRENGTH',
  specific_example: 'SPECIFIC EXAMPLE', close_match_detail: 'WHERE THE DECISION CAME DOWN TO', sector: 'SECTOR OR SPECIALISM', future_area: 'FUTURE OPPORTUNITY AREA',
};
for (let i = 1; i <= 2; i++) ['name', 'title', 'company', 'relationship', 'email', 'phone'].forEach(f => { OFFER_LABELS[`ref${i}_${f}`] = `REFEREE ${i} ${f.toUpperCase()}`; });

const OFFER_SIGS = {
  coordinator: 'Ella Pietrzak\nRecruitment Coordinator\nLive 2 Help Recruitment\nella.pietrzak@live2helprecruitment.co.uk\n07434 351996\nwww.live2helprecruitment.co.uk',
  consultant: 'Ella Pietrzak\nTalent Acquisition & Business Development Consultant\nLive 2 Help Recruitment\nella@live2helprecruitment.co.uk\n07434 351996\nwww.live2helprecruitment.co.uk',
};

const OFFER_EMAILS = {
  offer: {
    to: 'candidate_email', subject: 'Your offer: {{job_title}} at {{company}}', attach: ['Offer Letter'],
    body: `Dear {{candidate_name}},\n\nWe are delighted to offer you the position of {{job_title}} at {{company}}.\n\nYour formal offer letter is attached to this email. Please review the key details confirmed below:\n\nStart Date: {{start_date_long}}\nAnnual Salary: {{salary}}\nReporting To: {{reporting_to}}\n\nNEXT STEPS\n\nPlease sign and return the attached offer letter by {{offer_reply_by}}. Once we receive your signed acceptance, we will arrange the following:\n\n- Pre-start onboarding pack and site information\n- Confirmation of any compliance documentation needed (ID, references, proof of right to work)\n- First day briefing and induction overview\n\nIf you have any questions or need further information before your start date, please do not hesitate to reach out. I am here to help make this transition as smooth as possible for you.\n\nCongratulations again - we look forward to welcoming you to the team.\n\nKind regards,\n\n{{sig_consultant}}`,
  },
  info_request: {
    to: 'candidate_email', subject: 'Next Steps - A Few Things We Need From You', attach: [],
    body: `Hi {{candidate_first}},\n\nCongratulations again on accepting your offer - we are delighted for you and cannot wait to see you get started at {{company}}.\n\nTo make sure everything runs smoothly before your first day, we just need a few bits of information from you. This will not take long and will help us and {{company}} get everything in place ahead of your start.\n\nPlease respond to this email with the information below within 24 hours.\n\n1. YOUR DETAILS\n\nPlease confirm or provide the following:\n\n- Full legal name (as it appears on your passport or driving licence)\n- Home address (including postcode)\n- Personal email address\n- Personal mobile number\n- Date of birth\n- Emergency contact name, relationship, and phone number\n- Confirmed start date (we have noted {{start_date_long}} - please confirm this works for you)\n\n2. RIGHT TO WORK\n\nWe are required to confirm your Right to Work in the UK before your start date. Please provide one of the following:\n\n- A copy of your valid passport (photo page), or\n- A copy of your UK birth certificate and proof of National Insurance number, or\n- Your share code if you hold a Biometric Residence Permit or EU Settlement Scheme status\n\nYou can email a clear photo or scan to ella.pietrzak@live2helprecruitment.co.uk. This information is handled securely and in line with our Data Protection Policy.\n\n3. REFERENCES\n\nWe require two professional references before your start date. Please provide the details below for each referee. These should ideally be line managers or supervisors from your two most recent employers.\n\nReference 1: Full name, job title, company, relationship to you, email address, phone number\nReference 2: Full name, job title, company, relationship to you, email address, phone number\n\n4. ANYTHING ELSE WE SHOULD KNOW?\n\nIf there is anything you need us to be aware of before your start - for example, any reasonable adjustments, specific requirements for your first day, or anything that may affect your start date - please let us know here and we will make sure it is taken care of.\n\nThat is everything from us for now. Once we have received the above, we will be in touch with your pre-start onboarding information and details on what to expect before day one.\n\nIf you have any questions at all in the meantime, please do not hesitate to call or email me directly.\n\nBest regards,\n\n{{sig_coordinator}}`,
  },
  placement: {
    to: 'client_email', subject: '{{candidate_name}} confirmed as {{job_title}} at {{company}}', attach: ['Client Handover Pack'],
    body: `Dear {{client_contact}},\n\nWe are delighted to confirm that {{candidate_name}} will be joining {{company}} as {{job_title}}, commencing {{start_date_long}}.\n\nCANDIDATE PROFILE SNAPSHOT\n\n{{candidate_name}} brings {{key_strength_1}} and {{key_strength_2}} to this role. During the process, {{pron_subject}} demonstrated particular capability in {{evidence}}, which aligns directly with your team's requirements. {{pron_possessive_cap}} background in {{relevant_area}} positions {{pron_object}} well for immediate impact on {{impact_area}}.\n\nHANDOVER DOCUMENTS\n\nWe have attached our Client Handover Pack which contains {{candidate_name}}'s full record for your files. This includes personal details, employment history, proof of right to work confirmation and the two professional references with full contact information for any follow up required. Please keep this for your records.\n\nINVOICE & PAYMENT\n\nYour invoice will follow separately. Please direct any billing queries to office@live2helprecruitment.co.uk.\n\nPOST-PLACEMENT SUPPORT\n\nWe will be in touch for our standard post-placement check-ins at Week 1 and Month 1 to ensure everything is progressing well on both sides. If anything requires attention before then, please contact me directly and I will respond the same day.\n\nA SMALL FAVOUR\n\nIf you have had a positive experience working with Live 2 Help Recruitment, we would be really grateful if you could take two minutes to leave us a review. It makes a genuine difference to a growing business and helps other organisations understand what we do.\n\nLeave a review here: https://g.page/r/CU5L4ObMovbGEBM/review\n\nThank you for partnering with us on this placement. We hope {{candidate_name}} makes a real difference to your team and we look forward to supporting you on future hires.\n\nKind regards,\n\n{{sig_consultant}}`,
  },
  prestart: {
    to: 'candidate_email', subject: 'Your pre-start pack: {{job_title}} at {{company}}', attach: ['Pre-Start Onboarding Pack'],
    body: `Hi {{candidate_first}},\n\nYour start date at {{company}} is {{start_date_long}}, so we have put together your pre-start onboarding pack. It is attached, and it covers where to go, who to ask for, what to bring and what to expect in your first week.\n\nPlease read it in full and bring the items on the Day One checklist. If we do not yet have your Right to Work documents or references, please send them over today so nothing delays your start.\n\nIf anything is unclear, call or email me and I will sort it straight away.\n\nWe are rooting for you.\n\nWarm regards,\n\n{{sig_coordinator}}`,
  },
  rejection: {
    to: 'candidate_email', subject: 'Your application for {{job_title}} at {{company}}', attach: [],
    body: `Dear {{candidate_name}},\n\nThank you for investing your time in the process and for the genuine effort you put into your preparation. It was a pleasure getting to know you and we appreciated the quality of your engagement throughout.\n\nWe wanted to let you know that we have decided to move forward with another candidate for this particular role. This was not a reflection of your capabilities - you demonstrated real strengths in {{specific_strength}}, and we were genuinely impressed by {{specific_example}}. The decision came down to a very close match of specific experience within {{close_match_detail}}.\n\nWe would very much like to stay in touch. Your background in {{sector}} puts you in a strong position for future opportunities, particularly in {{future_area}}. If your situation changes or you update your CV, please do let us know - we check profiles regularly and if something lands that fits, we will reach out directly.\n\nIf you would like to chat about next steps or explore other possibilities in your field, I am always happy to have that conversation. Please feel free to reach out at any time.\n\nKind regards,\n\n{{sig_consultant}}`,
  },
};

const OFFER_SYNONYMS = { ellaConsultant: 'consultant' };

function offerLongDate(iso) {
  const d = parseISODate(iso);
  return d ? d.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).replace(/^(\w+),\s*/, '$1 ') : '';
}
function offerPlainDate(iso) {
  const d = parseISODate(iso);
  return d ? d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }) : '';
}
function offerMoney(v) {
  const n = parseFloat(String(v || '').replace(/[^0-9.]/g, ''));
  return n ? '£' + n.toLocaleString('en-GB', { maximumFractionDigits: 0 }) : '';
}
function packPlace(s) { return [s.address, s.postcode].filter(Boolean).join(', '); }

async function gatherOfferValues(body) {
  const c = body.candidate || {};
  const extra = body.extra || {};
  const id = placementKey(c.company, c.name, c.role);
  let saved = {};
  try {
    const row = (await offerDetailsTable.list()).find(o => o.id === id);
    if (row && row.details_json) saved = JSON.parse(row.details_json);
  } catch (e) { saved = {}; }

  let role = {}, site = {}, logistics = {}, cdet = {}, clientRow = null;
  try { role = (await rolesTable.list()).find(r => lc(r.company) === lc(c.company) && (lc(r.role) === lc(c.role) || lc(r.public_title) === lc(c.role))) || {}; } catch (e) { /* optional */ }
  try {
    const sites = (await clientSitesTable.list()).filter(s => lc(s.company) === lc(c.company));
    site = sites[0] || {};
    try { logistics = JSON.parse(site.logistics_json || '{}'); } catch (e) { logistics = {}; }
  } catch (e) { /* optional */ }
  try { cdet = (await candidateDetailsTable.list()).find(o => lc(o.candidate_name) === lc(c.name) && lc(o.company) === lc(c.company)) || {}; } catch (e) { /* optional */ }

  const merged = { ...saved, ...extra };
  const contactName = merged.client_contact || role.contact || '';
  try {
    const rows = (await readClientRows()).filter(r => lc(r[1]) === lc(c.company));
    clientRow = rows.find(r => contactName && lc(r[4]) === lc(contactName)) || rows[0] || null;
  } catch (e) { clientRow = null; }

  const parts = String(c.name || '').trim().split(/\s+/);
  const pr = merged.pronouns === 'he' ? ['he', 'him', 'His'] : merged.pronouns === 'she' ? ['she', 'her', 'Her'] : ['they', 'them', 'Their'];
  const addr1 = merged.address_line1 || '', addr2 = merged.address_line2 || '', pc = merged.postcode || '';
  const v = {
    candidate_name: c.name || '', candidate_first: parts[0] || '', candidate_last: parts.slice(1).join(' '),
    candidate_email: c.email || merged.candidate_email || '', candidate_phone: c.phone || merged.candidate_phone || '',
    company: c.company || '', job_title: merged.job_title || role.public_title || c.role || '',
    salary: offerMoney(c.salary || merged.salary), start_date_long: offerLongDate(c.startDate || merged.start_date),
    start_time: merged.start_time || cdet.start_time || '', reporting_to: merged.reporting_to || cdet.reporting_to || '',
    work_location: merged.work_location || packPlace(site) || role.location || '',
    employment_type: merged.employment_type || 'Full time',
    address_line1: addr1, address_line2: addr2, postcode: pc,
    home_address: merged.home_address || [addr1, addr2, pc].filter(Boolean).join(', '),
    dob: merged.dob ? offerPlainDate(merged.dob) : '', emergency_contact: merged.emergency_contact || '',
    rtw_doc_type: merged.rtw_doc_type || '', rtw_verified: merged.rtw_verified || 'Yes - scanned copy provided', rtw_original: merged.rtw_original || 'Yes',
    special_requirements: merged.special_requirements || 'N/A',
    parking: merged.parking || logistics.parking || 'N/A', dress_code: merged.dress_code || logistics.dress_code || '',
    company_item: merged.company_item || 'Anything specific to the site', company_item_note: merged.company_item_note || 'N/A',
    client_contact: contactName || (clientRow ? clientRow[4] : ''), client_email: (clientRow && clientRow[6]) || '',
    offer_reply_by: merged.offer_reply_by ? offerLongDate(merged.offer_reply_by) : offerLongDate(toISODate(addDays(new Date(), 1))),
    today: offerPlainDate(todayISO()),
    pron_subject: pr[0], pron_object: pr[1], pron_possessive_cap: pr[2],
    sig_coordinator: OFFER_SIGS.coordinator, sig_consultant: OFFER_SIGS.consultant,
  };
  try {
    const pl = (await placementsTable.list()).find(o => o.id === placementKey(c.company, c.name, c.role));
    const weeks = parseInt(pl && pl.guarantee_weeks, 10) || DEFAULT_GUARANTEE_WEEKS;
    const sd = parseISODate(c.startDate || merged.start_date);
    v.guarantee_end = sd ? offerPlainDate(toISODate(new Date(sd.getTime() + weeks * 7 * 86400000))) : '';
  } catch (e) { v.guarantee_end = ''; }
  const compRec = await complianceFor(c.company, c.name, c.role);
  if (compRec) {
    if (!merged.rtw_doc_type && compRec.rtw_doc) v.rtw_doc_type = compRec.rtw_doc;
    v.rtw_verified = RTW_DONE.includes(lc(compRec.rtw_status)) ? 'Yes - scanned copy provided' : 'Pending - not yet verified';
    v.rtw_original = lc(compRec.rtw_original_seen) === 'yes' ? 'Seen and retained' : 'Yes';
    v._compliance = compRec;
  }
  ['key_strength_1', 'key_strength_2', 'evidence', 'relevant_area', 'impact_area', 'specific_strength', 'specific_example', 'close_match_detail', 'sector', 'future_area'].forEach(k => { v[k] = merged[k] || ''; });
  for (let i = 1; i <= 2; i++) ['name', 'title', 'company', 'relationship', 'email', 'phone'].forEach(f => { v[`ref${i}_${f}`] = merged[`ref${i}_${f}`] || ''; });
  return { values: v, saved, id };
}

function offerFill(text, vals, missing) {
  return String(text).replace(/\{\{(\w+)\}\}/g, (m, k) => {
    const val = vals[k];
    if (val === undefined || val === null || String(val).trim() === '') {
      if (OFFER_LABELS[k]) { missing.add(k); return `[${OFFER_LABELS[k]}]`; }
      return '';
    }
    return String(val);
  });
}
const xmlEsc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// The three Word templates are built into this file, so nothing else needs uploading.
// If a templates folder sits next to server.js its copy is used instead (handy for editing wording without a code change).
const OFFER_TEMPLATES_B64 = {
  'Offer Letter': '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',
  'Client Handover Pack': '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',
  'Pre-Start Onboarding Pack': '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',
};
async function offerFillDocx(templateName, vals, missing) {
  let JSZip;
  try { JSZip = (await import('jszip')).default; }
  catch (e) { throw new Error('The "jszip" package is not installed on the server. Add "jszip" to the dependencies in package.json and redeploy.'); }
  const file = path.join(__dirname, 'templates', templateName + '.docx');
  let tplBuf = null;
  if (fs.existsSync(file)) tplBuf = fs.readFileSync(file);
  else if (OFFER_TEMPLATES_B64[templateName]) tplBuf = Buffer.from(OFFER_TEMPLATES_B64[templateName], 'base64');
  if (!tplBuf) throw new Error(`Template "${templateName}" is not available on the server`);
  const zip = await JSZip.loadAsync(tplBuf);
  for (const name of Object.keys(zip.files)) {
    if (!/^word\/(document|header\d*|footer\d*)\.xml$/.test(name)) continue;
    let xml = await zip.file(name).async('string');
    xml = xml.replace(/\{\{(\w+)\}\}/g, (m, k) => xmlEsc(offerFill(m, vals, missing)));
    zip.file(name, xml);
  }
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

function offerFileName(kind, vals) {
  const who = `${vals.candidate_first} ${String(vals.candidate_last || '').charAt(0)}`.trim();
  const role = String(vals.job_title || '').replace(/[^A-Za-z0-9 \-]/g, '');
  return `${kind} ${who} ${role}.docx`.replace(/\s+/g, ' ').trim();
}

app.post('/api/offer-docs/build', async (req, res) => {
  try {
    const { kind } = req.body || {};
    const tpl = OFFER_EMAILS[kind];
    if (!tpl) return res.status(400).json({ error: 'Unknown document set' });
    const c = (req.body || {}).candidate || {};
    if (!c.name || !c.company) return res.status(400).json({ error: 'candidate name and company are required' });
    const { values, saved, id } = await gatherOfferValues(req.body);
    const missing = new Set();
    const attachments = [];
    for (const t of tpl.attach) {
      const buf = await offerFillDocx(t, values, missing);
      attachments.push({ fileName: offerFileName(t, values), mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', base64: buf.toString('base64') });
    }
    const subject = offerFill(tpl.subject, values, new Set());
    const body = offerFill(tpl.body, values, missing);
    const needed = (tpl.body + ' ' + tpl.subject).match(/\{\{(\w+)\}\}/g) || [];
    const toKey = tpl.to === 'client_email' ? 'client_email' : 'candidate_email';
    const to = values[toKey] || '';
    const warnings = [];
    if (kind === 'placement') {
      const cr = values._compliance;
      if (!cr || !RTW_DONE.includes(lc(cr.rtw_status))) warnings.push('Right to work is not marked as verified on the candidate card, so the handover pack says Pending.');
      if (!cr || !REF_DONE.includes(lc(cr.ref1_status)) || !REF_DONE.includes(lc(cr.ref2_status))) warnings.push('One or both references are not marked as received.');
    }
    auditLog(auditActorOf(req), 'offer_docs_built', 'candidate', `${c.name} - ${c.role}`, kind);
    res.json({
      warnings,
      kind, to, subject, body, attachments,
      missing: [...missing].map(k => ({ key: k, label: OFFER_LABELS[k] || k })),
      missingTo: !to ? (toKey === 'client_email' ? 'client contact email' : 'candidate email') : '',
      saved, id, hasNeeded: needed.length,
    });
  } catch (e) {
    console.error('POST /api/offer-docs/build error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Fields used by each document set, so the dashboard can ask only for what is missing
app.get('/api/offer-docs/fields', (req, res) => {
  const out = {};
  Object.entries(OFFER_EMAILS).forEach(([k, t]) => {
    const keys = new Set((t.body + ' ' + t.subject).match(/\{\{(\w+)\}\}/g) || []);
    out[k] = [...keys].map(x => x.slice(2, -2)).filter(x => OFFER_LABELS[x]);
  });
  const docKeys = {
    offer: ['address_line1', 'address_line2', 'postcode', 'employment_type', 'work_location', 'reporting_to'],
    placement: ['dob', 'home_address', 'emergency_contact', 'rtw_doc_type', 'start_time', 'work_location', 'employment_type', 'reporting_to', 'ref1_name', 'ref1_title', 'ref1_company', 'ref1_relationship', 'ref1_email', 'ref1_phone', 'ref2_name', 'ref2_title', 'ref2_company', 'ref2_relationship', 'ref2_email', 'ref2_phone'],
    prestart: ['start_time', 'work_location', 'reporting_to', 'dress_code', 'parking'],
  };
  Object.entries(docKeys).forEach(([k, arr]) => { out[k] = [...new Set([...(out[k] || []), ...arr])]; });
  res.json({ fields: out, labels: OFFER_LABELS });
});

// Optional AI help: draft the wording fields from the candidate's notes and any saved submission text
app.post('/api/offer-docs/draft-text', async (req, res) => {
  try {
    const { kind, candidate, notes } = req.body || {};
    const c = candidate || {};
    let subText = '';
    try {
      const d = (await submissionDraftsTable.list()).find(o => lc(o.candidate_name || o.name) === lc(c.name));
      if (d) subText = JSON.stringify(d).slice(0, 6000);
    } catch (e) { /* optional */ }
    const brief = (await roleBriefsTable.list().catch(() => [])).find(b => lc(b.company) === lc(c.company) && lc(b.role) === lc(c.role));
    const reqText = brief ? String(brief.requirements || brief.job_description || '').slice(0, 3000) : '';
    const placement = kind === 'placement';
    const tool = {
      name: 'fill_fields', description: 'Return the short wording fields for the email.',
      input_schema: { type: 'object', properties: placement
        ? { key_strength_1: { type: 'string' }, key_strength_2: { type: 'string' }, evidence: { type: 'string' }, relevant_area: { type: 'string' }, impact_area: { type: 'string' } }
        : { specific_strength: { type: 'string' }, specific_example: { type: 'string' }, close_match_detail: { type: 'string' }, sector: { type: 'string' }, future_area: { type: 'string' } },
        required: placement ? ['key_strength_1', 'key_strength_2', 'evidence', 'relevant_area', 'impact_area'] : ['specific_strength', 'specific_example', 'close_match_detail', 'sector', 'future_area'] },
    };
    const system = 'You write short phrase fragments for recruitment emails from a UK agency. Each value is a lower case noun phrase that completes a sentence (no full stops, no leading capital, no em dashes). Use only facts present in the notes. If the notes do not support a field, write a safe, honest, general phrase instead of inventing detail.';
    const content = `Candidate: ${c.name}, role: ${c.role} at ${c.company}.\nNotes:\n${notes || c.notes || '(none)'}\n\nSubmission draft data:\n${subText || '(none)'}\n\nClient requirements:\n${reqText || '(none)'}\n\nFields are for a ${placement ? 'placement confirmation email to the client' : 'warm rejection email to the candidate'}.`;
    const out = await callClaudeTool({ system, content, tool, maxTokens: 700 });
    res.json({ fields: out });
  } catch (e) {
    console.error('POST /api/offer-docs/draft-text error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Tasks for the offer path now point Ella to the documents button


/* ======================================================================
   AUTOMATION BATCH C
   Talent pool matching, right to work and reference tracker,
   Week 1 and Month 1 client check-in emails.
   ====================================================================== */

const complianceTable = makeSimpleTable({
  tab: 'Compliance',
  header: ['id', 'candidate_name', 'role', 'company', 'rtw_status', 'rtw_doc', 'rtw_date', 'rtw_original_seen', 'ref1_status', 'ref2_status', 'notes', 'updated_by', 'updated_at'],
  path: '/api/compliance',
  label: 'Compliance record',
  auditType: 'compliance',
  auditName: o => `${o.candidate_name} - ${o.role}`,
});

const MATCH_STOP = new Set(('a an and are as at be by for from in is it of on or the to with we you your our will can this that role job work working experience required ' +
  'must have has had able strong good excellent skills skill team within across more than including etc plus ideal desirable essential per year years new their they them who what when where how').split(/\s+/));
function matchTokens(text) {
  return String(text || '').toLowerCase().replace(/[^a-z0-9+#\s-]/g, ' ').split(/\s+/)
    .map(w => w.replace(/^-+|-+$/g, '')).filter(w => w.length > 2 && !MATCH_STOP.has(w));
}
function tokenSet(text) { return new Set(matchTokens(text)); }

/* ======================================================================
   Talent pool: CV search, 15 mile radius and AI ranking

   - Only people who agreed to be kept for future roles are ever considered.
   - Each CV is read ONCE by the AI into a short profile (skills, titles, home
     town or postcode). The profile is saved in a "Pool CV Index" tab and only
     re-read if the CV file changes.
   - The home town or postcode is turned into map coordinates with the free
     postcodes.io service, and compared with the client site (or the role
     location). Only people within the radius are ranked.
   - The AI scores each person against the role brief and reads their notes.
     Clear red flags in the notes (lacks required skills, interviewed badly,
     withdrew, rejected for capability, etc.) push them to the bottom with the
     reason shown.
   - Scores are saved per role and person in "Pool Match Scores" and reused.
     Only new or changed people are scored. Nothing runs in the background:
     work only happens when someone presses the button.
   ====================================================================== */

const MATCH_RADIUS_MILES = parseFloat(process.env.MATCH_RADIUS_MILES) || 15;
const MATCH_INDEX_MODEL = process.env.MATCH_INDEX_MODEL || 'claude-haiku-4-5-20251001';
const MATCH_MODEL = process.env.MATCH_MODEL || SUBMISSION_MODEL;
const MATCH_MAX_SCORED = parseInt(process.env.MATCH_MAX_SCORED, 10) || 120;
const MATCH_INDEX_BATCH = 4;
const MATCH_SCORE_BATCH = 8;

const poolCvIndexTable = makeSimpleTable({
  tab: 'Pool CV Index',
  header: ['id', 'cv_file_id', 'status', 'town', 'postcode', 'lat', 'lng', 'titles', 'skills', 'profile', 'indexed_at'],
  path: null,
  label: 'CV index',
});

const poolMatchTable = makeSimpleTable({
  tab: 'Pool Match Scores',
  header: ['id', 'role_key', 'pool_id', 'score', 'reason', 'negative', 'negative_reason', 'strengths', 'input_hash', 'scored_at', 'shortlisted'],
  path: null,
  label: 'Match score',
});

function matchRoleKey(company, roleName) { return `${lc(company)}|${lc(roleName)}`.replace(/[^a-z0-9|]+/g, '-'); }
function sha1(s) { return crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 16); }

// One read, one write: update rows that exist and append the ones that do not
async function bulkUpsert(tbl, objs) {
  if (!objs.length) return;
  const byId = new Map(objs.map(o => [o.id, o]));
  const existing = new Set((await tbl.listAll()).map(o => o.id));
  const upd = objs.filter(o => existing.has(o.id));
  const add = objs.filter(o => !existing.has(o.id));
  if (upd.length) await tbl.updateWhere(o => byId.has(o.id) && existing.has(o.id), o => ({ ...o, ...byId.get(o.id) }));
  for (const o of add) await tbl.append(o);
}

/* ---------- Locations (free postcodes.io lookups, cached) ---------- */
const geoCache = new Map();
async function geoGet(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(7000) });
  if (!r.ok) return null;
  return r.json().catch(() => null);
}
async function geocodeUK(postcode, place) {
  const pc = String(postcode || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const town = String(place || '').split(',')[0].replace(/\b(uk|united kingdom|england)\b/gi, '').trim();
  const key = `${pc}|${lc(town)}`;
  if (!pc && !town) return null;
  const hit = geoCache.get(key);
  if (hit && Date.now() - hit.at < 24 * 3600 * 1000) return hit.v;
  let v = null;
  try {
    if (/^[A-Z]{1,2}\d[A-Z\d]?\d[A-Z]{2}$/.test(pc)) {
      const j = await geoGet(`https://api.postcodes.io/postcodes/${pc}`);
      if (j && j.result) v = { lat: j.result.latitude, lng: j.result.longitude, label: j.result.admin_district || pc };
    } else if (/^[A-Z]{1,2}\d[A-Z\d]?$/.test(pc)) {
      const j = await geoGet(`https://api.postcodes.io/outcodes/${pc}`);
      if (j && j.result) v = { lat: j.result.latitude, lng: j.result.longitude, label: pc };
    }
    if (!v && town) {
      const j = await geoGet(`https://api.postcodes.io/places?q=${encodeURIComponent(town)}&limit=1`);
      const p0 = j && j.result && j.result[0];
      if (p0 && p0.latitude != null) v = { lat: p0.latitude, lng: p0.longitude, label: p0.name_1 || town };
    }
  } catch (e) { v = null; }
  if (v && (typeof v.lat !== 'number' || typeof v.lng !== 'number')) v = null;
  geoCache.set(key, { at: Date.now(), v });
  return v;
}

function milesBetween(a, b) {
  const R = 3958.8, rad = x => x * Math.PI / 180;
  const dLat = rad(b.lat - a.lat), dLng = rad(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

// Where the job is: the client's site postcode if there is one, otherwise the role location
async function resolveRoleOrigin(company, role) {
  const loc = String(role.location || '').trim();
  let sites = [];
  try { sites = (await clientSitesTable.list()).filter(s => lc(s.company) === lc(company)); } catch (e) { sites = []; }
  const locTokens = tokenSet(loc);
  const pick = sites.find(s => s.postcode && locTokens.size && [...tokenSet(`${s.site_name} ${s.address}`)].some(t => locTokens.has(t)))
    || sites.find(s => s.postcode) || null;
  if (pick) {
    const g = await geocodeUK(pick.postcode, '');
    if (g) return { ok: true, lat: g.lat, lng: g.lng, label: `${pick.site_name || pick.address || company} (${pick.postcode})` };
  }
  if (loc) {
    const g = await geocodeUK('', loc);
    if (g) return { ok: true, lat: g.lat, lng: g.lng, label: loc };
  }
  return { ok: false, label: loc || '' };
}

/* ---------- Reading a CV into a saved profile ---------- */
const CVINDEX_SYSTEM = `You read a candidate's CV for a UK recruitment agency and return a short factual profile used for searching and matching.
- Use ONLY what the CV says. Never invent.
- town: the candidate's home town or city if shown (for example "Stoke-on-Trent"). postcode: their full home postcode only if it appears on the CV. Leave blank if not shown. Do not use an employer's address.
- profile: about 250 words of plain factual text covering current and recent job titles, employers, sectors, systems and tools, key responsibilities, measurable achievements, qualifications and seniority. Do NOT include the person's name, email, phone number or street address. No em dashes.`;
const CVINDEX_TOOL = {
  name: 'save_cv_profile',
  description: 'Return the searchable profile of the CV.',
  input_schema: {
    type: 'object',
    properties: {
      town: { type: 'string' },
      postcode: { type: 'string' },
      recent_titles: { type: 'array', items: { type: 'string' } },
      key_skills: { type: 'array', items: { type: 'string' } },
      profile: { type: 'string' },
    },
    required: ['town', 'postcode', 'recent_titles', 'key_skills', 'profile'],
  },
};

async function indexOneCv(p) {
  const base = { id: p.id, cv_file_id: p.cvFileId, indexed_at: new Date().toISOString() };
  try {
    const drive = getDriveClient();
    const meta = await drive.files.get({ fileId: p.cvFileId, fields: 'name, mimeType, size' });
    const fileName = meta.data.name || p.cvFileName || 'CV';
    const kind = cvKind(fileName, meta.data.mimeType || '');
    if (!['pdf', 'docx', 'gdoc'].includes(kind) || Number(meta.data.size || 0) > 12 * 1024 * 1024) {
      return { ...base, status: 'unreadable', town: '', postcode: '', lat: '', lng: '', titles: '', skills: '', profile: '' };
    }
    const dl = await downloadCv({ fileId: p.cvFileId, kind });
    const cvDoc = { kind: dl.kind, buffer: dl.buffer, text: dl.kind === 'docx' ? docxToText(dl.buffer) : '' };
    const content = [{ type: 'text', text: 'Read this CV and return the profile.' }, ...cvBlocks(cvDoc)];
    const out = await callClaudeTool({ system: CVINDEX_SYSTEM, content, tool: CVINDEX_TOOL, maxTokens: 1500, model: MATCH_INDEX_MODEL });
    const g = await geocodeUK(out.postcode, out.town);
    return {
      ...base, status: 'ok', town: String(out.town || '').slice(0, 80), postcode: String(out.postcode || '').slice(0, 12),
      lat: g ? String(g.lat) : '', lng: g ? String(g.lng) : '',
      titles: (out.recent_titles || []).join('; ').slice(0, 400), skills: (out.key_skills || []).join('; ').slice(0, 800),
      profile: String(out.profile || '').slice(0, 4000),
    };
  } catch (e) {
    console.error('CV index failed for', p.id, e.message);
    return { ...base, status: 'failed', town: '', postcode: '', lat: '', lng: '', titles: '', skills: '', profile: '' };
  }
}

/* ---------- AI ranking ---------- */
const MATCH_SYSTEM = `You rank candidates from a UK recruitment agency's talent pool against ONE open role. You are the agency's senior researcher: sharp, fair and specific.

For every candidate return:
- score 0-100 for how well they fit this role: relevant job titles and seniority, the required skills and systems, sector knowledge, and evidence of results. 85+ is a strong, interview-ready match; 60-84 is plausible; below 40 is a weak match.
- reason: one plain sentence (maximum 28 words) naming the strongest evidence for or against. No em dashes.
- strengths: up to 3 short phrases.
- negative: true ONLY if the candidate's notes or history show a clear red flag for this kind of role: they lack a skill or qualification the role requires, interviewed badly or were assessed as weak, were rejected by a client for capability or fit, withdrew or said they are not interested or not available, no-showed, failed checks, or have a salary or travel expectation that cannot be bridged. Neutral notes, or rejections for reasons outside the candidate's control (role filled, hiring freeze, client changed brief), are NOT negative.
- negative_reason: when negative is true, the specific red flag in plain words (maximum 20 words). Otherwise an empty string.

Use ONLY the information supplied. Never invent experience. Judge by the role requirements and job description first.`;
const MATCH_TOOL = {
  name: 'rank_candidates',
  description: 'Return a score for every candidate supplied.',
  input_schema: {
    type: 'object',
    properties: {
      results: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            score: { type: 'number' },
            reason: { type: 'string' },
            strengths: { type: 'array', items: { type: 'string' } },
            negative: { type: 'boolean' },
            negative_reason: { type: 'string' },
          },
          required: ['id', 'score', 'reason', 'strengths', 'negative', 'negative_reason'],
        },
      },
    },
    required: ['results'],
  },
};

async function scoreBatch(roleCtx, items) {
  const cands = items.map(it => [
    `ID: ${it.p.id}`,
    `Previously applied for: ${it.p.role}${it.p.company ? ` at ${it.p.company}` : ''}; furthest stage reached: ${String(it.p.furthestStage).replace(/_/g, ' ')}`,
    it.idx && it.idx.town ? `Based in: ${it.idx.town}` : '',
    it.p.tags ? `Tags: ${it.p.tags}` : '',
    it.idx && it.idx.titles ? `Recent titles: ${it.idx.titles}` : '',
    it.idx && it.idx.profile ? `CV profile: ${it.idx.profile}` : 'CV profile: not available',
    `Recruiter notes: ${String(it.p.notes || '').trim().slice(0, 1500) || 'None'}`,
  ].filter(Boolean).join('\n')).join('\n\n----\n\n');
  const content = `ROLE: ${roleCtx.title}${roleCtx.location ? ` (location: ${roleCtx.location})` : ''}\n\nREQUIREMENTS:\n${roleCtx.requirements || 'None supplied'}\n\nJOB DESCRIPTION:\n${roleCtx.jobDescription || 'None supplied'}\n\nCANDIDATES TO RANK:\n\n${cands}`;
  const out = await callClaudeTool({ system: MATCH_SYSTEM, content, tool: MATCH_TOOL, maxTokens: 3500, model: MATCH_MODEL });
  const map = new Map();
  (out.results || []).forEach(r => { if (r && r.id) map.set(String(r.id), r); });
  return map;
}

/* ---------- Building the view ---------- */
async function loadMatchContext(company, roleName) {
  const roles = await rolesTable.list().catch(() => []);
  const role = roles.find(r => lc(r.company) === lc(company) && (lc(r.role) === lc(roleName) || lc(r.public_title) === lc(roleName))) || {};
  const brief = await loadRoleBrief(role.role || roleName).catch(() => ({ requirements: '', jobDescription: '' }));
  const requirements = String(brief.requirements || role.requirements || '').trim();
  const jobDescription = String(brief.jobDescription || role.public_content || '').trim().slice(0, 6000);
  const roleCtx = { title: role.public_title || roleName, location: role.location || '', requirements: requirements.slice(0, 3000), jobDescription };
  const roleHash = sha1(JSON.stringify([roleCtx.title, roleCtx.location, roleCtx.requirements, roleCtx.jobDescription]));
  const origin = await resolveRoleOrigin(company, role);
  const [poolRaw, idxRows, scoreRows] = await Promise.all([
    readPoolRows(), poolCvIndexTable.list().catch(() => []), poolMatchTable.list().catch(() => []),
  ]);
  return { role, roleCtx, roleHash, origin, poolRaw, idxMap: new Map(idxRows.map(o => [o.id, o])), scoreRows };
}

function buildMatchView(company, roleName, ctx, opts) {
  const { role, roleCtx, roleHash, origin, poolRaw, idxMap, scoreRows } = ctx;
  const key = matchRoleKey(company, roleName);
  const scoreMap = new Map(scoreRows.filter(r => r.role_key === key).map(r => [r.pool_id, r]));
  const bodyTokens = tokenSet(`${roleCtx.title} ${roleCtx.requirements} ${roleCtx.jobDescription}`);
  let excludedConsent = 0, considered = 0;
  const items = [];
  for (const row of poolRaw) {
    if (!row || !row[0]) continue;
    const p = rowToPoolEntry(row);
    p.cvFileId = row[11] || '';
    if (lc(p.erased) === 'yes') continue;
    if (lc(p.role) === lc(roleName) && lc(p.company || company) === lc(company) && p.inPipeline) continue;
    considered++;
    const basis = lc(p.consentBasis);
    const okConsent = basis.includes('talent pool') || basis.includes('legitimate') || (basis.includes('consent') && !basis.includes('this role only'));
    if (!okConsent || basis.includes('this role only')) { excludedConsent++; continue; }

    const idx = idxMap.get(p.id) || null;
    const indexFresh = !!(idx && idx.cv_file_id === p.cvFileId);
    const needsIndex = !!(p.cvFileId && !indexFresh);
    const hasLoc = !!(indexFresh && idx.lat !== '' && idx.lng !== '' && !isNaN(parseFloat(idx.lat)));
    let distance = null;
    if (hasLoc && origin.ok) distance = Math.round(milesBetween({ lat: origin.lat, lng: origin.lng }, { lat: parseFloat(idx.lat), lng: parseFloat(idx.lng) }) * 10) / 10;
    let band = 'unknown';
    if (distance !== null) band = distance <= MATCH_RADIUS_MILES ? 'within' : 'outside';

    const candTokens = tokenSet(`${p.role} ${p.tags || ''} ${p.notes || ''} ${indexFresh ? `${idx.titles} ${idx.skills} ${idx.profile}` : ''}`);
    let kw = 0; bodyTokens.forEach(t => { if (candTokens.has(t)) kw++; });
    const inputHash = sha1(JSON.stringify([roleHash, p.notes, p.tags, p.furthestStage, p.currentStage, p.cvFileId, indexFresh ? idx.indexed_at : '']));
    const sc = scoreMap.get(p.id) || null;
    const scored = !!(sc && sc.score !== '' && sc.input_hash === inputHash);
    const stale = !!(sc && sc.score !== '' && !scored);
    const ai = scored || stale ? parseFloat(sc.score) : null;
    const prox = distance !== null ? Math.max(0, 100 * (1 - distance / MATCH_RADIUS_MILES)) : null;
    const combined = ai === null ? null : Math.round(prox === null ? ai : 0.75 * ai + 0.25 * prox);
    items.push({
      id: p.id, name: p.name, email: p.email, phone: p.phone, previousRole: p.role, previousCompany: p.company,
      furthestStage: p.furthestStage, tags: p.tags, hasCv: p.hasCv, consentDate: p.consentDate,
      indexed: indexFresh && idx.status === 'ok', cvProblem: indexFresh && idx.status !== 'ok',
      town: indexFresh ? idx.town : '', distance, band, kw,
      ai, combined, scored, stale,
      reason: sc ? sc.reason : '', strengths: sc && sc.strengths ? String(sc.strengths).split('; ').filter(Boolean) : [],
      negative: !!(sc && String(sc.negative).toUpperCase() === 'TRUE'), negativeReason: sc ? sc.negative_reason : '',
      shortlisted: !!(sc && String(sc.shortlisted).toUpperCase() === 'TRUE'),
      needsIndex, _p: p, _idx: indexFresh ? idx : null, _hash: inputHash,
    });
  }
  const order = (a, b) => {
    if (a.negative !== b.negative) return a.negative ? 1 : -1;
    const as = a.combined !== null, bs = b.combined !== null;
    if (as !== bs) return as ? -1 : 1;
    if (as) return b.combined - a.combined;
    return b.kw - a.kw;
  };
  const within = items.filter(i => i.band === 'within').sort(order);
  const unknown = items.filter(i => i.band === 'unknown').sort(order);
  const outside = items.filter(i => i.band === 'outside').sort((a, b) => a.distance - b.distance);
  const needsIndex = items.filter(i => i.needsIndex);
  const scorable = [...within, ...unknown].filter(i => !i.needsIndex && !i.scored).sort((a, b) => b.kw - a.kw).slice(0, MATCH_MAX_SCORED);
  return { key, within, unknown, outside, needsIndex, scorable, considered, excludedConsent };
}

function publicItem(i) { const { _p, _idx, _hash, ...rest } = i; return rest; }

app.get('/api/pool-matches', async (req, res) => {
  try {
    const company = String(req.query.company || ''), roleName = String(req.query.role || '');
    if (!roleName) return res.status(400).json({ error: 'role is required' });
    const ctx = await loadMatchContext(company, roleName);
    const v = buildMatchView(company, roleName, ctx);
    const shortlist = [...v.within, ...v.unknown, ...v.outside].filter(i => i.shortlisted);
    res.json({
      role: { company, role: roleName, location: ctx.role.location || '', salary_band: ctx.role.salary_band || '', public_title: ctx.role.public_title || '' },
      origin: { ok: ctx.origin.ok, label: ctx.origin.label }, radius: MATCH_RADIUS_MILES,
      shortlist: shortlist.map(publicItem),
      within: v.within.map(publicItem), unknown: v.unknown.map(publicItem), outside: v.outside.map(publicItem),
      pending: { needsIndex: v.needsIndex.length, needsScore: v.scorable.length },
      considered: v.considered, excludedConsent: v.excludedConsent,
    });
  } catch (e) {
    console.error('GET /api/pool-matches error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Does one batch of work (read some CVs, or score some people). The page calls it repeatedly until nothing is left.
app.post('/api/pool-matches/process', async (req, res) => {
  try {
    const b = req.body || {};
    const company = String(b.company || ''), roleName = String(b.role || '');
    if (!roleName) return res.status(400).json({ error: 'role is required' });
    if (!API_KEY) return res.status(500).json({ error: 'The AI key is not set on the server' });
    const key = matchRoleKey(company, roleName);
    if (b.force && b.first) {
      // Re-score: forget the saved scores for this role (shortlist ticks are kept)
      await poolMatchTable.updateWhere(o => o.role_key === key, o => ({ ...o, input_hash: '' }));
      // also give any CV that could not be read last time another go
      await poolCvIndexTable.updateWhere(o => o.status && o.status !== 'ok', o => ({ ...o, cv_file_id: '' }));
    }
    const ctx = await loadMatchContext(company, roleName);
    let v = buildMatchView(company, roleName, ctx);
    const done = { indexed: 0, scored: 0 };

    if (v.needsIndex.length) {
      const batch = v.needsIndex.slice(0, MATCH_INDEX_BATCH);
      const rows = await Promise.all(batch.map(i => indexOneCv(i._p)));
      await bulkUpsert(poolCvIndexTable, rows);
      done.indexed = rows.length;
      ctx.idxMap = new Map([...ctx.idxMap, ...rows.map(r => [r.id, r])]);
      v = buildMatchView(company, roleName, ctx);
    } else if (v.scorable.length) {
      const batch = v.scorable.slice(0, MATCH_SCORE_BATCH);
      const map = await scoreBatch(ctx.roleCtx, batch.map(i => ({ p: i._p, idx: i._idx })));
      const now = new Date().toISOString();
      const existing = new Map(ctx.scoreRows.filter(r => r.role_key === key).map(r => [r.pool_id, r]));
      const rows = [];
      batch.forEach(i => {
        const r = map.get(String(i.id));
        if (!r) return;
        const prev = existing.get(i.id);
        const score = Math.max(0, Math.min(100, Math.round(Number(r.score) || 0)));
        rows.push({
          id: `${key}|${i.id}`, role_key: key, pool_id: i.id, score: String(score),
          reason: String(r.reason || '').slice(0, 300), negative: r.negative ? 'TRUE' : 'FALSE',
          negative_reason: r.negative ? String(r.negative_reason || '').slice(0, 200) : '',
          strengths: (r.strengths || []).slice(0, 3).join('; ').slice(0, 300),
          input_hash: i._hash, scored_at: now, shortlisted: prev ? prev.shortlisted : 'FALSE',
        });
      });
      await bulkUpsert(poolMatchTable, rows);
      done.scored = rows.length;
      if (rows.length) auditLog(auditActorOf(req), 'pool_ai_ranked', 'pool', `${roleName}${company ? ` - ${company}` : ''}`, `${rows.length} ranked`);
      ctx.scoreRows = [...ctx.scoreRows.filter(r => !(r.role_key === key && rows.some(x => x.pool_id === r.pool_id))), ...rows];
      v = buildMatchView(company, roleName, ctx);
    }
    res.json({ ok: true, done, remaining: { needsIndex: v.needsIndex.length, needsScore: v.scorable.length } });
  } catch (e) {
    console.error('POST /api/pool-matches/process error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/pool-matches/shortlist', async (req, res) => {
  try {
    const b = req.body || {};
    const company = String(b.company || ''), roleName = String(b.role || ''), poolId = String(b.poolId || '');
    if (!roleName || !poolId) return res.status(400).json({ error: 'role and poolId are required' });
    const key = matchRoleKey(company, roleName);
    const id = `${key}|${poolId}`;
    const flag = b.shortlisted ? 'TRUE' : 'FALSE';
    const existing = (await poolMatchTable.list()).find(o => o.id === id);
    if (existing) await poolMatchTable.updateWhere(o => o.id === id, o => ({ ...o, shortlisted: flag }));
    else await poolMatchTable.append({ id, role_key: key, pool_id: poolId, score: '', reason: '', negative: 'FALSE', negative_reason: '', strengths: '', input_hash: '', scored_at: '', shortlisted: flag });
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/pool-matches/shortlist error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Used by the erase tool: remove everything the matching feature holds about one person
async function purgeMatchData(poolIds) {
  const ids = new Set(poolIds);
  let n = 0;
  for (const o of await poolCvIndexTable.listAll()) if (ids.has(o.id)) { await poolCvIndexTable.remove(o.id); n++; }
  for (const o of await poolMatchTable.listAll()) if (ids.has(o.pool_id)) { await poolMatchTable.remove(o.id); n++; }
  return n;
}

/* ---------- Compliance helpers used by documents and tasks ---------- */
const RTW_DONE = ['verified'];
const REF_DONE = ['received', 'checked'];

async function complianceFor(company, name, role) {
  try {
    const id = placementKey(company, name, role);
    return (await complianceTable.list()).find(o => o.id === id) || null;
  } catch (e) { return null; }
}

async function complianceTasks() {
  const list = [];
  const rows = (await readAllRows()).filter(r => r && r[0]).map(rowToCandidate)
    .filter(c => ['offer', 'start_date', 'day1'].includes(normStage(c.stage)) && !isTestRecord(c.name, c.notes));
  if (!rows.length) return list;
  const comp = new Map((await complianceTable.list().catch(() => [])).map(o => [o.id, o]));
  const t = todayISO();
  rows.forEach(c => {
    const k = placementKey(c.company, c.name, c.role);
    const rec = comp.get(k) || {};
    const sd = parseISODate(c.startDate);
    const days = sd ? daysBetween(new Date(), sd) : null;
    const base = slugKey(`${c.name}-${c.role}`);
    const who = `${c.name} (${c.role} at ${c.company})`;
    if (!RTW_DONE.includes(lc(rec.rtw_status)) && (days === null || days <= 5)) {
      list.push({ key: `${base}-rtw`, user: 'ella', priority: 'High', dueDate: t,
        title: `Right to work not verified: ${c.name}${sd ? ' starts ' + formatDateUK(toISODate(sd)) : ''}`,
        context: `${who}. Current status: ${rec.rtw_status || 'not requested'}. Collect and check the document, then mark it verified on the candidate card under Compliance.` });
    }
    const r1 = REF_DONE.includes(lc(rec.ref1_status)), r2 = REF_DONE.includes(lc(rec.ref2_status));
    if ((!r1 || !r2) && (days === null || days <= 5)) {
      list.push({ key: `${base}-refs`, user: 'ella', priority: 'Medium', dueDate: t,
        title: `References outstanding: ${c.name}`,
        context: `${who}. Reference 1: ${rec.ref1_status || 'not requested'}. Reference 2: ${rec.ref2_status || 'not requested'}. Update the status on the candidate card under Compliance.` });
    }
  });
  return list;
}

/* ---------- Client check-in emails ---------- */
OFFER_LABELS.guarantee_end = 'GUARANTEE END DATE';
OFFER_EMAILS.feedback_week1 = {
  to: 'client_email', subject: 'Checking in on {{candidate_first}}: week one at {{company}}', attach: [],
  body: `Dear {{client_contact}},\n\nI hope {{candidate_first}}'s first week as {{job_title}} has gone well.\n\nThis is our standard Week 1 check-in. Two quick questions, and a short reply is perfect:\n\n- How is {{candidate_first}} settling in, and is the role what you expected?\n- Is there anything you would like us to pick up with {{candidate_first}} on your behalf?\n\nIf anything needs attention, call me and I will deal with it the same day.\n\nKind regards,\n\n{{sig_consultant}}`,
};
OFFER_EMAILS.feedback_month1 = {
  to: 'client_email', subject: 'One month in: how is {{candidate_first}} getting on at {{company}}?', attach: [],
  body: `Dear {{client_contact}},\n\n{{candidate_first}} reaches one month at {{company}} this week, so this is our Month 1 check-in.\n\nCould you spare two minutes to tell me:\n\n- How is {{candidate_first}} performing against what you hoped for?\n- How did you find working with Live 2 Help, and is there anything we should do better?\n- Do you have any other vacancies coming up, or know of another business who may need support with hiring?\n\nAs a reminder, your replacement guarantee on this placement runs until {{guarantee_end}}, so please tell me early if you have any concerns.\n\nIf you have been happy with the service, a short review would mean a great deal to a growing business: https://g.page/r/CU5L4ObMovbGEBM/review\n\nThank you for your continued support.\n\nKind regards,\n\n{{sig_consultant}}`,
};


/* ======================================================================
   AUTOMATION BATCH D - Client reply links
   Each submission email can carry one short link per candidate. The client
   clicks it, sees a small branded page and answers in one click, with no
   login. The answer moves the card, logs feedback and emails the team.
   Links look like  https://<your api>/r/<code>  and expire after 30 days.
   ====================================================================== */

const replyLinksTable = makeSimpleTable({
  tab: 'Reply Links',
  header: ['id', 'created', 'expires', 'company', 'role', 'candidate_name', 'candidate_id', 'source_tab', 'form_role', 'contact', 'last_answer', 'last_answer_at', 'answers_json', 'sender_key', 'sender_name', 'sender_email'],
  path: null,
  label: 'Reply link',
});

const REPLY_DAYS = 30;
// Who gets the alert when a client answers: whoever built and sent the submission email.
const TEAM_CONTACTS = (() => {
  const base = {
    dan: { name: 'Dan', email: process.env.REPLY_EMAIL_DAN || 'dan.brown@live2helprecruitment.co.uk' },
    ella: { name: 'Ella', email: process.env.REPLY_EMAIL_ELLA || 'ella@live2helprecruitment.co.uk' },
  };
  try { Object.assign(base, JSON.parse(process.env.TEAM_CONTACTS_JSON || '{}')); } catch (e) { /* ignore bad JSON */ }
  return base;
})();
const REPLY_MOVE_FROM = {
  interested: ['applied', 'ready_to_submit', 'submitted'],
  not_interested: ['applied', 'ready_to_submit', 'submitted', 'interview_requested', 'interview_scheduled', 'interviewed'],
};
const REPLY_REASONS = {
  skills: 'Skills', experience: 'Experience level', salary: 'Salary expectations', culture: 'Culture or personality fit',
  location: 'Location or commute', availability: 'Availability or notice period', communication: 'Communication',
  timing: 'Timing or role changed', other: 'Other',
};

function replyBase(req) {
  return (process.env.PUBLIC_API_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}
function shortName(full) {
  const p = String(full || '').trim().split(/\s+/);
  return p.length > 1 ? `${p[0]} ${p[p.length - 1].charAt(0).toUpperCase()}` : (p[0] || 'Candidate');
}
const htmlEsc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// Change a candidate's stage straight in the sheet and/or append a note.
// Looks for the card where the link says it is, then in the other places a card can live, so a
// stale link can never leave a client answer unapplied. Returns { before, changed, where } or null.
function sameCandidateName(a, b) {
  a = lc(a); b = lc(b);
  if (!a || !b) return false;
  if (a === b) return true;
  const pa = a.split(/\s+/), pb = b.split(/\s+/);
  return pa.length > 1 && pb.length > 1 && pa[0] === pb[0] && pa[pa.length - 1].charAt(0) === pb[pb.length - 1].charAt(0);
}

async function applyStageChange(ref, newStage, allowFrom, noteAppend) {
  const sheets = getSheetsClient();
  const today = todayISO();
  const addNote = old => noteAppend ? ((old ? old + '\n' : '') + noteAppend) : old;

  const tryApplication = async () => {
    const formRoles = [...new Set([ref.formRole, ref.role].filter(Boolean))];
    for (const fr of formRoles) {
      const tabName = `Applications - ${fr}`;
      let rows;
      try {
        const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tabName}'!A2:U` });
        rows = r.data.values || [];
      } catch (e) { continue; }
      let idx = rows.findIndex(x => lc(x[2]) === lc(ref.name));
      if (idx < 0) idx = rows.findIndex(x => sameCandidateName(x[2], ref.name));
      if (idx < 0) continue;
      const row = rows[idx]; while (row.length < 21) row.push('');
      const before = normStage(row[19] || 'applied');
      const allowed = !!newStage && !(allowFrom && !allowFrom.includes(before));
      if (allowed) row[19] = newStage;
      if (noteAppend) row[20] = addNote(row[20]);
      if (!allowed && !noteAppend) return { before, changed: false, where: 'application' };
      await sheets.spreadsheets.values.update({ spreadsheetId: SHEET_ID, range: `'${tabName}'!A${idx + 2}:U${idx + 2}`, valueInputOption: 'RAW', requestBody: { values: [row] } });
      return { before, changed: allowed, where: 'application' };
    }
    return null;
  };

  const tryDashboard = async () => {
    const rows = await readAllRows();
    let idx = ref.id ? rows.findIndex(x => x && x[0] === ref.id) : -1;
    if (idx < 0) idx = rows.findIndex(x => x && lc(x[3]) === lc(ref.name) && lc(x[2]) === lc(ref.role));
    if (idx < 0) idx = rows.findIndex(x => x && sameCandidateName(x[3], ref.name) && lc(x[2]) === lc(ref.role));
    if (idx < 0) return null;
    const row = rows[idx]; while (row.length < 12) row.push('');
    const before = normStage(row[4] || 'submitted');
    const allowed = !!newStage && !(allowFrom && !allowFrom.includes(before));
    if (allowed) { row[4] = newStage; row[5] = today; }
    if (noteAppend) row[6] = addNote(row[6]);
    if (!allowed && !noteAppend) return { before, changed: false, where: 'dashboard' };
    await sheets.spreadsheets.values.update({ spreadsheetId: SHEET_ID, range: `${TAB}!A${idx + 2}:L${idx + 2}`, valueInputOption: 'RAW', requestBody: { values: [row] } });
    return { before, changed: allowed, where: 'dashboard' };
  };

  const order = ref.sourceTab === 'application' ? [tryApplication, tryDashboard] : [tryDashboard, tryApplication];
  for (const fn of order) {
    const r = await fn().catch(e => { console.error('applyStageChange lookup failed:', e.message); return null; });
    if (r) return r;
  }
  return null;
}

// Create (or reuse) links for the candidates in a submission email
app.post('/api/reply-links', async (req, res) => {
  try {
    const list = Array.isArray((req.body || {}).candidates) ? req.body.candidates : [];
    if (!list.length) return res.status(400).json({ error: 'candidates are required' });
    const existing = await replyLinksTable.list();
    const now = Date.now();
    const out = [];
    const senderKey = String((req.body || {}).sender || '').toLowerCase();
    const sender = TEAM_CONTACTS[senderKey] ? { key: senderKey, name: TEAM_CONTACTS[senderKey].name, email: TEAM_CONTACTS[senderKey].email } : { key: '', name: '', email: '' };
    for (const c of list) {
      if (!c || !c.id || !c.name || !c.role) continue;
      let link = existing.find(o => o.candidate_id === c.id && lc(o.role) === lc(c.role) && o.expires && new Date(o.expires).getTime() > now + 5 * 86400000);
      if (!link) {
        link = {
          id: crypto.randomBytes(9).toString('base64url'),
          created: new Date().toISOString(), expires: new Date(now + REPLY_DAYS * 86400000).toISOString(),
          company: c.company || '', role: c.role, candidate_name: c.name, candidate_id: c.id,
          source_tab: c.sourceTab || '', form_role: c.formRole || '', contact: c.contact || '',
          last_answer: '', last_answer_at: '', answers_json: '[]',
          sender_key: sender.key, sender_name: sender.name, sender_email: sender.email,
        };
        await replyLinksTable.upsert(link);
        existing.push(link);
      } else if (sender.key && link.sender_key !== sender.key) {
        // Whoever builds the email now is the one who gets the alert
        link.sender_key = sender.key; link.sender_name = sender.name; link.sender_email = sender.email;
        await replyLinksTable.upsert(link);
      }
      out.push({ id: c.id, name: c.name, url: `${replyBase(req)}/r/${link.id}` });
    }
    replyLinkCache = { at: 0, list: null };
    auditLog(auditActorOf(req), 'reply_links_created', 'candidate', `${out.length} link${out.length === 1 ? '' : 's'}`, '');
    res.json({ links: out });
  } catch (e) {
    console.error('POST /api/reply-links error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

function replyPage(link, state) {
  const nm = htmlEsc(shortName(link.candidate_name)), role = htmlEsc(link.role);
  const done = state.done ? `<div class="done">${state.done}</div>` : '';
  const reasons = Object.entries(REPLY_REASONS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reply: ${nm} - ${role}</title><meta name="robots" content="noindex,nofollow">
<style>
:root{--navy:#0B0B18;--gold:#C9A84C;--ink:#1A1A1A;--grey:#555;--line:#DDD;--bg:#F7F6F3}
*{box-sizing:border-box}body{margin:0;font-family:"Gill Sans MT","Gill Sans",Calibri,Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{background:var(--navy);padding:18px 20px;border-bottom:3px solid var(--gold);color:#fff;letter-spacing:2px;font-size:13px}
header b{color:var(--gold)}
main{max-width:560px;margin:0 auto;padding:22px 18px 40px}
h1{font-size:21px;margin:6px 0 4px}p{line-height:1.5;color:var(--grey);font-size:15px}
.card{background:#fff;border:1px solid var(--line);border-top:3px solid var(--gold);padding:18px;margin:16px 0}
button.big{display:block;width:100%;padding:15px;margin:10px 0;border:1px solid var(--ink);background:#fff;font:inherit;font-size:16px;cursor:pointer;border-radius:2px;text-align:left}
button.big strong{display:block}button.big span{font-size:13px;color:var(--grey)}
button.gold{background:var(--gold);border-color:var(--gold)}button.gold span{color:#3a2f0b}
select,textarea,input{width:100%;padding:11px;border:1px solid var(--line);font:inherit;font-size:16px;margin:6px 0 10px;border-radius:2px;background:#fff}
textarea{min-height:90px}label{font-size:12px;color:#888;letter-spacing:.5px;display:block}
.row2{display:grid;grid-template-columns:3fr 2fr;gap:10px}
.done{background:#EAF4EC;border-left:4px solid #2E7D4F;padding:12px 14px;margin:14px 0;font-size:15px}
.err{background:#FDF1EF;border-left:4px solid #B3372B;padding:12px 14px;margin:14px 0;font-size:14px;display:none}
.link{background:none;border:none;color:var(--grey);text-decoration:underline;cursor:pointer;font:inherit;font-size:14px;padding:6px 0;width:auto}
.hint{font-size:13px;color:#888;margin:0 0 8px}
.opt{display:inline-block;background:#F1EBD8;color:#6b5a1c;font-size:11px;padding:1px 8px;border-radius:9px;margin-left:6px;letter-spacing:0;font-weight:600}
.chk{display:flex;gap:12px;align-items:center;padding:12px 14px;border:1px solid var(--line);margin:6px 0;background:#fff;font-size:16px;color:var(--ink);letter-spacing:0;cursor:pointer;border-radius:2px}
.chk input{width:22px;height:22px;margin:0;padding:0;flex:none}
.chk:has(input:checked){border-color:var(--gold);background:#FBF6EA}
.note{font-size:13px;color:#888;margin:2px 0 0;text-align:center}
.sub{display:none}
footer{text-align:center;color:#999;font-size:12px;padding:16px}
</style></head><body>
<header>LIVE <b>2</b> HELP RECRUITMENT</header>
<main>
<h1>${nm}</h1><p>${role}${link.company ? ' - ' + htmlEsc(link.company) : ''}</p>
${done}
<div class="err" id="err"></div>
<div class="card" id="choices">
<p style="margin-top:0">Tell us what you would like to do next. We act on your answer straight away.</p>
<button class="big gold" onclick="show('yes')"><strong>Interested - arrange an interview</strong><span>You can suggest a date and time on the next step</span></button>
<button class="big" onclick="show('more')"><strong>I need more information first</strong><span>Tell us what you would like to know</span></button>
<button class="big" onclick="show('no')"><strong>Not for us</strong><span>Tick the reason and we will keep looking</span></button>
</div>
<div class="card sub" id="yes">
<p class="hint"><strong style="color:#1A1A1A">Everything on this page is optional.</strong> You can simply press Send and we will arrange the interview time with you.</p>
<label>FIRST CHOICE OF DATE AND TIME <span class="opt">Optional</span></label><div class="row2"><input type="date" id="d1"><input type="time" id="t1"></div>
<label>SECOND CHOICE <span class="opt">Optional</span></label><div class="row2"><input type="date" id="d2"><input type="time" id="t2"></div>
<label>LOCATION, WHO IS INTERVIEWING, OR ANYTHING ELSE <span class="opt">Optional</span></label><textarea id="extra" placeholder="Leave blank if you prefer. For example: at your site, with the Supply Chain Manager, one hour"></textarea>
<button class="big gold" onclick="send('interested')"><strong>Send</strong></button><p class="note">Nothing above is required</p><button class="link" onclick="show('choices')">Back</button></div>
<div class="card sub" id="more"><label>WHAT WOULD YOU LIKE TO KNOW?</label><textarea id="msg" placeholder="For example: notice period, salary expectation, reasons for leaving"></textarea>
<button class="big gold" onclick="send('more_info')"><strong>Send</strong></button><button class="link" onclick="show('choices')">Back</button></div>
<div class="card sub" id="no"><label>TICK THE REASON(S) - ONE OR MORE</label>
${Object.entries(REPLY_REASONS).map(([k, v]) => `<label class="chk"><input type="checkbox" name="why" value="${k}"><span>${v}</span></label>`).join('')}
<label style="margin-top:14px">ANYTHING ELSE <span class="opt">Optional</span></label><textarea id="detail" placeholder="Leave blank if you prefer. This helps us find you a better match"></textarea>
<button class="big gold" onclick="send('not_interested')"><strong>Send</strong></button><button class="link" onclick="show('choices')">Back</button></div>
</main><footer>Live 2 Help Recruitment Ltd - Anyone - Anywhere - Anytime</footer>
<script>
var today=new Date().toISOString().slice(0,10);['d1','d2'].forEach(function(i){document.getElementById(i).min=today;});
function show(id){['choices','yes','more','no'].forEach(function(x){var e=document.getElementById(x);e.style.display=(x===id)?'block':'none';});document.getElementById('err').style.display='none';window.scrollTo(0,0);}
function fail(m){var err=document.getElementById('err');err.textContent=m;err.style.display='block';window.scrollTo(0,0);}
async function send(a){
  var body={answer:a,message:document.getElementById('msg').value,reasons:Array.prototype.map.call(document.querySelectorAll('input[name=why]:checked'),function(x){return x.value;}),detail:document.getElementById('detail').value,extra:document.getElementById('extra').value,slots:[]};
  [['d1','t1'],['d2','t2']].forEach(function(p){var d=document.getElementById(p[0]).value;if(d)body.slots.push({date:d,time:document.getElementById(p[1]).value});});
  if(a==='not_interested'&&!body.reasons.length){fail('Please tick at least one reason.');return;}
  if(a==='more_info'&&!body.message.trim()){fail('Please tell us what you would like to know.');return;}
  try{
    var r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var j=await r.json().catch(function(){return{};});
    if(!r.ok) throw new Error(j.error||'Something went wrong');
    document.querySelector('main').innerHTML='<h1>Thank you</h1><div class="done">'+j.message+'</div><p>You can close this page. If you need to change your answer, reply to our email and we will update it.</p>';
  }catch(e){fail(e.message+' If it keeps failing, please reply to the email instead.');}
}
var q=new URLSearchParams(location.search).get('a');if(q==='yes')show('yes');else if(q==='no')show('no');
</script></body></html>`;
}

let replyLinkCache = { at: 0, list: null };
async function loadReplyLink(id, fresh) {
  if (!/^[A-Za-z0-9_-]{8,20}$/.test(String(id || ''))) return null;
  const usable = !fresh && replyLinkCache.list && Date.now() - replyLinkCache.at < 30 * 60 * 1000;
  if (usable) {
    const hit = replyLinkCache.list.find(o => o.id === id);
    if (hit) return hit;
  }
  const list = await replyLinksTable.list();
  replyLinkCache = { at: Date.now(), list };
  return list.find(o => o.id === id) || null;
}

app.get('/r/:id', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const link = await loadReplyLink(req.params.id);
    if (!link) return res.status(404).type('html').send('<p style="font-family:sans-serif;padding:30px">This link is not valid. Please reply to our email instead.</p>');
    if (new Date(link.expires).getTime() < Date.now()) return res.status(410).type('html').send('<p style="font-family:sans-serif;padding:30px">This link has expired. Please reply to our email and we will help.</p>');
    const prev = link.last_answer ? `Your last reply was recorded on ${htmlEsc(offerPlainDate(String(link.last_answer_at).slice(0, 10)))}. You can change it below.` : '';
    res.type('html').send(replyPage(link, { done: prev }));
  } catch (e) {
    console.error('GET /r/:id error:', e.message);
    res.status(500).type('html').send('<p style="font-family:sans-serif;padding:30px">Something went wrong. Please reply to our email instead.</p>');
  }
});

const replyHits = new Map();

function cleanSlot(s) {
  const d = String((s && s.date) || ''), t = String((s && s.time) || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return null;
  const dt = parseISODate(d);
  if (!dt) return null;
  const days = daysBetween(new Date(), dt);
  if (days < -1 || days > 120) return null;
  const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(t) ? t : '';
  return { date: d, time, text: `${offerLongDate(d)}${time ? ' at ' + time : ''}` };
}
function oneLine(s, n) { return String(s || '').replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n); }

// Builds the note that is added to the candidate card. No reply to the client is written or sent by the system.
function buildReplyNote(answer, c) {
  if (answer === 'interested') {
    const opts = c.slots.map((s, i) => `${c.slots.length > 1 ? 'Option ' + (i + 1) + ': ' : ''}${s.text}`);
    return `[Client reply ${c.today}: interested in an interview.` + (c.slots.length ? ` Preferred: ${opts.join('; ')}.` : ' No time given.') + (c.extra ? ` Note: ${c.extra}.` : '') + ']';
  }
  if (answer === 'not_interested') {
    return `[Client reply ${c.today}: not taking ${c.label} forward. Reasons: ${c.reasonText}.${c.detail ? ' ' + c.detail + '.' : ''}]`;
  }
  return `[Client reply ${c.today}: asked for more information on ${c.label}: ${c.message}]`;
}

const recentReplyJobs = new Map();

// Does all the work after a client has been thanked: moves the card, adds the task, alerts the sender,
// and records the result for the dashboard pop-up. If it cannot finish, the sender gets an email with the
// client's full answer so nothing is ever lost.
async function runReplyJob(j) {
  const { answer, reasons, reasonText, message, label, slots, ctx, note, ref, newStage, summary } = j;
  let link = j.link;
  const outcome = { moved: false, found: false, before: '', taskAdded: false, emailed: false, emailError: '', failed: '' };
  const notifyTo = link.sender_email || process.env.REPLY_NOTIFY_TO || TEAM_CONTACTS.ella.email;
  const who = TEAM_CONTACTS[link.sender_key] ? link.sender_key : 'ella';
  const plainNote = note.replace(/^\[|\]$/g, '');

  // 1. Move the card and save the note (retried, because this is the part that must not be lost)
  let moved = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try { moved = await applyStageChange(ref, newStage, REPLY_MOVE_FROM[answer], note); outcome.failed = ''; break; }
    catch (e) { outcome.failed = String(e.message || e).slice(0, 160); console.error(`reply stage change attempt ${attempt} failed:`, e.message); await new Promise(r => setTimeout(r, 1500 * attempt)); }
  }
  outcome.moved = !!(moved && moved.changed);
  outcome.found = !!moved;
  outcome.before = moved ? moved.before : '';
  if (outcome.moved) {
    stageAutomation({ name: link.candidate_name, role: link.role, company: link.company, notes: '' }, newStage);
    scheduleReconcile();
  }

  // 2. Everything else is independent, so run it together
  const tasks = [];
  if (answer === 'not_interested') {
    tasks.push(feedbackTable.upsert({ id: `fb-${Date.now()}`, date: todayISO(), company: link.company, role: link.role, candidate_name: link.candidate_name,
      outcome: 'rejected_by_client', reason: reasons[0], detail: (reasons.length > 1 ? `All reasons ticked: ${reasonText}. ` : '') + (ctx.detail || 'Replied through the one-click link'), logged_by: 'client reply link' })
      .catch(e => console.error('reply feedback log failed:', e.message)));
  }
  tasks.push((async () => {
    try {
      const tTitle = answer === 'interested'
        ? `Confirm interview for ${label} with ${link.company}${slots.length ? ': ' + slots[0].text : ''}`
        : answer === 'not_interested' ? `Reply to ${link.company} about ${label} (not taking forward)` : `${link.company} wants more information on ${label}`;
      const tCtx = plainNote + '. ' + (answer === 'interested' ? 'Call the candidate to check the time, then reply to the client yourself.' : answer === 'more_info' ? 'Answer once only, then ask them to decide: interview or reject. Reply to the client yourself.' : 'Reply to the client yourself.');
      const added = await addAutoTasks([{ key: `${slugKey(link.candidate_name + '-' + link.role)}-clientreply-${Date.now().toString(36)}`, priority: 'High', dueDate: todayISO(), title: tTitle, context: tCtx, user: who }]);
      outcome.taskAdded = added > 0;
    } catch (e) { console.error('reply task failed:', e.message); }
  })());
  tasks.push(commsTable.upsert({ id: `cm-${Date.now()}`, timestamp: new Date().toISOString(), user: 'client', entity_type: 'candidate', entity_name: link.candidate_name,
    company: link.company, role: link.role, channel: 'Reply link', direction: 'In', summary: plainNote, follow_up_date: '', follow_up_done: '' })
    .catch(e => console.error('reply comms log failed:', e.message)));
  await Promise.all(tasks);

  // 3. Alert the sender
  const stageNote = answer === 'more_info' ? 'No stage change. The question is saved in the candidate notes.'
    : outcome.failed ? 'The dashboard could not be updated after three tries, so please move the card yourself.'
    : !moved ? 'The candidate could not be found on the board, so please check it.'
    : moved.changed ? `The card has moved to ${newStage.replace(/_/g, ' ')} and the reply is saved in the candidate notes.`
    : `The card was not moved because it is already at ${moved.before.replace(/_/g, ' ')}. The reply is saved in the candidate notes.`;
  try {
    if (!process.env.BREVO_SMTP_USER || !process.env.BREVO_SMTP_PASS || !process.env.BREVO_SENDER_EMAIL) throw new Error('Brevo email settings are missing on the server');
    await emailTransporter.sendMail({
      from: process.env.BREVO_SENDER_EMAIL, to: notifyTo,
      subject: `Client reply: ${summary}`,
      text: `${summary}\n\n${plainNote}\n\n${stageNote}\n\nA task has been added to your Tasks tab. Please reply to the client personally.\n\nLive 2 Help dashboard`,
    });
    outcome.emailed = true;
  } catch (e) { outcome.emailError = String(e.message || e).slice(0, 160); console.error('reply notify failed:', e.message); }

  // 4. Record the result for the dashboard pop-up (fresh read, so earlier answers are never overwritten)
  try {
    const fresh = (await loadReplyLink(link.id, true)) || link;
    const answers = (() => { try { return JSON.parse(fresh.answers_json || '[]'); } catch (e) { return []; } })();
    answers.push({ at: new Date().toISOString(), answer, reasons, slots: slots.map(s => s.text), note: (ctx.extra || ctx.detail || message || '').slice(0, 200), message: message.slice(0, 300),
      moved: outcome.moved, found: outcome.found && !outcome.failed, before: outcome.before, to: outcome.moved ? newStage : '', taskAdded: outcome.taskAdded, emailed: outcome.emailed, emailError: outcome.emailError || outcome.failed });
    const updated = { ...fresh, last_answer: answer, last_answer_at: new Date().toISOString(), answers_json: JSON.stringify(answers.slice(-10)) };
    await replyLinksTable.upsert(updated);
    if (replyLinkCache.list) { const i = replyLinkCache.list.findIndex(o => o.id === link.id); if (i >= 0) replyLinkCache.list[i] = updated; }
  } catch (e) {
    console.error('reply result not recorded:', e.message, JSON.stringify({ link: link.id, answer, note: plainNote }));
  }
  auditLog('client-link', 'client_reply', 'candidate', `${link.candidate_name} - ${link.role}`, `${answer}${outcome.moved ? ' (moved)' : outcome.found ? ' (left as is: ' + outcome.before + ')' : ' (card not found)'}`);
}

app.post('/r/:id', async (req, res) => {
  try {
    const ip = req.ip || 'x', now = Date.now();
    const hits = (replyHits.get(ip) || []).filter(t => now - t < 60000);
    if (hits.length >= 12) return res.status(429).json({ error: 'Too many attempts, please wait a minute.' });
    hits.push(now); replyHits.set(ip, hits);

    const link = await loadReplyLink(req.params.id);
    if (!link) return res.status(404).json({ error: 'This link is not valid.' });
    if (new Date(link.expires).getTime() < now) return res.status(410).json({ error: 'This link has expired.' });
    const b = req.body || {};
    const answer = String(b.answer || '');
    if (!['interested', 'not_interested', 'more_info'].includes(answer)) return res.status(400).json({ error: 'Unknown answer.' });
    let reasons = (Array.isArray(b.reasons) ? b.reasons : []).filter(k => REPLY_REASONS[k]).filter((k, i, a) => a.indexOf(k) === i).slice(0, 9);
    if (!reasons.length && REPLY_REASONS[b.reason]) reasons = [b.reason];
    if (answer === 'not_interested' && !reasons.length) return res.status(400).json({ error: 'Please tick at least one reason.' });
    const reasonText = reasons.map(k => REPLY_REASONS[k]).join(', ');
    const message = oneLine(b.message, 600);
    if (answer === 'more_info' && !message) return res.status(400).json({ error: 'Please tell us what you would like to know.' });

    const label = shortName(link.candidate_name);
    const slots = (Array.isArray(b.slots) ? b.slots : []).slice(0, 2).map(cleanSlot).filter(Boolean);
    const ctx = { label, contact: link.contact, today: todayISO(), slots, extra: oneLine(b.extra, 400), reasonText, detail: oneLine(b.detail, 600), message };
    const note = buildReplyNote(answer, ctx);
    const ref = { id: link.candidate_id, sourceTab: link.source_tab, formRole: link.form_role, name: link.candidate_name, role: link.role, company: link.company };
    const newStage = answer === 'interested' ? 'interview_requested' : answer === 'not_interested' ? 'rejected' : '';

    let summary, thanks;
    if (answer === 'interested') {
      summary = `${link.company} replied: interested in ${label}` + (slots.length ? ` - ${slots.map(s => s.text).join(' or ')}` : '');
      thanks = slots.length
        ? `Thank you. We have noted your preferred ${slots.length > 1 ? 'times' : 'time'} and will confirm with ${htmlEsc(label)} shortly.`
        : `Thank you. We will contact ${htmlEsc(label)} now and come back to you to confirm interview times.`;
    } else if (answer === 'not_interested') {
      summary = `${link.company} replied: not for them - ${label} (${reasonText})`;
      thanks = 'Thank you for letting us know. We will keep searching and send you stronger matches.';
    } else {
      summary = `${link.company} asked for more information on ${label}: ${message}`;
      thanks = 'Thank you. We will come back to you shortly with the answer.';
    }

    // Answer the client straight away. Everything below happens in the background.
    const dupKey = `${link.id}|${answer}|${note}`;
    const lastSame = recentReplyJobs.get(dupKey);
    res.json({ ok: true, message: thanks });
    if (lastSame && now - lastSame < 20000) return; // a double click: already being handled
    recentReplyJobs.set(dupKey, now);
    setTimeout(() => recentReplyJobs.delete(dupKey), 60000);
    setImmediate(() => {
      runReplyJob({ link, answer, reasons, reasonText, message, label, slots, ctx, note, ref, newStage, summary })
        .catch(e => console.error('reply job crashed:', e.message));
    });
  } catch (e) {
    console.error('POST /r/:id error:', e.message);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

// Lets the dashboard show which server version is live
const SERVER_BUILD = '2 Oct 2026 - build 7';
app.get('/api/version', (req, res) => res.json({ build: SERVER_BUILD }));

// Recent client answers from the one-click reply links, for the pop-up on the dashboard.
// Each person sees the replies to the emails they built (anything without a sender is shown to everyone).
app.get('/api/reply-activity', async (req, res) => {
  try {
    const me = actorOf(req);
    const cutoff = Date.now() - 14 * 86400000;
    const out = [];
    (await replyLinksTable.list()).forEach(l => {
      if (l.sender_key && l.sender_key !== me) return;
      let arr = [];
      try { arr = JSON.parse(l.answers_json || '[]'); } catch (e) { arr = []; }
      arr.forEach(a => {
        if (!a || !a.at || Date.parse(a.at) < cutoff) return;
        out.push({
          key: `${l.id}|${a.at}`, at: a.at, company: l.company, role: l.role, candidate: l.candidate_name, candidateId: l.candidate_id,
          answer: a.answer, slots: a.slots || [], reasons: (a.reasons || []).map(k => REPLY_REASONS[k] || k), note: a.note || '', message: a.message || '',
          moved: !!a.moved, found: a.found !== false, before: a.before || '', to: a.to || '', taskAdded: !!a.taskAdded, emailed: !!a.emailed, emailError: a.emailError || '',
        });
      });
    });
    out.sort((x, y) => String(y.at).localeCompare(String(x.at)));
    res.json({ data: out.slice(0, 30) });
  } catch (e) {
    console.error('GET /api/reply-activity error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
