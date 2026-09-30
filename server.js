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
   A "passwordHash" ("salt:scrypt-hex") can be used instead of "password".
   Until L2H_USERS is set the server behaves exactly as before, so deploying
   this is safe. Once set, every /api call except the public application
   form needs a signed token from POST /api/login.
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

const loginAttempts = new Map();
app.post('/api/login', (req, res) => {
  if (!AUTH_ENABLED) return res.status(501).json({ error: 'Server login is not configured' });
  const ip = req.ip || 'unknown';
  const now = Date.now();
  let rec = loginAttempts.get(ip);
  if (!rec || rec.reset < now) rec = { count: 0, reset: now + 15 * 60 * 1000 };
  if (rec.count >= 10) return res.status(429).json({ error: 'Too many attempts. Please try again in a few minutes.' });
  const pw = String((req.body || {}).password || '');
  const user = pw ? AUTH_USERS.find(u => checkPassword(u, pw)) : null;
  if (!user) {
    rec.count++;
    loginAttempts.set(ip, rec);
    return res.status(401).json({ error: 'Incorrect password' });
  }
  loginAttempts.delete(ip);
  const token = signToken({ key: user.key, name: user.name, admin: user.admin, exp: Date.now() + TOKEN_TTL_MS });
  res.json({ token, user: { key: user.key, name: user.name, admin: user.admin } });
  auditLog(user.key, 'login', 'session', user.name, '');
});

// Routes that stay public: the careers site application form, the Career Hub AI proxy,
// and the daily reminder cron (which can be locked with CRON_SECRET).
const PUBLIC_API = [
  { method: 'POST', re: /^\/api\/login$/ },
  { method: 'POST', re: /^\/api\/applications\/[^/]+$/ },
  { method: 'POST', re: /^\/api\/claude$/ },
];
let cronWarned = false;

app.use('/api', (req, res, next) => {
  if (req.method === 'OPTIONS' || !AUTH_ENABLED) return next();
  const p = req.originalUrl.split('?')[0].replace(/\/+$/, '');
  if (PUBLIC_API.some(r => r.method === req.method && r.re.test(p))) return next();
  if (p === '/api/check-invoice-reminders') {
    const secret = process.env.CRON_SECRET;
    if (!secret) {
      if (!cronWarned) { console.warn('CRON_SECRET is not set: /api/check-invoice-reminders is open'); cronWarned = true; }
      return next();
    }
    if (String(req.query.key || '') === secret) return next();
  }
  const header = String(req.get('Authorization') || '');
  let token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token && req.method === 'GET' && req.query.token) token = String(req.query.token);
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Please sign in again', code: 'AUTH' });
  req.user = payload;
  req.headers['x-user-role'] = payload.key;
  next();
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

// Helper: read from Applications tabs and convert to candidates with 'applied' stage
async function readApplicationsRows(strict = false) {
  const sheets = getSheetsClient();
  const allApplications = [];
  try {
    const spreadsheet = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID });
    const tabs = spreadsheet.data.sheets;

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
          role: tabName.replace('Applications - ', ''),
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
      const tabName = `Applications - ${c.role}`;
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
  const tabName = `Applications - ${role}`;
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

app.post('/api/applications/:role', async (req, res) => {
  res.on('finish', () => { if (res.statusCode < 400) scheduleReconcile(); });
  try {
    const { role } = req.params;
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
          auditLog(actorOf(req), 'candidate_deleted', 'candidate', `${gone.name} - ${gone.role}`, `stage ${gone.stage}`);
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
        auditLog(actorOf(req), 'candidate_deleted', 'candidate', `${gone.name} - ${gone.role}`, `stage ${gone.stage}`);
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
    auditLog(actorOf(req), idx >= 0 ? 'updated' : 'created', 'kpi_target', `${quarter} - ${owner || 'team'}`, `roles ${newKPI.targetRoles}, clients ${newKPI.targetNewClients}, fill ${newKPI.targetAvgFillSpeedDays}`);
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
    auditLog(actorOf(req), 'deleted', 'kpi_target', `${quarter} - ${owner || 'team'}`, '');
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

// GET progress metrics (roles filled, clients, fill speed this quarter)
app.get('/api/metrics/progress', async (req, res) => {
  try {
    const sheets = getSheetsClient();
    
    // Read candidates to calculate fill speed
    const candResult = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `${TAB}!A2:L`,
    });
    const candRows = candResult.data.values || [];
    
    // Count roles filled in current quarter and calculate fill speed
    let rolesFilledThisQuarter = 0;
    let fillSpeedDays = [];
    
    candRows.forEach(row => {
      if (row[4] === 'success') { // stage column
        const dateStr = row[5]; // date column
        if (dateStr && isInCurrentQuarter(dateStr)) {
          rolesFilledThisQuarter++;
          
          // Calculate days to fill (date - some start date or estimate)
          // For now, we'll use a placeholder calculation
          fillSpeedDays.push(14); // Default assumption
        }
      }
    });
    
    // Read clients to count new ones this quarter
    const clientResult = await sheets.spreadsheets.values.get({
      spreadsheetId: CLIENT_SHEET_ID,
      range: 'Dashboard!A2:J',
    });
    const clientRows = clientResult.data.values || [];
    let newClientsThisQuarter = 0;
    const seenCompanies = new Set();
    
    clientRows.forEach(row => {
      const company = row[1];
      if (company && !seenCompanies.has(company)) {
        const dateStr = row[0]; // timestamp
        if (dateStr && isInCurrentQuarter(dateStr)) {
          newClientsThisQuarter++;
        }
        seenCompanies.add(company);
      }
    });
    
    const avgFillSpeedDays = fillSpeedDays.length > 0 
      ? fillSpeedDays.reduce((a, b) => a + b, 0) / fillSpeedDays.length 
      : 0;
    
    res.json({
      rolesFilledThisQuarter,
      newClientsThisQuarter,
      avgFillSpeedDays: avgFillSpeedDays.toFixed(1)
    });
  } catch (e) {
    console.error('GET /api/metrics/progress error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET business health metrics (revenue, ROI, runway, invoices, client performance)
app.get('/api/metrics/business-health', async (req, res) => {
  try {
    const sheets = getSheetsClient();
    const filterYear = req.query.year ? parseInt(req.query.year) : new Date().getFullYear();
    
    // Read invoices
    const invResult = await sheets.spreadsheets.values.get({
      spreadsheetId: CLIENT_SHEET_ID,
      range: 'Invoices!A2:E',
    });
    const invRows = invResult.data.values || [];
    
    let ytdRevenue = 0;
    let invoicePaid = 0;
    let invoicePending = 0;
    let invoiceOverdue = 0;
    let invoiceCount = 0;
    
    const now = new Date();
    const yearStart = new Date(filterYear, 0, 1);
    const yearEnd = new Date(filterYear, 11, 31);
    
    invRows.forEach(row => {
      const amount = parseInt(row[2]) || 0;
      const paid = row[3];
      const paymentDate = row[4];
      const invoiceDate = new Date(row[1]);
      
      // Year calculation (based on selected year for reporting)
      if (invoiceDate >= yearStart && invoiceDate <= yearEnd) {
        ytdRevenue += amount;
        invoiceCount++;
      }
      
      // Invoice status (always current, not year-filtered)
      if (paid === 'yes') {
        invoicePaid += amount;
      } else {
        invoicePending += amount;
        
        // Check if overdue (14+ days)
        const daysDiff = (now - invoiceDate) / (1000 * 60 * 60 * 24);
        if (daysDiff > 14) {
          invoiceOverdue += amount;
        }
      }
    });
    
    // Calculate Ella's ROI (revenue - salary) / salary
    const ellaSalary = 25000;
    const ellaROI = ytdRevenue > 0 ? (ytdRevenue - ellaSalary) / ellaSalary : 0;
    
    // Client performance - count roles given in the selected year
    const clientResult = await sheets.spreadsheets.values.get({
      spreadsheetId: CLIENT_SHEET_ID,
      range: 'Dashboard!A2:J',
    });
    const clientRows = clientResult.data.values || [];
    
    const clientMap = new Map();
    
    // First pass: create all clients from dashboard
    clientRows.forEach(row => {
      const company = row[1];
      const dateStr = row[5];
      if (company) {
        if (!clientMap.has(company)) {
          clientMap.set(company, { company, revenue: 0, givenRoles: 0, filledRoles: 0 });
        }
      }
    });
    
    // Second pass: count roles given (created) in the selected year
    clientRows.forEach(row => {
      const company = row[1];
      const dateStr = row[5];
      
      if (company && clientMap.has(company)) {
        // Parse the date when role was created
        const createdDate = new Date(dateStr);
        if (createdDate >= yearStart && createdDate <= yearEnd) {
          clientMap.get(company).givenRoles += 1;
        }
      }
    });
    
    // Third pass: count filled roles (in offer/start/completion stages) in the selected year
    clientRows.forEach(row => {
      const company = row[1];
      const stage = row[4];
      const dateStr = row[5];
      
      if (company && clientMap.has(company)) {
        const stageDate = new Date(dateStr);
        const filledStages = ['offer', 'start_date', 'day1', 'week1', 'month1'];
        
        if (filledStages.includes(stage) && stageDate >= yearStart && stageDate <= yearEnd) {
          clientMap.get(company).filledRoles += 1;
        }
      }
    });
    
    // Calculate revenue per client from invoices (needs to match company to invoice company if available)
    // For now, simplified - revenue would come from invoices sheet with company column
    
    const clientPerformance = Array.from(clientMap.values());
    
    res.json({
      ytdRevenue,
      invoicePaid,
      invoicePending,
      invoiceOverdue,
      invoiceCount,
      ellaROI,
      clientPerformance
    });
  } catch (e) {
    console.error('GET /api/metrics/business-health error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

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
  const tabName = `Applications - ${role}`;
  try {
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A2:T`,
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
    SCREENING_FORM_FIELDS.forEach(field => {
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
    auditLog(actorOf(req), 'cv_uploaded', 'pool', `${found.row[1]} - ${found.row[5]}`, saved.fileName);
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
        if (auditType) auditLog(actorOf(req), existing ? 'updated' : 'created', auditType, auditName ? auditName(saved) : saved.id, '');
        res.json({ ok: true, data: saved });
      } catch (e) { console.error(`POST ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
    app.delete(`${path}/:id`, ...g, async (req, res) => {
      try {
        const existing = (await listAll()).find(o => o.id === req.params.id);
        const ok = await remove(req.params.id);
        if (!ok) return res.status(404).json({ error: `${label || 'Record'} not found` });
        if (auditType) auditLog(actorOf(req), 'deleted', auditType, existing && auditName ? auditName(existing) : req.params.id, '');
        res.json({ ok: true });
      } catch (e) { console.error(`DELETE ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
  }
  return { list, listAll, upsert, append, remove, updateWhere, ensure };
}

/* ---------- Roles / Vacancies ---------- */

const rolesTable = makeSimpleTable({
  tab: 'Roles',
  header: ['id', 'company', 'role', 'contact', 'salary_band', 'fee_percent', 'status', 'date_opened', 'date_closed', 'notes', 'positions', 'requirements'],
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
    auditLog(actorOf(req), 'placement_updated', 'placement', req.params.id, `${status}, ${saved.guarantee_weeks} weeks`);
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
  header: ['id', 'candidate_id', 'candidate_name', 'role', 'company', 'date', 'time', 'type', 'location', 'interviewer', 'status', 'notes', 'created_by', 'duration', 'candidate_email', 'interviewer_email'],
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
      if (a) auditLog(actorOf(req), a.action, a.type, a.entity, a.detail || '');
    } catch (e) { /* audit is best effort */ }
  });
}

async function snapshotCandidate(c) {
  try {
    if (!c || !c.name || !c.role) return null;
    if (c.sourceTab === 'application') {
      const sheets = getSheetsClient();
      const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'Applications - ${c.role}'!A2:U` });
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
  if (!before) { auditLog(who, 'candidate_created', 'candidate', label, `stage ${c.stage || 'submitted'}`); return; }
  if (c.stage && normStage(c.stage) !== normStage(before.stage)) {
    auditLog(who, 'stage_changed', 'candidate', label, `${before.stage} to ${c.stage}`);
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
    if (b.extendReview) auditLog(actorOf(req), 'retention_extended', 'pool', `${entry.name} - ${entry.role}`, `review ${entry.reviewDate}`);
    else if (b.consentDate !== undefined || b.consentBasis !== undefined) auditLog(actorOf(req), 'consent_recorded', 'pool', `${entry.name} - ${entry.role}`, entry.consentBasis);
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
    auditLog(actorOf(req), 'bulk_consent_recorded', 'pool', `${data.length} candidates`, basis);
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
      const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'Applications - ${row[5]}'!A2:U` });
      const ar = (r.data.values || []).find(x => match(x[2]));
      if (ar) {
        application = {};
        SCREENING_FORM_FIELDS.forEach(f => { application[f.label] = ar[f.col] || ''; });
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
    auditLog(actorOf(req), 'data_exported', 'pool', `${entry.name} - ${entry.role}`, '');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(bundle, null, 2));
  } catch (e) {
    console.error('GET /api/gdpr/export error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

async function deleteApplicationRows(role, variants) {
  const sheets = getSheetsClient();
  const ss = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties(sheetId,title)' });
  const tab = (ss.data.sheets || []).find(s => s.properties.title === `Applications - ${role}`);
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

    auditLog(actorOf(req), 'candidate_erased', 'pool', `Erased candidate (ref ${tombId})`, `role ${role}`);
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
  const tabName = `Applications - ${role}`;
  let all;
  try {
    const r = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `'${tabName}'!A1:Z` });
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
  for (let i = 5; i <= 16; i++) {
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

async function callClaudeTool({ system, content, tool, maxTokens }) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: SUBMISSION_MODEL,
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
    auditLog(actorOf(req), 'submission_generated', 'submission', `${name} - ${role}`, out.errors.cv ? 'CV not produced' : '');
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
    body.push(new Paragraph({ spacing: { after: 0 }, children: [run(SUBMISSION_CONTACT_LINE, { size: 18 })] }));
  } else if (kind === 'interview_pack') {
    const cons = data.consultant || {};
    const consFirst = cons.first_name || String(cons.name || 'Your consultant').split(' ')[0];
    const firstName = data.first_name || String(data.candidate_ref || '').split(' ')[0] || 'there';
    const company = data.company || '';
    body.push(new Paragraph({ spacing: { before: 200, after: 40 }, children: [run('Interview Preparation Pack', { bold: true, size: 52, color: DX.dark })] }));
    body.push(new Paragraph({ spacing: { after: 40 }, children: [run([data.candidate_ref, data.role_title, company].filter(Boolean).join('  \u00b7  '), { size: 21, color: DX.gold })] }));
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
    body.push(new Paragraph({ spacing: { after: 0 }, children: [run([cons.name, cons.phone, cons.email].filter(Boolean).join('  |  ') || SUBMISSION_CONTACT_LINE, { size: 18 })] }));
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
        const where = [site.site_name, site.address, site.postcode].filter(Boolean).join(', ');
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
    body.push(new Paragraph({ spacing: { after: 0 }, children: [run(SUBMISSION_CONTACT_LINE, { size: 18 })] }));
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

app.post('/api/submissions/docx', async (req, res) => {
  try {
    const { kind, data, name, role } = req.body || {};
    if (!['submission', 'cv'].includes(kind) || !data) return res.status(400).json({ error: 'kind and data are required' });
    const buf = await buildDocx(kind, cleanDeep(data), { role });
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
    await put(names.submission, await buildDocx('submission', cleanDeep(submission), { role }));
    if (cv) await put(names.cv, await buildDocx('cv', cleanDeep(cv), { role }));
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
      auditLog(actorOf(req), existing ? `submission_${clean.status}` : 'submission_draft_created', 'submission', `${saved.candidate_name} - ${saved.role}`, '');
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
    if (!body.preview) auditLog(actorOf(req), 'folders_created', 'client', `${results.filter(r => r.ok).length} clients`, '');
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
    if (!API_KEY) {
      warning = 'The AI key is not set on the server, so the form could not be read. Enter the details by hand.';
    } else {
      try { extracted = await extractSiteInfo(buf, company, siteName); }
      catch (e) { warning = `The form could not be read (${e.message}). Enter the details by hand.`; }
    }

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
    auditLog(actorOf(req), 'site_pdf_uploaded', 'client_site', `${company} - ${siteName || 'Main site'}`, fileError ? 'not saved to Drive' : '');
    res.json({ ok: true, file, fileError, extracted, warning, siteName: finalName });
  } catch (e) {
    console.error('POST /api/client-sites/:id/pdf error:', e.message);
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
    auditLog(actorOf(req), 'signature_saved', 'signature', key, '');
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
6. gaps: anything the recruiter should check or add before sending. Empty array if none.`;

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
    auditLog(actorOf(req), 'interview_pack_generated', 'interview_pack', `${name} - ${role}`, '');
    res.json({ pack: cleaned });
  } catch (e) {
    console.error('POST /api/interview-packs/generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

function packFileNames(pack) {
  const ref = candidateRef(pack.candidate_name || pack.candidate_ref || '');
  return {
    interview: safeFileName(`${ref} Interview Prep ${pack.role_title || 'Role'}`) + '.docx',
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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
