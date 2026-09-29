import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { google } from 'googleapis';
import PDFDocument from 'pdfkit';
import nodemailer from 'nodemailer';
import path from 'path';
import { Readable } from 'stream';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
        range: `'${tabName}'!A2:U`,
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
      additionalInfo
    } = req.body;

    if (!name || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const sheets = getSheetsClient();
    const applicationId = `${role}-${Date.now()}`;
    const dateApplied = new Date().toISOString();
    
    // Tab name format: "Applications - Transport Coordinator"
    const tabName = `Applications - ${role.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}`;
    const range = `'${tabName}'!A:T`;

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
      'applied'  // Status
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: range,
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [row] }
    });

    res.json({ success: true, applicationId });

  } catch (err) {
    console.error('POST /api/applications error:', err);
    res.status(500).json({ error: 'Failed to save application' });
  }
});

// Delete a candidate by id
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
      return res.status(404).json({ error: 'candidate not found' });
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

    res.json({ ok: true, client: newClient });
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
  const drive = google.drive({ version: 'v3', auth: getAuthClient() });
  try {
    // Look for existing folder
    const query = `'${companyFolderId}' in parents and name='${candidateName}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;
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

// POST CV file upload for a candidate
app.post('/api/candidates/:id/cv', async (req, res) => {
  try {
    const { id } = req.params;
    const { company, name, fileData, fileName, role } = req.body;
    if (!company || !name || !fileData || !fileName) {
      return res.status(400).json({ error: 'company, name, fileData, fileName required' });
    }
    const companyFolders = await listFolderContents(SUBMISSIONS_FOLDER_ID);
    const companyFolder = companyFolders.find(f => f.name === company && f.mimeType === 'application/vnd.google-apps.folder');
    if (!companyFolder) {
      return res.status(404).json({ error: `Company folder not found: ${company}` });
    }
    const candidateFolderId = await getOrCreateCandidateFolder(companyFolder.id, name);
    if (!candidateFolderId) {
      return res.status(500).json({ error: 'Could not create candidate folder' });
    }
    const drive = google.drive({ version: 'v3', auth: getAuthClient() });
    const buffer = Buffer.from(fileData, 'base64');
    const file = await drive.files.create({
      resource: {
        name: fileName,
        parents: [candidateFolderId],
      },
      media: {
        mimeType: mimeFromName(fileName),
        body: Readable.from([buffer]),
      },
      fields: 'id, webViewLink',
    });
    if (role) {
      try {
        await upsertPoolEntry({ name, role, company, stage: 'applied', source: 'application' }, true, { createOnly: true });
        await attachCvToPool(poolIdFor(name, role), { fileId: file.data.id, fileName, link: file.data.webViewLink || '' });
      } catch (poolErr) {
        console.error('Could not link uploaded CV to pool:', poolErr.message);
      }
    }
    res.json({ 
      ok: true, 
      fileId: file.data.id,
      fileName: fileName,
      link: file.data.webViewLink 
    });
  } catch (e) {
    console.error('POST /api/candidates/:id/cv error:', e.message);
    res.status(500).json({ error: e.message });
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
    const companyFolder = companyFolders.find(f => f.name === company && f.mimeType === 'application/vnd.google-apps.folder');
    if (!companyFolder) {
      return res.status(404).json({ error: `Company folder not found: ${company}` });
    }
    const query = `'${companyFolder.id}' in parents and name='${name}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;
    const list = await drive.files.list({
      q: query,
      spaces: 'drive',
      pageSize: 1,
      fields: 'files(id)',
    });
    if (list.data.files.length === 0) {
      return res.status(404).json({ error: 'Candidate folder not found' });
    }
    const candidateFolderId = list.data.files[0].id;
    const cvQuery = `'${candidateFolderId}' in parents and (mimeType='application/pdf' or name contains 'CV' or name contains 'cv') and trashed=false`;
    const cvList = await drive.files.list({
      q: cvQuery,
      spaces: 'drive',
      pageSize: 1,
      fields: 'files(id, name, webViewLink, mimeType)',
    });
    if (cvList.data.files.length === 0) {
      return res.status(404).json({ error: 'No CV found for this candidate' });
    }
    const cvFile = cvList.data.files[0];
    res.json({ 
      data: {
        fileId: cvFile.id,
        fileName: cvFile.name,
        link: cvFile.webViewLink,
        mimeType: cvFile.mimeType
      }
    });
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

async function readPoolRows() {
  await ensurePoolTab();
  const sheets = getSheetsClient();
  const result = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `'${POOL_TAB}'!A2:${POOL_LAST_COL}`,
  });
  return result.data.values || [];
}

// ---- Serialised access so concurrent saves never create duplicate rows --

let poolChain = Promise.resolve();
function withPoolLock(fn) {
  const run = poolChain.then(fn);
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
    if (opts.autoConsent && live.source === 'application') { row[17] = row[8]; row[18] = 'Application form'; }
  } else if (!opts.createOnly) {
    if (liveRank > stageRank(row[6])) row[6] = stage;
    row[7] = stage;
    if (inPipeline && live.notes !== undefined) row[10] = live.notes || '';
    row[14] = inPipeline ? 'Yes' : 'No';
  }

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
      source: 'dashboard',
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
  const cf = companyFolders.find(f => f.name === company && f.mimeType === 'application/vnd.google-apps.folder');
  if (!cf) return null;

  const parts = String(name).trim().split(/\s+/);
  const variants = [String(name).trim()];
  if (parts.length >= 2) variants.push(`${parts[0]} ${parts[parts.length - 1][0]}`);

  for (const v of variants) {
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

// Upload (or replace) the CV for a pool record
app.post('/api/candidate-pool/:id/cv', async (req, res) => {
  try {
    const { fileData, fileName } = req.body || {};
    if (!fileData || !fileName) return res.status(400).json({ error: 'fileData and fileName required' });
    const found = await findPoolRowById(req.params.id);
    if (!found) return res.status(404).json({ error: 'Pool record not found' });

    const folderId = await getOrCreateCandidateFolder(SUBMISSIONS_FOLDER_ID, POOL_CV_FOLDER_NAME);
    if (!folderId) return res.status(500).json({ error: 'Could not create the Candidate Pool CVs folder in Drive' });

    const ext = (String(fileName).match(/\.[A-Za-z0-9]+$/) || ['.pdf'])[0].toLowerCase();
    const driveName = `${found.row[1]} - ${found.row[5]} - CV${ext}`;
    const drive = getDriveClient();
    const file = await drive.files.create({
      resource: { name: driveName, parents: [folderId] },
      media: { mimeType: mimeFromName(fileName), body: Readable.from([Buffer.from(fileData, 'base64')]) },
      fields: 'id, name, webViewLink',
    });

    const row = await attachCvToPool(req.params.id, {
      fileId: file.data.id,
      fileName: driveName,
      link: file.data.webViewLink || '',
    });
    auditLog(actorOf(req), 'cv_uploaded', 'pool', `${found.row[1]} - ${found.row[5]}`, driveName);
    res.json({ ok: true, data: rowToPoolEntry(row) });
  } catch (e) {
    console.error('POST /api/candidate-pool/:id/cv error:', e.message);
    res.status(500).json({ error: e.message });
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
  header: ['id', 'company', 'role', 'contact', 'salary_band', 'fee_percent', 'status', 'date_opened', 'date_closed', 'notes', 'positions'],
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
  if (all.some(t => t.id === '__templates_v3')) { tplMigrated = true; return; }
  for (const d of DEFAULT_TEMPLATES) {
    const ex = all.find(t => t.id === d.id);
    if (!ex || ex.updated_by === 'system') await templatesTable.upsert(d);
  }
  for (const oldId of ['tpl-offer']) {
    const ex = all.find(t => t.id === oldId);
    if (ex && ex.updated_by === 'system') await templatesTable.remove(oldId);
  }
  await templatesTable.upsert({ id: '__templates_v3', name: 'migration marker', category: '', subject: '', body: '', updated_by: 'system' });
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


app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
