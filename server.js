import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { google } from 'googleapis';
import PDFDocument from 'pdfkit';
import nodemailer from 'nodemailer';
import path from 'path';
import { Readable } from 'stream';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

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
const KPI_TARGETS_RANGE = `${KPI_TARGETS_TAB}!A2:D`;

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
  if (req.get('X-User-Role') !== 'dan') {
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
  };
}

function kpiTargetToRow(kpi) {
  return [
    kpi.quarter || '',
    kpi.targetRoles || 0,
    kpi.targetNewClients || 0,
    kpi.targetAvgFillSpeedDays || 0,
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

// GET all KPI targets
app.get('/api/kpi-targets', async (req, res) => {
  try {
    const rows = await readKPITargetRows();
    const targets = rows.map(r => rowToKPITarget(r));
    res.json({ data: targets });
  } catch (e) {
    console.error('GET /api/kpi-targets error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST add/update KPI target
app.post('/api/kpi-targets', async (req, res) => {
  try {
    const { quarter, targetRoles, targetNewClients, targetAvgFillSpeedDays } = req.body;
    
    if (!quarter) {
      return res.status(400).json({ error: 'quarter is required' });
    }

    const sheets = getSheetsClient();
    const rows = await readKPITargetRows();
    
    const newKPI = {
      quarter,
      targetRoles: parseInt(targetRoles) || 0,
      targetNewClients: parseInt(targetNewClients) || 0,
      targetAvgFillSpeedDays: parseInt(targetAvgFillSpeedDays) || 0,
    };

    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: KPI_TARGETS_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [kpiTargetToRow(newKPI)] },
    });

    res.json({ ok: true, kpiTarget: newKPI });
  } catch (e) {
    console.error('POST /api/kpi-targets error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE KPI target by quarter
app.delete('/api/kpi-targets/:quarter', async (req, res) => {
  try {
    const { quarter } = req.params;
    
    if (!quarter) {
      return res.status(400).json({ error: 'quarter is required' });
    }

    const sheets = getSheetsClient();
    const rows = await readKPITargetRows();
    
    // Find the row index for this quarter
    let rowIndexToDelete = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] === decodeURIComponent(quarter)) {
        rowIndexToDelete = i;
        break;
      }
    }

    if (rowIndexToDelete === -1) {
      return res.status(404).json({ error: 'KPI target not found' });
    }

    // Delete the row (Google Sheets uses 1-based indexing, and we start from row 2)
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: CLIENT_SHEET_ID,
      requestBody: {
        requests: [{
          deleteDimension: {
            range: {
              sheetId: 0, // Assuming KPI Targets sheet is the first sheet
              dimension: 'ROWS',
              startIndex: rowIndexToDelete + 1, // +1 because data starts at row 2
              endIndex: rowIndexToDelete + 2
            }
          }
        }]
      }
    });

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

const POOL_TAB = 'Candidate Pool';
const POOL_HEADER = [
  'id', 'name', 'email', 'phone', 'company', 'role', 'furthest_stage', 'current_stage',
  'date_added', 'last_updated', 'notes', 'cv_file_id', 'cv_file_name', 'cv_link', 'in_pipeline', 'tags',
];
const POOL_WIDTH = POOL_HEADER.length;
const POOL_LAST_COL = 'P';
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
    const merged = mergeLiveIntoPoolRow(ex ? ex.row : null, l, true);
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
    if ((ex.row[14] || '') === 'No') continue;
    const r = padPoolRow(ex.row);
    r[14] = 'No';
    r[9] = now;
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

function makeSimpleTable({ tab, header, path, label, seed }) {
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
    if (!first || first[0] !== header[0]) {
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

  async function list() { return (await readRows()).filter(r => r && r[0]).map(toObj); }

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

  if (path) {
    app.get(path, async (req, res) => {
      try { res.json({ data: await list() }); }
      catch (e) { console.error(`GET ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
    app.post(path, async (req, res) => {
      try {
        const b = req.body || {};
        if (!b.id) return res.status(400).json({ error: 'id is required' });
        const clean = {};
        header.forEach(h => { if (b[h] !== undefined) clean[h] = b[h]; });
        // keep any existing values the caller did not send
        const existing = (await list()).find(o => o.id === b.id);
        res.json({ ok: true, data: await upsert({ ...(existing || {}), ...clean }) });
      } catch (e) { console.error(`POST ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
    app.delete(`${path}/:id`, async (req, res) => {
      try {
        const ok = await remove(req.params.id);
        if (!ok) return res.status(404).json({ error: `${label || 'Record'} not found` });
        res.json({ ok: true });
      } catch (e) { console.error(`DELETE ${path} error:`, e.message); res.status(500).json({ error: e.message }); }
    });
  }
  return { list, upsert, append, remove, ensure };
}

/* ---------- Roles / Vacancies ---------- */

const rolesTable = makeSimpleTable({
  tab: 'Roles',
  header: ['id', 'company', 'role', 'contact', 'salary_band', 'fee_percent', 'status', 'date_opened', 'date_closed', 'notes'],
  path: '/api/roles',
  label: 'Role',
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
  header: ['id', 'candidate_id', 'candidate_name', 'role', 'company', 'date', 'time', 'type', 'location', 'interviewer', 'status', 'notes', 'created_by'],
  path: '/api/interviews',
  label: 'Interview',
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
});

const DEFAULT_TEMPLATES = [
  {
    id: 'tpl-client-follow-up', name: 'Client follow-up after submission', category: 'Client',
    subject: 'Following up: {{candidate_name}} for {{role}}',
    body: 'Hi {{contact_name}},\n\nI hope you are well. I wanted to follow up on the profile I sent over for {{candidate_name}} for your {{role}} vacancy.\n\nHave you had a chance to review it? {{first_name}} is keen and available to speak at your convenience, so if you would like to move forward I can arrange an interview at a time that suits you.\n\nKind regards,\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
  {
    id: 'tpl-interview-confirmation', name: 'Interview confirmation', category: 'Candidate',
    subject: 'Your interview for {{role}} at {{company}}',
    body: 'Hi {{first_name}},\n\nGreat news, {{company}} would like to interview you for the {{role}} position.\n\nInterview details:\nDate: {{interview_date}}\nTime: {{interview_time}}\nLocation: {{interview_location}}\n\nPlease reply to confirm you can attend. I will send over the site information and everything you need to prepare shortly.\n\nBest of luck,\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
  {
    id: 'tpl-offer', name: 'Offer congratulations', category: 'Candidate',
    subject: 'Congratulations, offer from {{company}}',
    body: 'Hi {{first_name}},\n\nCongratulations. I am delighted to let you know that {{company}} would like to offer you the {{role}} position.\n\nI will call you to talk through the terms and answer any questions. The formal offer letter will follow once we have spoken.\n\nWell done,\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
  {
    id: 'tpl-rejection', name: 'Candidate rejection', category: 'Candidate',
    subject: 'Your application for {{role}}',
    body: 'Hi {{first_name}},\n\nThank you for your time and interest in the {{role}} position with {{company}}. After careful consideration the client has decided not to progress your application on this occasion.\n\nThis is not a reflection of your ability and I would like to keep your details on file for future roles that suit your experience. Please keep in touch.\n\nKind regards,\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
  {
    id: 'tpl-day-one', name: 'Day 1 welcome message', category: 'Candidate',
    subject: 'Good luck today at {{company}}',
    body: 'Hi {{first_name}},\n\nJust a quick message to wish you the very best on your first day as {{role}} at {{company}}. You have earned it.\n\nIf anything comes up today, call me any time.\n\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
  {
    id: 'tpl-week-one', name: 'Week 1 check-in', category: 'Candidate',
    subject: 'How was your first week?',
    body: 'Hi {{first_name}},\n\nHow was your first week at {{company}}? I would love to hear how you are settling in, and whether there is anything I can help with.\n\nI will give you a quick call to catch up.\n\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
  {
    id: 'tpl-month-one', name: 'Month 1 check-in', category: 'Candidate',
    subject: 'One month in',
    body: 'Hi {{first_name}},\n\nYou have now been at {{company}} for a month. How are things going with the {{role}} role, and does it feel like the right fit?\n\nI will also check in with {{contact_name}} to make sure everything is going well from their side.\n\n{{my_name}}\nLive 2 Help Recruitment',
    updated_by: 'system',
  },
];

const templatesTable = makeSimpleTable({
  tab: 'Templates',
  header: ['id', 'name', 'category', 'subject', 'body', 'updated_by'],
  path: '/api/templates',
  label: 'Template',
  seed: DEFAULT_TEMPLATES,
});

const activityTable = makeSimpleTable({
  tab: 'Activity',
  header: ['id', 'timestamp', 'user', 'action', 'candidate', 'role', 'company', 'detail'],
  path: null,
  label: 'Activity',
});

app.get('/api/activity', async (req, res) => {
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


app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
