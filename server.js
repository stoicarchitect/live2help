import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { google } from 'googleapis';
import PDFDocument from 'pdfkit';
import nodemailer from 'nodemailer';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

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
async function readApplicationsRows() {
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
        range: `'${tabName}'!A2:T`,
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
          notes: '',
          salary: row[15] || '', // Salary Expectation is column P
          email: row[3] || '', // Email is column D
          phone: row[4] || '', // Phone is column E
          sourceTab: 'application'
        });
      });
    }
  } catch (e) {
    console.error('Error reading Applications tabs:', e.message);
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
      ];

      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID,
        range: `'${tabName}'!A${sheetRowNumber}:T${sheetRowNumber}`,
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
      range: `'${tabName}'!A2:T`,
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
    existing[17] = companyName;       // Company (column R)
    existing[19] = 'submitted';       // Status (column T)
    while (existing.length < 20) existing.push('');

    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A${sheetRowNumber}:T${sheetRowNumber}`,
      valueInputOption: 'RAW',
      requestBody: { values: [existing] },
    });
    return true;
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

    for (const companyFolder of companyFolders) {
      if (companyFolder.mimeType !== 'application/vnd.google-apps.folder') continue;

      const submissionFiles = await listFolderContents(companyFolder.id);
      const docFiles = submissionFiles.filter(f => !f.mimeType.includes('folder'));

      for (const file of docFiles) {
        const parsed = parseSubmissionFilename(file.name);
        if (!parsed) continue;

        const matchedApplication = await tryMarkApplicationSubmitted(companyFolder.name, parsed.role, parsed.name);
        if (matchedApplication) {
          updated++;
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
          console.log(`Auto-created candidate: ${parsed.name} for ${parsed.role} at ${companyFolder.name}`);
        }
      }
    }

    res.json({ synced: true, created, updated });
  } catch (e) {
    console.error('GET /api/sync-submissions error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// Applications intake - form submissions from screening forms
app.post('/api/applications/:role', async (req, res) => {
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
    const { company, name, fileData, fileName } = req.body;
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
        mimeType: 'application/pdf',
        body: require('stream').Readable.from([buffer]),
      },
      fields: 'id, webViewLink',
    });
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
        if (userRole === 'ella' && t.user === 'ella') return true;
        
        return false;
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
        if (userRole === 'ella' && t.user === 'ella') return true;
        
        return false;
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

app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
