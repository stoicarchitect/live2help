import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { google } from 'googleapis';

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
     id | company | role | name | stage | date | notes | salary | email | phone
---------------------------------------------------------------------- */

const SHEET_ID = process.env.SHEET_ID;
const SUBMISSIONS_FOLDER_ID = '1MplgUUbCNy64ZxDz4EQtc8GtnZ7S9Ipo';
const TAB = 'Dashboard';
const RANGE = `${TAB}!A2:J`;

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
  };
}

function candidateToRow(c) {
  return [
    c.id, c.company, c.role, c.name, c.stage || 'submitted',
    c.date || new Date().toISOString().slice(0, 10),
    c.notes || '', c.salary || '', c.email || '', c.phone || '',
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
        range: `${TAB}!A${sheetRowNumber}:J${sheetRowNumber}`,
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
    const rowIndex = rows.findIndex(r => (r[2] || '').trim().toLowerCase() === candidateName.trim().toLowerCase());
    if (rowIndex === -1) return false;

    const sheetRowNumber = rowIndex + 2;
    const existing = rows[rowIndex];
    existing[17] = companyName;       // Company
    existing[19] = 'submitted';       // Status
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
      range: `${TAB}!A${sheetRowNumber}:J${sheetRowNumber}`,
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
const INVOICES_TAB = 'Invoices';
const INVOICES_RANGE = `${INVOICES_TAB}!A2:E`;
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

/* ======================================================================
   Invoices - Dan only
   
   Columns: Invoice Number | Invoice Date | Invoice Amount | Paid Status | Payment Date
====================================================================== */

function rowToInvoice(row) {
  return {
    number: row[0] || '',
    date: row[1] || '',
    amount: parseFloat(row[2]) || 0,
    paidStatus: row[3] || 'No',
    paymentDate: row[4] || '',
  };
}

function invoiceToRow(inv) {
  return [
    inv.number || '',
    inv.date || '',
    inv.amount || 0,
    inv.paidStatus || 'No',
    inv.paymentDate || '',
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

// GET all invoices
app.get('/api/invoices', async (req, res) => {
  try {
    const rows = await readInvoiceRows();
    const invoices = rows.map(r => rowToInvoice(r));
    res.json({ data: invoices });
  } catch (e) {
    console.error('GET /api/invoices error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST add new invoice
app.post('/api/invoices', async (req, res) => {
  try {
    const { number, date, amount, paidStatus, paymentDate } = req.body;
    
    if (!number || !date || !amount) {
      return res.status(400).json({ error: 'number, date, and amount are required' });
    }

    const sheets = getSheetsClient();
    const newInvoice = {
      number,
      date,
      amount: parseFloat(amount),
      paidStatus: paidStatus || 'No',
      paymentDate: paymentDate || '',
    };

    await sheets.spreadsheets.values.append({
      spreadsheetId: CLIENT_SHEET_ID,
      range: INVOICES_RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [invoiceToRow(newInvoice)] },
    });

    res.json({ ok: true, invoice: newInvoice });
  } catch (e) {
    console.error('POST /api/invoices error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// PUT update invoice (paid status, payment date)
app.put('/api/invoices/:number', async (req, res) => {
  try {
    const { number } = req.params;
    const { paidStatus, paymentDate } = req.body;
    
    const sheets = getSheetsClient();
    const rows = await readInvoiceRows();
    
    const rowIndex = rows.findIndex(r => r[0] === number);
    if (rowIndex === -1) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const updatedRow = [...rows[rowIndex]];
    if (paidStatus !== undefined) updatedRow[3] = paidStatus;
    if (paymentDate !== undefined) updatedRow[4] = paymentDate;

    await sheets.spreadsheets.values.update({
      spreadsheetId: CLIENT_SHEET_ID,
      range: `${INVOICES_TAB}!A${rowIndex + 3}:E${rowIndex + 3}`,
      valueInputOption: 'RAW',
      requestBody: { values: [updatedRow] },
    });

    res.json({ ok: true, invoice: rowToInvoice(updatedRow) });
  } catch (e) {
    console.error('PUT /api/invoices error:', e.message);
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

// Helper: find screening answers row for a candidate
// candidateId format: "company-name-lower"
async function findApplicationRow(candidateId, role) {
  const sheets = getSheetsClient();
  const tabName = `Applications - ${role}`;
  try {
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `'${tabName}'!A2:T`,
    });
    const rows = result.data.values || [];
    const namePart = candidateId.split('-').pop(); // Get the last part (name)
    const rowIndex = rows.findIndex(r => 
      (r[2] || '').toLowerCase().replace(/\s+/g, '-') === namePart
    );
    return rowIndex !== -1 ? rows[rowIndex] : null;
  } catch (e) {
    console.error(`Error finding application row for ${candidateId} in ${tabName}:`, e.message);
    return null;
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
app.get('/api/candidates/:id/screening-answers', async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.query;
    if (!role) {
      return res.status(400).json({ error: 'role query parameter required' });
    }
    const row = await findApplicationRow(id, role);
    if (!row) {
      return res.status(404).json({ error: 'Screening answers not found' });
    }
    const answers = {};
    SCREENING_FORM_FIELDS.forEach(field => {
      answers[field.key] = {
        label: field.label,
        value: row[field.col] || ''
      };
    });
    res.json({ data: answers });
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

app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
