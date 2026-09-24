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
const TAB = 'Dashboard';
const RANGE = `${TAB}!A2:J`;

let sheetsClientCache = null;

function getSheetsClient() {
  if (sheetsClientCache) return sheetsClientCache;
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not set on this server');
  let creds;
  try {
    creds = JSON.parse(raw);
  } catch (e) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON - paste the full key file contents as-is');
  }
  const auth = new google.auth.JWT(
    creds.client_email,
    null,
    creds.private_key,
    ['https://www.googleapis.com/auth/spreadsheets']
  );
  sheetsClientCache = google.sheets({ version: 'v4', auth });
  return sheetsClientCache;
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

// GET all candidates, grouped by company then role - shape the dashboard expects
app.get('/api/candidates', async (req, res) => {
  try {
    const rows = await readAllRows();
    const grouped = {};
    rows.filter(r => r[0]).forEach(r => {
      const c = rowToCandidate(r);
      if (!grouped[c.company]) grouped[c.company] = {};
      if (!grouped[c.company][c.role]) grouped[c.company][c.role] = [];
      grouped[c.company][c.role].push(c);
    });
    res.json({ data: grouped });
  } catch (e) {
    console.error('GET /api/candidates error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Create or update a single candidate (upsert by id)
app.post('/api/candidates', async (req, res) => {
  try {
    const c = req.body;
    if (!c.id || !c.company || !c.role || !c.name) {
      return res.status(400).json({ error: 'id, company, role and name are required' });
    }
    const sheets = getSheetsClient();
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
      const sheetRowNumber = rowIndex + 2; // +1 for header, +1 for 1-indexing
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

app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
