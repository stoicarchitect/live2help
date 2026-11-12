// Restores a Live 2 Help database dump (made by the nightly backup) into an empty schema.
//   node scripts/restore-dump.mjs "Workspace database dump 2026-11-12.json.gz" "postgres://user:pass@host/db" [schema]
// The schema defaults to "public". It must hold no tables, so a restore can never overwrite live data.
// Add --inspect to only read the file and print what it holds (no database needed).
import fs from 'fs';
import pg from 'pg';
import { inspectDump, restoreDatabase } from '../db-dump.js';

const args = process.argv.slice(2).filter(a => !a.startsWith('--'));
const inspectOnly = process.argv.includes('--inspect');
const [file, url, schema = 'public'] = args;
if (!file || (!inspectOnly && !url)) {
  console.error('Usage: node scripts/restore-dump.mjs <dump.json.gz> <database url> [schema]   (or --inspect <dump.json.gz>)');
  process.exit(1);
}
const buffer = fs.readFileSync(file);
const info = await inspectDump(buffer);
console.log(`Dump made ${info.at} on Postgres ${info.pg}: ${info.tables} tables, ${info.rows} rows`);
if (inspectOnly) { console.table(info.perTable); process.exit(0); }
const host = new URL(url).hostname;
const ssl = host.includes('.') && host !== '127.0.0.1' ? { rejectUnauthorized: false } : false;
const pool = new pg.Pool({ connectionString: url, ssl, max: 1 });
try {
  const out = await restoreDatabase(pool, buffer, { schema });
  console.log(`Restored ${out.tables} tables and ${out.rows} rows into schema "${out.schema}". Row counts checked against the dump.`);
} catch (e) {
  console.error('Restore failed, nothing was changed:', e.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
