/* Live 2 Help - database dump and restore (audit Nov 2026)

   A true restore point for the workspace database. dumpDatabase() reads every table in the
   public schema inside one read-only snapshot and returns a gzip file: the table definitions
   (columns, keys, indexes, sequences) plus every row, with nothing cut or shortened.
   restoreDatabase() rebuilds all of it into an empty schema of any Postgres database.

   File layout (gzip, one JSON object per line):
     {"kind":"header", format, at, pg, extensions, sequences}
     {"kind":"table", name, columns, constraints, indexes}
     {"kind":"rows", table, rows:[...]}            repeated
     {"kind":"end", tables, rows}

   Used by the nightly backup in server.js and by scripts/restore-dump.mjs. */
import zlib from 'zlib';
import readline from 'readline';
import { Readable } from 'stream';

export const DUMP_FORMAT = 'l2h-dump-1';
const q = id => '"' + String(id).replace(/"/g, '""') + '"';

export async function dumpDatabase(pool, { batchRows = 400 } = {}) {
  const client = await pool.connect();
  const gz = zlib.createGzip({ level: 6 });
  const chunks = [];
  gz.on('data', c => chunks.push(c));
  const done = new Promise((resolve, reject) => { gz.on('end', resolve); gz.on('error', reject); });
  const line = async obj => { if (!gz.write(JSON.stringify(obj) + '\n')) await new Promise(r => gz.once('drain', r)); };
  let tables = 0, rows = 0;
  const perTable = {};
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query("SET LOCAL search_path TO public");
    const ver = (await client.query('SHOW server_version')).rows[0].server_version;
    const ext = (await client.query("SELECT extname FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1")).rows.map(r => r.extname);
    const seqs = (await client.query("SELECT sequencename AS name, last_value, start_value, increment_by FROM pg_sequences WHERE schemaname = 'public' ORDER BY 1")).rows;
    await line({ kind: 'header', format: DUMP_FORMAT, at: new Date().toISOString(), pg: ver, extensions: ext, sequences: seqs });
    const tbls = (await client.query(
      "SELECT c.oid, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY c.relname")).rows;
    for (const t of tbls) {
      const columns = (await client.query(
        `SELECT a.attname AS name, format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull AS notnull,
                pg_get_expr(d.adbin, d.adrelid) AS dflt, a.attidentity AS identity, a.attgenerated AS generated
           FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
          WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`, [t.oid])).rows;
      const constraints = (await client.query(
        "SELECT conname AS name, contype AS type, pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid = $1 AND contype <> 'n' ORDER BY conname", [t.oid])).rows;
      const cnames = new Set(constraints.map(c => c.name));
      const indexes = (await client.query(
        "SELECT indexname AS name, indexdef AS def FROM pg_indexes WHERE schemaname = 'public' AND tablename = $1 ORDER BY indexname", [t.relname])).rows
        .filter(i => !cnames.has(i.name));
      await line({ kind: 'table', name: t.relname, columns, constraints, indexes });
      tables++;
      perTable[t.relname] = 0;
      const cur = 'c_' + tables;
      await client.query(`DECLARE ${cur} NO SCROLL CURSOR FOR SELECT to_jsonb(t) AS j FROM public.${q(t.relname)} t`);
      for (;;) {
        const r = await client.query(`FETCH ${batchRows} FROM ${cur}`);
        if (!r.rows.length) break;
        // written in parts of about 1 MB so reading a dump back never needs much memory
        let part = [], size = 0;
        for (const x of r.rows) {
          part.push(x.j);
          size += JSON.stringify(x.j).length;
          if (size > 1000000) { await line({ kind: 'rows', table: t.relname, rows: part }); part = []; size = 0; }
        }
        if (part.length) await line({ kind: 'rows', table: t.relname, rows: part });
        rows += r.rows.length;
        perTable[t.relname] += r.rows.length;
      }
      await client.query(`CLOSE ${cur}`);
    }
    await line({ kind: 'end', tables, rows });
    await client.query('COMMIT');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (x) { /* ignore */ }
    gz.destroy();
    throw e;
  } finally {
    client.release();
  }
  gz.end();
  await done;
  const buffer = Buffer.concat(chunks);
  return { buffer, tables, rows, bytes: buffer.length, perTable };
}

// Reads a dump without touching any database: confirms the file is whole and counts what it holds
// One line at a time, so a large dump is never held in memory unpacked
function dumpLines(buffer) {
  return readline.createInterface({ input: Readable.from([buffer]).pipe(zlib.createGunzip()), crlfDelay: Infinity });
}
export async function inspectDump(buffer) {
  let header = null, end = null;
  const perTable = {};
  for await (const ln of dumpLines(buffer)) {
    if (!ln) continue;
    const o = JSON.parse(ln);
    if (o.kind === 'header') header = o;
    else if (o.kind === 'table') perTable[o.name] = perTable[o.name] || 0;
    else if (o.kind === 'rows') perTable[o.table] = (perTable[o.table] || 0) + o.rows.length;
    else if (o.kind === 'end') end = o;
  }
  if (!header || header.format !== DUMP_FORMAT) throw new Error('Not a Live 2 Help database dump');
  if (!end) throw new Error('The dump is incomplete (no end marker)');
  const rows = Object.values(perTable).reduce((a, b) => a + b, 0);
  if (rows !== end.rows || Object.keys(perTable).length !== end.tables) throw new Error('The dump does not match its own totals');
  return { at: header.at, pg: header.pg, tables: end.tables, rows, perTable };
}

/* Rebuilds a dump into `schema` (made if missing, and it must hold no tables).
   Restoring into "public" of a new, empty database gives a working copy of the workspace data. */
export async function restoreDatabase(pool, buffer, { schema = 'public' } = {}) {
  const info = await inspectDump(buffer);
  const S = q(schema);
  const client = await pool.connect();
  const fks = [], indexes = [], serials = [];
  let header = null;
  const cols = {};
  try {
    await client.query('BEGIN');
    await client.query(`CREATE SCHEMA IF NOT EXISTS ${S}`);
    const existing = await client.query('SELECT count(*)::int AS n FROM pg_tables WHERE schemaname = $1', [schema]);
    if (existing.rows[0].n) throw new Error(`Schema "${schema}" already holds ${existing.rows[0].n} table(s). Restore only into an empty schema.`);
    await client.query(`SET LOCAL search_path TO ${S}, public`);
    for await (const ln of dumpLines(buffer)) {
      if (!ln) continue;
      const o = JSON.parse(ln);
      if (o.kind === 'header') {
        header = o;
        for (const e of o.extensions || []) { try { await client.query('SAVEPOINT ext'); await client.query(`CREATE EXTENSION IF NOT EXISTS ${q(e)}`); } catch (x) { await client.query('ROLLBACK TO SAVEPOINT ext'); } }
        for (const s of o.sequences || []) await client.query(`CREATE SEQUENCE IF NOT EXISTS ${S}.${q(s.name)} INCREMENT BY ${Number(s.increment_by) || 1}`);
      } else if (o.kind === 'table') {
        const defs = o.columns.map(c => {
          let d = `${q(c.name)} ${c.type}`;
          if (c.generated === 's') d += ` GENERATED ALWAYS AS (${c.dflt}) STORED`;
          else if (c.identity === 'a' || c.identity === 'd') d += ` GENERATED ${c.identity === 'a' ? 'ALWAYS' : 'BY DEFAULT'} AS IDENTITY`;
          else if (c.dflt != null) d += ` DEFAULT ${c.dflt}`;
          if (c.notnull) d += ' NOT NULL';
          return d;
        });
        await client.query(`CREATE TABLE ${S}.${q(o.name)} (${defs.join(', ')})`);
        cols[o.name] = o.columns.filter(c => c.generated !== 's').map(c => c.name);
        for (const c of o.columns) {
          if (c.identity === 'a' || c.identity === 'd' || /nextval\(/.test(String(c.dflt || ''))) serials.push({ table: o.name, col: c.name });
        }
        for (const c of o.constraints) {
          const sql = `ALTER TABLE ${S}.${q(o.name)} ADD CONSTRAINT ${q(c.name)} ${c.def}`;
          if (c.type === 'f') fks.push(sql); else indexes.push(sql);
        }
        for (const i of o.indexes) indexes.push(i.def.replace(' ON public.', ` ON ${S}.`));
      } else if (o.kind === 'rows') {
        const list = cols[o.table].map(q).join(', ');
        // identity ALWAYS columns need OVERRIDING SYSTEM VALUE to take the saved numbers
        await client.query(
          `INSERT INTO ${S}.${q(o.table)} (${list}) OVERRIDING SYSTEM VALUE SELECT ${list} FROM jsonb_populate_recordset(NULL::${S}.${q(o.table)}, $1::jsonb)`,
          [JSON.stringify(o.rows)]);
      }
    }
    for (const sql of indexes) await client.query(sql);
    for (const sql of fks) await client.query(sql);
    for (const s of (header && header.sequences) || []) {
      if (s.last_value != null) await client.query('SELECT setval($1::regclass, $2::bigint, true)', [`${S}.${q(s.name)}`, s.last_value]);
    }
    for (const s of serials) {
      const seq = (await client.query('SELECT pg_get_serial_sequence($1, $2) AS s', [`${S}.${q(s.table)}`, s.col])).rows[0].s;
      if (seq) await client.query(`SELECT setval($1::regclass, GREATEST((SELECT COALESCE(MAX(${q(s.col)}), 0) FROM ${S}.${q(s.table)}), 1)::bigint, true)`, [seq]);
    }
    // prove it: every table must hold exactly the rows the dump says
    const mismatches = [];
    for (const [name, n] of Object.entries(info.perTable)) {
      const got = (await client.query(`SELECT count(*)::int AS n FROM ${S}.${q(name)}`)).rows[0].n;
      if (got !== n) mismatches.push(`${name}: dump ${n}, restored ${got}`);
    }
    if (mismatches.length) throw new Error('Row counts do not match after restore: ' + mismatches.join('; '));
    await client.query('COMMIT');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (x) { /* ignore */ }
    throw e;
  } finally {
    client.release();
  }
  return { schema, tables: info.tables, rows: info.rows, dumpedAt: info.at };
}
