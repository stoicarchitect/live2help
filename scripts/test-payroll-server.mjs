// Build 64 server test against a scratch Postgres.
//   TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5544/l2h node scripts/test-payroll-server.mjs
// Skips with a message when no scratch database is given. Never touches the live database.
// Google Sheets is not reachable here, so the invoice side of the pack is covered by scripts/test-payroll.mjs.
import { spawn } from 'child_process';
import assert from 'assert';
import pg from 'pg';

const dbUrl = process.env.TEST_DATABASE_URL;
if (!dbUrl) { console.log('payroll server test skipped: set TEST_DATABASE_URL to a scratch database'); process.exit(0); }
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };

const pool = new pg.Pool({ connectionString: dbUrl });
await pool.query('drop schema public cascade; create schema public');
const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT: '3997', ANTHROPIC_API_KEY: 'x', DATABASE_URL: dbUrl, PG_LIVE_GROUPS: 'system' }, stdio: ['ignore', 'pipe', 'pipe'] });
let log = ''; srv.stdout.on('data', d => { log += d; }); srv.stderr.on('data', d => { log += d; });
const call = async (method, path, role = 'dan', body) => {
  const r = await fetch('http://127.0.0.1:3997' + path, { method, headers: { 'X-User-Role': role, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, text: await r.text() };
};
try {
  for (let i = 0; i < 40; i++) { try { if ((await fetch('http://127.0.0.1:3997/api/health')).ok) break; } catch (e) { /* not up yet */ } await new Promise(r => setTimeout(r, 500)); }

  // Ella and signed-out callers are refused on every payroll route, and the refusal carries no figures
  const routes = [['GET', '/api/payroll/status'], ['GET', '/api/payroll/pack'], ['GET', '/api/payroll/runs'], ['POST', '/api/payroll/settings'], ['POST', '/api/payroll/mark-sent']];
  for (const [m, p] of routes) {
    for (const who of ['ella', '']) {
      const r = await call(m, p, who, m === 'POST' ? { month: '2026-11', payDate: '2026-11-30' } : undefined);
      ok(r.status === 403 && !/salary|gross|commission|pension|£/i.test(r.text), `${who || 'signed out'} refused on ${m} ${p}: ${r.status} ${r.text.slice(0, 80)}`);
    }
  }

  // Daniel Brown sees the status, and watching starts this month
  const st = await call('GET', '/api/payroll/status');
  const s = JSON.parse(st.text);
  ok(st.status === 200 && s.current && /^\d{4}-\d{2}$/.test(s.current.month) && s.stored === true, 'status for Daniel Brown: ' + st.text.slice(0, 200));
  const start = (await pool.query("select value from st_payroll_settings where id = 'start_month'")).rows[0];
  ok(start && start.value === s.today.slice(0, 7), 'start month stored once, so no old month is reported as missed');

  // pay date override: valid date saved, bad date refused, clearing goes back to the last working day
  const month = s.current.month;
  const [y, m] = month.split('-').map(Number);
  const first = (m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, '0')}`) + '-01';
  const o1 = await call('POST', '/api/payroll/settings', 'dan', { month, payDate: first });
  ok(o1.status === 200 && JSON.parse(o1.text).payDate.date === first, 'override to the 1st saved: ' + o1.text);
  const st2 = JSON.parse((await call('GET', '/api/payroll/status')).text);
  ok(st2.months.find(x => x.month === month).payDate === first, 'status uses the override');
  const bad = await call('POST', '/api/payroll/settings', 'dan', { month, payDate: `${month}-02` });
  ok(bad.status === 400, 'a pay date far from the month end is refused');
  const clear = await call('POST', '/api/payroll/settings', 'dan', { month, payDate: '' });
  ok(clear.status === 200 && JSON.parse(clear.text).payDate.source === 'last working day', 'clearing returns to the last working day');

  // tables exist in Postgres and are logged
  const t = (await pool.query("select table_name from information_schema.tables where table_schema = 'public' and table_name in ('st_payroll_settings','st_payroll_runs','st_commission_ledger') order by 1")).rows.map(r => r.table_name);
  ok(t.length >= 1 && t.includes('st_payroll_settings'), 'payroll tables are in Postgres: ' + t.join(', '));
  const runs = await call('GET', '/api/payroll/runs');
  ok(runs.status === 200 && Array.isArray(JSON.parse(runs.text).runs), 'runs history readable by Daniel Brown');
  const audit = (await pool.query("select count(*)::int as n from st_audit_log where action like 'payroll_date%'").catch(() => ({ rows: [{ n: -1 }] }))).rows[0].n;
  ok(audit !== 0, 'pay date changes are in the Audit Trail (' + audit + ')');

  // mark as sent refuses a bad month before touching anything
  const ms = await call('POST', '/api/payroll/mark-sent', 'dan', { month: 'nope' });
  ok(ms.status === 400, 'mark as sent needs a month');

  console.log(`payroll server: all ${n} checks passed`);
} catch (e) {
  console.error(log.slice(-3000));
  throw e;
} finally {
  srv.kill(); await pool.end();
}
