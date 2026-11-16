// Build 65 server test against a scratch Postgres and a fake mail server.
//   TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5544/l2h node scripts/test-reports-server.mjs
// Skips with a message when no scratch database is given. Never touches the live database or sends a real email.
// Google Sheets is not reachable here, so the KPI input comes from a fixture file (only honoured under NODE_ENV=test)
// and Emails to review (a Sheets table) is covered by scripts/test-reports.mjs and the build 65 handover.
import { spawn, execFileSync } from 'child_process';
import net from 'net';
import fs from 'fs';
import assert from 'assert';
import pg from 'pg';

const dbUrl = process.env.TEST_DATABASE_URL;
if (!dbUrl) { console.log('reports server test skipped: set TEST_DATABASE_URL to a scratch database'); process.exit(0); }
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };

/* ---------- a fake mail server that records every message ---------- */
const mails = [];
const smtp = net.createServer(sock => {
  let cur = null, data = null, auth = 0, buf = '';
  const say = s => sock.write(s + '\r\n');
  say('220 fake ESMTP');
  sock.on('data', chunk => {
    buf += chunk.toString('latin1');
    for (;;) {
      if (data !== null) {
        const end = buf.indexOf('\r\n.\r\n');
        if (end < 0) { data += buf; buf = ''; return; }
        data += buf.slice(0, end); buf = buf.slice(end + 5);
        cur.data = data; mails.push(cur); data = null; cur = null; say('250 queued'); continue;
      }
      const i = buf.indexOf('\r\n'); if (i < 0) return;
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (auth === 1) { auth = 2; say('334 UGFzc3dvcmQ6'); continue; }
      if (auth === 2) { auth = 0; say('235 ok'); continue; }
      if (/^EHLO|^HELO/i.test(line)) say('250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME');
      else if (/^AUTH PLAIN/i.test(line)) say('235 ok');
      else if (/^AUTH LOGIN/i.test(line)) { auth = 1; say('334 VXNlcm5hbWU6'); }
      else if (/^MAIL FROM/i.test(line)) { cur = { from: line, to: [], data: '' }; say('250 ok'); }
      else if (/^RCPT TO/i.test(line)) { cur.to.push(line.replace(/^RCPT TO:\s*<?|>?\s*$/gi, '').toLowerCase()); say('250 ok'); }
      else if (/^DATA/i.test(line)) { data = ''; say('354 go'); }
      else if (/^QUIT/i.test(line)) { say('221 bye'); sock.end(); }
      else say('250 ok');
    }
  });
  sock.on('error', () => {});
});
await new Promise(r => smtp.listen(0, '127.0.0.1', r));
const smtpPort = smtp.address().port;

/* ---------- a fixture for last month, built from today's date ---------- */
const londonToday = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/London' }).format(new Date());
const today = londonToday();
const [ty, tm] = today.split('-').map(Number);
const prev = tm === 1 ? `${ty - 1}-12` : `${ty}-${String(tm - 1).padStart(2, '0')}`;
const monthEnd = new Date(Date.UTC(+prev.slice(0, 4), +prev.slice(5, 7), 0)).toISOString().slice(0, 10);
const d = day => `${prev}-${String(day).padStart(2, '0')}`;
const inv = (number, date, company, amount, status, paymentDate, consultant, commissionAmount, dueDate) =>
  ({ number, date, dueDate, company, role: 'Welder', candidateName: 'Cand ' + number, amount, status, paymentDate: paymentDate || '', consultant, commissionAmount: commissionAmount || 0, commissionPaidDate: '' });
const fixture = {
  invoices: [inv('T1', d(3), 'Acme Ltd', 6100, 'paid', d(12), 'Ella', 915, d(17)), inv('T2', d(10), 'Beta Ltd', 4700, 'pending', '', 'Dan', 0, d(24)), inv('T3', d(20), 'Gamma Ltd', 3100, 'pending', '', 'Ella', 465, d(27))],
  candidates: [], roles: [{ id: 'r1', company: 'Beta Ltd', role: 'Fitter', status: 'open', date_opened: d(1), positions: '1', salary_band: '28000' }], audit: [], activity: [
    ...[3, 5, 9].map(x => ({ timestamp: d(x) + 'T09:00:00Z', user: 'ella', action: 'submitted', company: 'Acme Ltd', role: 'Welder' }))], comms: [], interviews: [], adSpend: [], placements: [], otherSales: [],
  settings: {}, snapshots: {}, vatMarkers: {}, kpiTargets: [], clientFirstSeen: [],
  employees: [{ name: 'Ella Pietrzak', role: 'Consultant', salary: '26000', pensionPct: '3', commissionPct: '15', startDate: '2026-01-01', endDate: '', pensionOnComm: true }],
  fin: { manualAd: 0, overheads: 0, payrollCutoff: '' }, forecastWeights: null, bank: { connected: false, settings: {}, status: {} },
};
fs.writeFileSync('/tmp/l2h-reports-fixture.json', JSON.stringify(fixture));

const pool = new pg.Pool({ connectionString: dbUrl });
await pool.query('drop schema public cascade; create schema public');
const srv = spawn('node', ['server.js'], { env: { ...process.env, NODE_ENV: 'test', PORT: '3996', ANTHROPIC_API_KEY: 'x', DATABASE_URL: dbUrl, PG_LIVE_GROUPS: 'system', L2H_TEST_KPI_INPUT: '/tmp/l2h-reports-fixture.json',
  BREVO_SMTP_HOST: '127.0.0.1', BREVO_SMTP_PORT: String(smtpPort), BREVO_SMTP_USER: 'x', BREVO_SMTP_PASS: 'x', BREVO_SENDER_EMAIL: 'sender@l2h.test', REMINDER_EMAIL_TO: 'dan@l2h.test', CRON_SECRET: 'secret' }, stdio: ['ignore', 'pipe', 'pipe'] });
let log = ''; srv.stdout.on('data', x => { log += x; }); srv.stderr.on('data', x => { log += x; });
const call = async (method, path, role = 'dan', body, raw) => {
  const r = await fetch('http://127.0.0.1:3996' + path, { method, headers: { 'X-User-Role': role, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return raw ? { status: r.status, buf: Buffer.from(await r.arrayBuffer()) } : { status: r.status, text: await r.text() };
};
const settle = () => new Promise(r => setTimeout(r, 600));
try {
  for (let i = 0; i < 40; i++) { try { if ((await fetch('http://127.0.0.1:3996/api/health')).ok) break; } catch (e) { /* not up yet */ } await new Promise(r => setTimeout(r, 500)); }

  // Ella and signed-out callers are refused everywhere, and the refusal carries no figures
  for (const [m, p, b] of [['GET', '/api/reports'], ['GET', `/api/reports/owner:${prev}`], ['GET', `/api/reports/owner:${prev}/pdf`], ['POST', '/api/reports/generate', { kind: 'owner', period: prev }], ['POST', '/api/outbox/ob-x/note', { note: 'hi' }]]) {
    for (const who of ['ella', '']) {
      const r = await call(m, p, who, b);
      ok(r.status === 403 && !/invoiced|£|salary|balance/i.test(r.text), `${who || 'signed out'} refused on ${m} ${p}: ${r.status} ${r.text.slice(0, 80)}`);
    }
  }
  ok((await call('GET', '/api/cron/reports', 'ella')).status === 403, 'the cron route refuses Ella');

  // the owner report is built once and frozen
  const g1 = await call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: prev, send: false });
  ok(g1.status === 200 && JSON.parse(g1.text).id === `owner:${prev}`, 'owner report generated: ' + g1.text.slice(0, 160));
  const one = JSON.parse((await call('GET', `/api/reports/owner:${prev}`)).text);
  ok(one.snapshot && one.snapshot.kind === 'owner' && one.markdown.includes('## Headline numbers'), 'snapshot and text stored');
  await new Promise(r => setTimeout(r, 1100));
  await call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: prev, send: false });
  const two = JSON.parse((await call('GET', `/api/reports/owner:${prev}`)).text);
  ok(two.generated_at === one.generated_at && JSON.stringify(two.snapshot) === JSON.stringify(one.snapshot), 'asking again does not rebuild it: the numbers stay frozen');
  ok(mails.length === 0, 'generating without sending sends nothing');

  // numbers equal the KPI screen for the same period
  const screen = JSON.parse((await call('GET', `/api/kpi/owner?asOf=${monthEnd}`)).text);
  ok(one.snapshot.headline.invoiced.now === screen.money.invoiced.month.now && screen.money.invoiced.month.now === 13900, `report invoiced ${one.snapshot.headline.invoiced.now} equals the screen ${screen.money.invoiced.month.now}`);
  ok(one.snapshot.headline.paid.now === screen.money.paid.month.now && one.snapshot.headline.rolesFilled.now === screen.pipeline.rolesFilled.month.now, 'paid and roles filled equal the screen');
  const screenNow = JSON.parse((await call('GET', '/api/kpi/owner')).text);
  ok(one.snapshot.money.outstanding.now === screenNow.money.outstanding.now && one.snapshot.money.overdue.now === screenNow.money.overdue.now, 'money owed and overdue equal the live screen');

  // the PDF shows the same numbers
  const pdf = await call('GET', `/api/reports/owner:${prev}/pdf`, 'dan', undefined, true);
  ok(pdf.status === 200 && pdf.buf.slice(0, 5).toString() === '%PDF-', 'a real PDF is served');
  fs.writeFileSync('/tmp/l2h-owner-report.pdf', pdf.buf);
  const txt = execFileSync('pdftotext', ['-layout', '/tmp/l2h-owner-report.pdf', '-'], { encoding: 'utf8' });
  ok(txt.includes('£13,900') && /Owner report/i.test(txt) && /Three focus points/.test(txt) && /Team performance/.test(txt), 'the PDF text holds the headline figure and every section');
  ok(!/[—–]/.test(txt), 'no em dash or en dash in the PDF');

  // sending: once, to Daniel Brown only, with the PDF. Asking again, or at the same moment, sends nothing more.
  const [s1, s2] = await Promise.all([call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: prev, send: true }), call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: prev, send: true })]);
  await settle();
  ok(s1.status === 200 && s2.status === 200, 'both calls answer');
  ok(mails.length === 1, `two sends at once make one email (${mails.length})`);
  ok(mails[0].to.length === 1 && mails[0].to[0] === 'dan@l2h.test', 'the owner report goes to Daniel Brown only: ' + mails[0].to.join(','));
  ok(/Subject: Live 2 Help owner report/.test(mails[0].data) && mails[0].data.includes('JVBERi0'), 'subject and the PDF attached');
  const s3 = await call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: prev, send: true });
  await settle();
  ok(JSON.parse(s3.text).skipped === 'already sent' && mails.length === 1, 'running the same month again creates no second email');
  const rows = (await pool.query("select id, status from st_report_runs where kind = 'owner'")).rows;
  ok(rows.length === 1 && rows[0].status === 'sent' && rows[0].id === `owner:${prev}`, 'one stored report for the month, marked sent');
  const rs = await call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: prev, send: true, resend: true });
  await settle();
  ok(rs.status === 200 && mails.length === 2 && mails[1].to.join() === 'dan@l2h.test', 'an explicit resend sends again, still to Daniel Brown only');
  ok((await call('POST', '/api/reports/generate', 'dan', { kind: 'owner', period: today.slice(0, 7), send: true })).status === 400, 'the month in progress is refused');
  const audit = (await pool.query("select count(*)::int as n from st_audit_log where action in ('report_generated','report_sent')").catch(() => ({ rows: [{ n: -1 }] }))).rows[0].n;
  ok(audit !== 0, 'reports are in the Audit Trail (' + audit + ')');

  // the weekly brief: once per day, Daniel Brown only
  mails.length = 0;
  const w1 = await call('POST', '/api/reports/generate', 'dan', { kind: 'weekly' });
  await settle();
  ok(w1.status === 200 && mails.length === 1 && mails[0].to.join() === 'dan@l2h.test', 'the weekly brief reaches Daniel Brown only: ' + w1.text.slice(0, 120));
  ok(/Subject: Live 2 Help week ahead/.test(mails[0].data) && /CASH/.test(mails[0].data) && /NEEDS A DECISION/.test(mails[0].data), 'the brief has cash and decisions');
  await call('POST', '/api/reports/generate', 'dan', { kind: 'weekly' });
  await settle();
  ok(mails.length === 1, 'asking again the same day sends no second brief');
  ok(!/[—–]/.test(mails[0].data.replace(/=\?UTF-8\?[^?]*\?[^?]*\?=/g, '')), 'no em dash or en dash in the brief');

  // the morning step records where reporting starts, and does not send an old month late
  mails.length = 0;
  const c1 = await call('GET', '/api/cron/reports?key=secret');
  ok(c1.status === 200, 'cron step runs: ' + c1.text.slice(0, 200));
  const start = (await pool.query("select value from st_settings where id = 'reports_start_month'")).rows[0];
  ok(start && start.value === today.slice(0, 7), 'first run records this month as the first to report');
  const c1j = JSON.parse(c1.text);
  ok(!c1j.owner && !c1j.ella, 'no old month is reported late: ' + c1.text.slice(0, 160));
  const list = JSON.parse((await call('GET', '/api/reports')).text);
  ok(list.reports.some(r => r.id === `owner:${prev}`) && list.startMonth === today.slice(0, 7) && list.reports.every(r => !('snapshot' in r)), 'the report list has no snapshots in it');
  console.log(`reports server: all ${n} checks passed`);
} catch (e) {
  console.error('FAILED:', e.message); console.error(log.split('\n').slice(-25).join('\n')); process.exitCode = 1;
} finally { srv.kill(); smtp.close(); await pool.end(); }
