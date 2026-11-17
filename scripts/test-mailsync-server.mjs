// Build 66 server test: the mailbox sync routes against a scratch Postgres.
//   TEST_DATABASE_URL=postgres://postgres:x@127.0.0.1:5432/l2h node scripts/test-mailsync-server.mjs
// Skips when no scratch database is given. Never touches a real mailbox or the live database.
// Google Sheets and Microsoft Graph are not reachable here, so this covers who may do what, the switch, suggestions, do not log and
// what happens when the sync cannot read its records. The reading itself is covered by scripts/test-mailsync.mjs.
import { spawn } from 'child_process';
import assert from 'assert';
import pg from 'pg';

const dbUrl = process.env.TEST_DATABASE_URL;
if (!dbUrl) { console.log('mailsync server test skipped: set TEST_DATABASE_URL to a scratch database'); process.exit(0); }
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const pool = new pg.Pool({ connectionString: dbUrl });
await pool.query('drop schema public cascade; create schema public');
const srv = spawn('node', ['server.js'], { env: { ...process.env, NODE_ENV: 'test', PORT: '3997', ANTHROPIC_API_KEY: 'x', DATABASE_URL: dbUrl, PG_LIVE_GROUPS: 'system',
  BREVO_SMTP_HOST: '127.0.0.1', BREVO_SMTP_PORT: '1', BREVO_SMTP_USER: 'x', BREVO_SMTP_PASS: 'x', BREVO_SENDER_EMAIL: 'sender@l2h.test', REMINDER_EMAIL_TO: 'dan@l2h.test', CRON_SECRET: 'secret' }, stdio: ['ignore', 'pipe', 'pipe'] });
let log = ''; srv.stdout.on('data', x => { log += x; }); srv.stderr.on('data', x => { log += x; });
const call = async (method, path, role = 'dan', body) => {
  const r = await fetch('http://127.0.0.1:3997' + path, { method, headers: { 'X-User-Role': role, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, text: await r.text() };
};
const J = r => JSON.parse(r.text);
try {
  for (let i = 0; i < 40; i++) { try { if ((await fetch('http://127.0.0.1:3997/api/health')).ok) break; } catch (e) { /* not up yet */ } await new Promise(r => setTimeout(r, 500)); }

  // only Daniel Brown can look at or change the sync
  for (const [m, p, b] of [['GET', '/api/mailsync/status'], ['POST', '/api/mailsync/settings', { enabled: true }], ['POST', '/api/mailsync/run', {}], ['POST', '/api/mailsync/do-not-log', { email: 'a@b.com' }], ['DELETE', '/api/mailsync/do-not-log/a@b.com']]) {
    for (const who of ['ella', '']) {
      const r = await call(m, p, who, b);
      ok(r.status === 403, `${who || 'signed out'} refused on ${m} ${p}: ${r.status}`);
    }
  }
  ok((await call('GET', '/api/mailsync/log?email=a@b.com', '')).status === 403, 'signed out cannot read the log');
  ok((await call('GET', '/api/mailsync/suggestions', '')).status === 403, 'signed out cannot read suggestions');

  // off until switched on
  let st = J(await call('GET', '/api/mailsync/status'));
  ok(st.stored === true && st.enabled === false && st.noReplyDays === 2, 'starts off, with a 2 day no reply rule');
  const off = await call('POST', '/api/mailsync/run', 'dan', {});
  ok(off.status === 409 && /switched off/.test(off.text), 'a run while off is refused with a plain message');

  // switch on, starting 7 days back
  const on = await call('POST', '/api/mailsync/settings', 'dan', { enabled: true, backfillDays: 7, noReplyDays: 3 });
  ok(on.status === 200 && J(on).enabled === true && J(on).noReplyDays === 3, 'switched on with 3 days: ' + on.text.slice(0, 120));
  st = J(await call('GET', '/api/mailsync/status'));
  const since = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
  ok(st.enabled && st.sinceDay === since, `first read starts from ${since}: ${st.sinceDay}`);
  const aud = (await pool.query("select count(*)::int as n from st_audit_log where action = 'switched_on'").catch(() => ({ rows: [{ n: -1 }] }))).rows[0].n;
  ok(aud !== 0, 'switching on is in the Audit Trail (' + aud + ')');

  // with the records unreadable (no Google here) the run stops cleanly, reports why, and reads no mail
  const run = await call('POST', '/api/mailsync/run', 'dan', {});
  ok(run.status === 200 && J(run).errors && J(run).errors.length === 1 && /nothing is missed|No mail was read/i.test(J(run).errors[0]), 'an unreadable record source stops the run and says so: ' + run.text.slice(0, 200));
  st = J(await call('GET', '/api/mailsync/status'));
  ok(st.error && st.lastOk === '' , 'the status shows the problem');

  // seed the tables the sync writes, now they exist
  const sug = (id, owner, kind) => pool.query(`insert into st_mail_suggestions (id, kind, contact_email, contact_name, contact_type, company, role, mailbox, owner, mail_id, subject, evidence, status, created_at, handled_by, handled_at, result) values ($1,$2,'x@y.com','Sam','candidate','Acme','Welder',$3,$4,'ml-1','Re: offer','I accept the offer','pending','2026-11-17T09:00:00Z','','','')`,
    [id, kind, owner + '@l2h.test', owner]);
  await sug('sg-dan', 'dan', 'offer_accepted'); await sug('sg-ella', 'ella', 'candidate_withdrawn');
  const ellaSees = J(await call('GET', '/api/mailsync/suggestions', 'ella'));
  ok(ellaSees.pending.length === 1 && ellaSees.pending[0].id === 'sg-ella', 'Ella sees only the suggestions from her own mailbox');
  ok(J(await call('GET', '/api/mailsync/suggestions', 'dan')).pending.length === 2, 'Daniel Brown sees both');
  ok((await call('POST', '/api/mailsync/suggestions/sg-dan/dismiss', 'ella')).status === 404, 'Ella cannot touch a suggestion from his mailbox');
  const dis = await call('POST', '/api/mailsync/suggestions/sg-ella/dismiss', 'ella');
  ok(dis.status === 200, 'Ella can dismiss her own');
  ok((await call('POST', '/api/mailsync/suggestions/sg-ella/dismiss', 'ella')).status === 409, 'a handled suggestion cannot be handled twice');
  const row = (await pool.query("select status, handled_by from st_mail_suggestions where id = 'sg-ella'")).rows[0];
  ok(row.status === 'dismissed' && row.handled_by === 'ella', 'dismissal recorded against Ella');
  ok(J(await call('GET', '/api/mailsync/suggestions', 'dan')).pending.length === 1, 'it leaves the pending list');

  // the log: each person sees only their own mailbox, and a contact removed from logging is cleared
  const ml = (id, owner, email) => pool.query(`insert into st_mailbox_log (id, mailbox, owner, direction, contact_email, contact_name, contact_type, company, role, subject, preview, at, conversation_id, logged_at) values ($1,$2,$3,'in',$4,'Jane','client','Acme','','Hello','hi there','2026-11-17T09:00:00Z','c','2026-11-17T09:01:00Z')`, [id, owner + '@l2h.test', owner, email]);
  await ml('ml-a', 'dan', 'jane@acme.co.uk'); await ml('ml-b', 'ella', 'jane@acme.co.uk'); await ml('ml-c', 'dan', 'other@acme.co.uk');
  ok(J(await call('GET', '/api/mailsync/log?email=jane@acme.co.uk', 'dan')).rows.length === 2, 'Daniel Brown sees both mailboxes on a contact');
  const ellaLog = J(await call('GET', '/api/mailsync/log?email=jane@acme.co.uk', 'ella')).rows;
  ok(ellaLog.length === 1 && ellaLog[0].owner === 'ella', 'Ella sees only mail from her own mailbox');
  ok((await call('GET', '/api/mailsync/log', 'dan')).status === 400, 'the log needs an address or a company');
  ok(J(await call('GET', '/api/mailsync/log?company=Acme', 'dan')).rows.length === 3, 'a company timeline shows all its contacts');

  const dn = await call('POST', '/api/mailsync/do-not-log', 'dan', { email: 'Jane@Acme.co.uk' });
  ok(dn.status === 200 && J(dn).removed === 2, 'do not log clears what was stored: ' + dn.text);
  ok((await pool.query("select count(*)::int as n from st_mailbox_log where contact_email = 'jane@acme.co.uk'")).rows[0].n === 0, 'nothing is left for that address');
  ok((await pool.query("select count(*)::int as n from st_mailbox_log where contact_email = 'other@acme.co.uk'")).rows[0].n === 1, 'other contacts are untouched');
  ok((await call('POST', '/api/mailsync/do-not-log', 'dan', { email: 'not an address' })).status === 400, 'a bad address is refused');
  st = J(await call('GET', '/api/mailsync/status'));
  ok(st.doNotLog.length === 1 && st.doNotLog[0].email === 'jane@acme.co.uk' && st.loggedTotal === 1, 'the list and counts update');
  ok((await call('DELETE', '/api/mailsync/do-not-log/jane@acme.co.uk', 'dan')).status === 200 && J(await call('GET', '/api/mailsync/status')).doNotLog.length === 0, 'an address can be taken off the list');

  // switching off
  ok(J(await call('POST', '/api/mailsync/settings', 'dan', { enabled: false })).enabled === false, 'it can be switched off again');
  ok(!/[–—]/.test(JSON.stringify(st)), 'no em or en dashes in what the status says');
  console.log(`mailsync server: all ${n} checks passed`);
} catch (e) {
  console.error('FAILED:', e.message); console.error(log.split('\n').slice(-15).join('\n')); process.exitCode = 1;
} finally { srv.kill(); await pool.end(); }
