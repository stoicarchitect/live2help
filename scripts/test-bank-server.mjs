// Build 63 server test against a fake Starling bank and a scratch Postgres.
//   TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5544/l2h node scripts/test-bank-server.mjs
// Skips with a message when no scratch database is given. Never touches the live database or the real bank.
import http from 'http';
import { spawn } from 'child_process';
import assert from 'assert';
import pg from 'pg';

const dbUrl = process.env.TEST_DATABASE_URL;
if (!dbUrl) { console.log('bank server test skipped: set TEST_DATABASE_URL to a scratch database'); process.exit(0); }
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };

const seen = [];
const feedItems = [
  { feedItemUid: 'it-1', categoryUid: 'cat-1', amount: { currency: 'GBP', minorUnits: 420050 }, direction: 'IN', transactionTime: '2026-11-10T09:00:00Z', settlementTime: '2026-11-10T12:00:00Z', updatedAt: '2026-11-10T12:00:00Z', counterPartyName: 'ACME FABRICATION LTD', reference: 'RS051126', spendingCategory: 'INCOME', source: 'FASTER_PAYMENTS_IN', status: 'SETTLED' },
  { feedItemUid: 'it-2', categoryUid: 'cat-1', amount: { currency: 'GBP', minorUnits: 28900 }, direction: 'OUT', transactionTime: '2026-11-09T09:00:00Z', settlementTime: '2026-11-09T12:00:00Z', updatedAt: '2026-11-09T12:00:00Z', counterPartyName: 'INDEED', reference: 'SPONSORED JOB', spendingCategory: 'MARKETING', source: 'MASTER_CARD', status: 'SETTLED' },
  { feedItemUid: 'it-3', categoryUid: 'cat-1', amount: { currency: 'GBP', minorUnits: 125000 }, direction: 'IN', transactionTime: '2026-11-08T09:00:00Z', settlementTime: '2026-11-08T12:00:00Z', updatedAt: '2026-11-08T12:00:00Z', counterPartyName: 'STRIPE TECHNOLOGY EUROPE', reference: 'STRIPE', spendingCategory: 'INCOME', source: 'FASTER_PAYMENTS_IN', status: 'SETTLED' },
  { feedItemUid: 'it-4', categoryUid: 'cat-1', amount: { currency: 'GBP', minorUnits: 5000 }, direction: 'OUT', transactionTime: '2026-11-07T09:00:00Z', updatedAt: '2026-11-07T09:00:00Z', counterPartyName: 'COFFEE', reference: '', spendingCategory: 'EATING_OUT', source: 'MASTER_CARD', status: 'DECLINED' },
];
const bank = http.createServer((req, res) => {
  seen.push(req.method + ' ' + req.url.split('?')[0] + ' auth=' + (req.headers.authorization || ''));
  const json = o => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.url === '/api/v2/accounts') return json({ accounts: [{ accountUid: 'acc-1', accountType: 'PRIMARY', defaultCategory: 'cat-1', currency: 'GBP', name: 'Fake business account' }] });
  if (/\/balance$/.test(req.url)) return json({ effectiveBalance: { currency: 'GBP', minorUnits: 1234567 }, clearedBalance: { currency: 'GBP', minorUnits: 1234567 } });
  if (/\/feed\/account\/acc-1\/category\/cat-1/.test(req.url)) return json({ feedItems: feedItems });
  res.statusCode = 404; res.end('{}');
});
await new Promise(r => bank.listen(5599, '127.0.0.1', r));

const pool = new pg.Pool({ connectionString: dbUrl });
await pool.query('drop schema public cascade; create schema public');

const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT: '3998', ANTHROPIC_API_KEY: 'x', DATABASE_URL: dbUrl, PG_LIVE_GROUPS: 'system', STARLING_TOKEN: 'fake-token', STARLING_BASE_URL: 'http://127.0.0.1:5599' }, stdio: ['ignore', 'pipe', 'pipe'] });
let log = ''; srv.stdout.on('data', d => { log += d; }); srv.stderr.on('data', d => { log += d; });
const call = async (method, path, role = 'dan', body) => {
  const r = await fetch('http://127.0.0.1:3998' + path, { method, headers: { 'X-User-Role': role, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
try {
  for (let i = 0; i < 40; i++) { try { if ((await fetch('http://127.0.0.1:3998/api/health')).ok) break; } catch (e) { /* not up yet */ } await new Promise(r => setTimeout(r, 500)); }

  const p1 = await call('POST', '/api/bank/poll');
  ok(p1.body.ok === true && p1.body.added === 4, 'first poll stores the four feed items: ' + JSON.stringify(p1.body));
  const p2 = await call('POST', '/api/bank/poll');
  ok(p2.body.ok === true && p2.body.added === 0, 'second poll creates no duplicates: ' + JSON.stringify(p2.body));
  const count = +(await pool.query('select count(*)::int as n from st_bank_transactions')).rows[0].n;
  ok(count === 4, 'four rows in the table after two polls, got ' + count);

  const rows = (await pool.query('select * from st_bank_transactions order by id')).rows;
  const by = id => rows.find(r => r.id === id);
  ok(by('it-1').kind === 'client_payment' && by('it-1').amount === '4200.5', 'client payment classified');
  ok(by('it-2').kind === 'cost' && by('it-2').cost_bucket === 'Advertising', 'Indeed is an advertising cost');
  ok(by('it-3').kind === 'stripe_payout', 'Stripe payout recognised');
  ok(by('it-4').status === 'DECLINED', 'declined item kept but not settled');

  // only GETs, only the three read-only paths, with the token as a bearer header
  ok(seen.length >= 5 && seen.every(s => s.startsWith('GET ')), 'bank only ever saw GET requests: ' + seen.join(' | '));
  ok(seen.every(s => /accounts( |$)|\/balance|\/feed\/account\//.test(s)), 'only read-only paths');
  ok(seen.every(s => s.endsWith('auth=Bearer fake-token')), 'token sent as a bearer header');

  // the token and balance never come back to the browser
  const st = await call('GET', '/api/bank/status');
  ok(st.status === 200 && st.body.hasToken === true && !JSON.stringify(st.body).includes('fake-token'), 'status never returns the token');
  ok(st.body.balance && st.body.balance.amount === 12345.67, 'balance stored: ' + JSON.stringify(st.body.balance));
  const set = (await pool.query("select id, value from st_settings")).rows.map(r => r.id + '=' + r.value).join('\n');
  ok(!set.includes('fake-token'), 'the token is not stored in the database');

  // Ella and anonymous get nothing
  for (const role of ['ella', '']) for (const [m, p] of [['GET', '/api/bank/status'], ['GET', '/api/bank/transactions'], ['GET', '/api/bank/summary'], ['POST', '/api/bank/poll'], ['GET', '/api/bank-rules']]) {
    const r = await call(m, p, role); ok(r.status === 403, `${role || 'anonymous'} refused on ${p}`);
  }
  const tx = await call('GET', '/api/bank/transactions');
  ok(tx.status === 200 && tx.body.data.length === 3 && tx.body.data[0].id === 'it-1', 'owner sees settled transactions newest first');

  // rules: seeded, editable, and the reclassify route applies a change
  const rules = await call('GET', '/api/bank-rules');
  ok(rules.status === 200 && rules.body.data.length >= 10, 'default rules seeded');
  await pool.query("update st_bank_rules set bucket = 'Job boards' where pattern = 'INDEED'");
  const rc = await call('POST', '/api/bank/reclassify');
  ok(rc.body.ok && rc.body.changed === 1, 'reclassify applied the edited rule: ' + JSON.stringify(rc.body));
  ok((await pool.query("select cost_bucket from st_bank_transactions where id = 'it-2'")).rows[0].cost_bucket === 'Job boards', 'cost re-filed under the edited rule');

  // a decision made by Daniel Brown survives the bank re-sending the same item
  await pool.query("update st_bank_transactions set match_status = 'ignored', role_tag = 'Welder' where id = 'it-1'");
  feedItems[0].updatedAt = '2026-11-11T08:00:00Z'; feedItems[0].status = 'SETTLED';
  await call('POST', '/api/bank/poll');
  const kept = (await pool.query("select match_status, role_tag from st_bank_transactions where id = 'it-1'")).rows[0];
  ok(kept.match_status === 'ignored' && kept.role_tag === 'Welder', 'a re-sent item keeps the decisions made here');

  // the pause switch
  console.log(`bank server: all ${n} checks passed`);
} finally {
  srv.kill(); bank.close(); await pool.end();
}
