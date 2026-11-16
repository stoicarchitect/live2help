// Build 63 tests: node scripts/test-bank.mjs
import assert from 'assert';
import {
  createStarlingClient, createDemoStarling, isAllowedStarlingPath, toBankRow, classifyRow, matchPayments, nameMatches, referenceHasInvoice,
  findPayoutFor, reconcilePayout, latePayerScores, detectRecurring, corporationTax, cashForecast, bankKpi, monthlyFlows, categoriseCost,
} from '../bank.js';
import { computeOwnerKpi, computeMyKpi } from '../kpi-owner.js';

let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const eq = (a, b, m) => { assert.deepStrictEqual(a, b, m); n++; };

// ---------- read only: nothing but three GET paths is possible ----------
ok(isAllowedStarlingPath('/api/v2/accounts'), 'accounts allowed');
ok(isAllowedStarlingPath('/api/v2/accounts/abc-123/balance'), 'balance allowed');
ok(isAllowedStarlingPath('/api/v2/feed/account/abc/category/def'), 'feed allowed');
for (const bad of ['/api/v2/payments/local/account/a/category/c', '/api/v2/account/a/payees', '/api/v2/payments/mandates', '/api/v2/accounts/a/standing-orders', '/api/v2/accounts/a/balance/../x', '/api/v2/feed/account/a/category/c/transactions-between/x', '/api/v2/accounts/a/savings-goals']) ok(!isAllowedStarlingPath(bad), 'blocked ' + bad);
{
  const calls = [];
  const c = createStarlingClient({ token: 't0ken', fetchImpl: async (url, o) => { calls.push({ url, o }); return { ok: true, json: async () => ({ accounts: [], feedItems: [] }), text: async () => '' }; } });
  await c.accounts(); await c.balance('a1'); await c.feed('a1', 'c1', '2026-01-01T00:00:00Z');
  ok(calls.every(x => x.o.method === 'GET'), 'every call is a GET');
  ok(calls.every(x => x.o.headers.Authorization === 'Bearer t0ken'), 'token sent as bearer only');
  ok(calls[2].url.includes('changesSince='), 'feed uses changesSince');
  const m = await c.feed('a1', 'c1', 'x').then(() => 'ok'); ok(m === 'ok');
  assert.throws(() => createStarlingClient({}), /No Starling token/); n++;
  const failing = createStarlingClient({ token: 'x', fetchImpl: async () => ({ ok: false, status: 403, text: async () => 'nope' }) });
  await assert.rejects(failing.accounts(), /403/); n++;
}
{
  const d = createDemoStarling('2026-11-16T12:00:00Z'); const [a] = await d.accounts();
  const items = await d.feed(a.accountUid, a.defaultCategory, '2026-01-01T00:00:00Z');
  ok(items.length >= 6 && (await d.balance()).effectiveBalance.minorUnits > 0, 'demo feed works');
}

// ---------- normalising and duplicate safe ----------
const item = { feedItemUid: 'f1', amount: { currency: 'GBP', minorUnits: 420050 }, direction: 'IN', transactionTime: '2026-11-10T09:30:00Z', settlementTime: '2026-11-10T12:00:00Z', counterPartyName: 'Acme Fabrication Ltd', reference: 'RS051126', spendingCategory: 'INCOME', source: 'FASTER_PAYMENTS_IN', status: 'SETTLED', updatedAt: '2026-11-10T12:00:00Z' };
const row = toBankRow(item, 'acc1');
eq([row.id, row.amount, row.direction, row.date], ['f1', '4200.5', 'IN', '2026-11-10'], 'row from feed item');
eq(toBankRow(item, 'acc1'), row, 'same item gives the same row (so a re-run overwrites, never duplicates)');

// ---------- invoice matching ----------
const inv = (number, company, amount, status = 'pending', extra = {}) => ({ number, company, amount, amountDue: amount, status, date: '2026-10-20', dueDate: '2026-11-03', ...extra });
const invoices = [inv('RS051126', 'Acme Fabrication Ltd', 4200.5), inv('RS071126', 'Beta Engineering Limited', 3000), inv('RS081126', 'Beta Engineering Limited', 3000), inv('RS091126', 'Gamma Tools', 5000), inv('RS101126', 'Delta Plastics', 2500, 'paid', { paymentDate: '2026-11-05' }), inv('RS111126', 'Echo Systems', 1800), inv('RS121126', 'Echo Systems', 1200)];
const tx = (id, amount, counterparty, reference, extra = {}) => ({ id, direction: 'IN', kind: 'client_payment', status: 'SETTLED', amount: String(amount), counterparty, reference, date: '2026-11-12', match_status: '', ...extra });
{
  const r = matchPayments([
    tx('t1', 4200.5, 'ACME FABRICATION LTD', 'Invoice RS051126'),          // number + amount -> auto
    tx('t2', 3000, 'BETA ENGINEERING', 'fees'),                            // two same amount invoices -> confirm
    tx('t3', 5000, 'Gamma Tools Ltd', ''),                                 // name + unique amount -> auto
    tx('t4', 1000, 'Echo Systems Ltd', 'RS 11 11 26'),                     // reference matches (spaces), part payment -> confirm
    tx('t5', 2500, 'DELTA PLASTICS', 'RS101126'),                          // already paid -> confirm duplicate
    tx('t6', 3000, 'SOMEONE ELSE', 'thanks'),                              // amount only -> confirm, not auto
    tx('t7', 77, 'Random Person', 'gift'),                                 // nothing -> ignored
    tx('t8', 3000, 'Cost Item', 'x', { direction: 'OUT', kind: 'cost' }),  // outgoing never matched
    tx('t9', 4200.5, 'ACME FABRICATION LTD', 'RS051126', { match_status: 'matched' }), // already done
  ], invoices);
  eq(r.auto.map(a => [a.tx.id, a.invoice.number]).sort(), [['t1', 'RS051126'], ['t3', 'RS091126']], 'exact and unique matches are automatic');
  const c = Object.fromEntries(r.confirm.map(x => [x.tx.id, x]));
  ok(c.t2 && c.t2.candidates.length === 2, 'same amount twice goes to confirm with both candidates');
  ok(c.t4 && /Part payment/.test(c.t4.reason), 'part payment goes to confirm');
  ok(c.t5 && /already marked paid/.test(c.t5.reason), 'payment for a paid invoice is flagged, never overwritten');
  ok(c.t6 && !r.auto.some(a => a.tx.id === 't6'), 'amount only is never automatic');
  ok(!c.t7 && !c.t8 && !c.t9, 'unrelated, outgoing and already matched items are left alone');
  // two payments for one invoice: neither is automatic
  const dup = matchPayments([tx('d1', 4200.5, 'ACME FABRICATION LTD', 'RS051126'), tx('d2', 4200.5, 'ACME FABRICATION LTD', 'RS051126')], invoices);
  eq(dup.auto.length, 0, 'two payments for one invoice both need confirming'); eq(dup.confirm.length, 2);
  // a paid invoice is never an automatic target
  eq(matchPayments([tx('p1', 2500, 'DELTA PLASTICS', '')], invoices).auto.length, 0, 'paid invoices are not matched');
}
ok(nameMatches('ACME FABRICATION LTD', 'Acme Fabrication Limited') && nameMatches('BETA ENGINEERING', 'Beta Engineering Limited') && !nameMatches('Beta Plastics', 'Beta Engineering'), 'name matching');
ok(referenceHasInvoice('RS-051126 thanks', 'RS051126') && !referenceHasInvoice('RS0511261', 'RS051126') && !referenceHasInvoice('xRS051126', 'RS051126'), 'reference boundaries');

// ---------- Stripe payouts ----------
{
  const payouts = [{ id: 'po_1', amount: 123456, currency: 'gbp', arrival_date: Date.parse('2026-11-10T00:00:00Z') / 1000 }, { id: 'po_2', amount: 5000, currency: 'gbp', arrival_date: Date.parse('2026-11-01T00:00:00Z') / 1000 }];
  const bank = { amount: '1234.56', date: '2026-11-11' };
  eq(findPayoutFor(bank, payouts).id, 'po_1', 'payout found by amount and date');
  eq(findPayoutFor({ amount: '1234.56', date: '2026-12-25' }, payouts), null, 'no payout far from the date');
  const bts = [{ type: 'charge', amount: 100000, fee: 1500, net: 98500 }, { type: 'charge', amount: 25000, fee: 44, net: 24956 }, { type: 'payment', amount: 1000, fee: 0, net: 1000 }, { type: 'payout', amount: -124456, fee: 0, net: -124456 }];
  const rec = reconcilePayout(payouts[0], bts);
  eq([rec.gross, rec.fees, rec.net, rec.ok], [1260, 15.44, 1244.56, false], 'payout shows its own gap when it does not add up');
  const rec2 = reconcilePayout({ id: 'po_x', amount: 124456 }, bts);
  eq([rec2.gross, rec2.fees, rec2.net, rec2.ok, rec2.count], [1260, 15.44, 1244.56, true, 3], 'payout reconciles to the sum of its payments less fees');
}

// ---------- cost rules ----------
eq(categoriseCost({ counterparty: 'INDEED', reference: 'x' }).bucket, 'Advertising', 'Indeed is advertising');
eq(categoriseCost({ counterparty: 'HMRC CT', reference: 'x' }).bucket, 'Tax (HMRC)');
eq(categoriseCost({ counterparty: 'Ella P', reference: 'Salary Nov' }).bucket, 'Payroll');
eq(categoriseCost({ counterparty: 'Joe Plumber', reference: 'x' }).bucket, 'Other');
eq(categoriseCost({ counterparty: 'ACME', reference: 'x' }, [{ pattern: 'ACME', bucket: 'Custom' }]).bucket, 'Custom', 'editable rules are used');

// ---------- late payers ----------
{
  const s = latePayerScores([inv('A1', 'Slow Co', 1000, 'paid', { date: '2026-06-01', dueDate: '2026-06-15', paymentDate: '2026-07-15' }), inv('A2', 'Slow Co', 1000, 'paid', { date: '2026-07-01', dueDate: '2026-07-15', paymentDate: '2026-08-14' }), inv('A3', 'Prompt Co', 1000, 'paid', { date: '2026-06-01', dueDate: '2026-06-15', paymentDate: '2026-06-10' }), inv('A4', 'Open Co', 10)], '2026-11-16');
  eq([s['slow co'].avgDaysLate, s['slow co'].label, s['slow co'].onTimePct], [30, 'Slow', 0], 'slow payer scored from invoice dates');
  eq([s['prompt co'].label, s['prompt co'].onTimePct], ['Prompt', 100]);
  ok(!s['open co'], 'unpaid invoices are not scored');
}

// ---------- recurring, flows ----------
const cost = (id, date, who, amount, bucket) => ({ id, date, direction: 'OUT', kind: 'cost', status: 'SETTLED', counterparty: who, amount: String(amount), cost_bucket: bucket });
const rows = [cost('c1', '2026-08-12', 'MICROSOFT 365', 38, 'Software'), cost('c2', '2026-09-12', 'MICROSOFT 365', 38, 'Software'), cost('c3', '2026-10-12', 'MICROSOFT 365', 38, 'Software'),
  cost('c4', '2026-10-03', 'INDEED', 289, 'Advertising'), cost('c5', '2026-11-03', 'INDEED', 411, 'Advertising'), cost('c6', '2026-09-30', 'HMRC', 900, 'Tax (HMRC)'), cost('c7', '2026-10-30', 'HMRC', 900, 'Tax (HMRC)'),
  { ...tx('i1', 5000, 'Gamma Tools', 'RS091126', { date: '2026-11-05' }) }, { ...tx('i2', 100, 'Savings', '', { date: '2026-11-05', kind: 'transfer' }) }];
{
  const rec = detectRecurring(rows, '2026-11-16');
  eq(rec.map(r => r.name), ['MICROSOFT 365'], 'only steady monthly costs are recurring (varying Indeed and HMRC are not)');
  ok(rec[0].nextDate >= '2026-11-16', 'next date is in the future');
  const f = monthlyFlows(rows, 3, '2026-11-16');
  eq(f.map(x => x.month), ['2026-09', '2026-10', '2026-11']); eq(f[2].in, 5000, 'internal transfers are not money in'); eq(f[2].out, 411);
}

// ---------- tax and cash ----------
eq([corporationTax(0), corporationTax(40000), corporationTax(50000), corporationTax(100000), corporationTax(250000), corporationTax(300000)], [0, 7600, 9500, 22750, 62500, 75000], 'corporation tax bands and marginal relief');
eq(corporationTax(100000, 20), 20000, 'flat rate setting overrides');
{
  const fc = cashForecast({ balance: 10000, openInvoices: [inv('F1', 'Prompt Co', 5000, 'pending', { dueDate: '2026-11-30' })], scores: { 'prompt co': { invoices: 3, avgDaysLate: 0 } }, recurring: [{ name: 'MICROSOFT 365', bucket: 'Software', amount: 38, nextDate: '2026-12-12' }], monthlyPayroll: 3000, todayISO: '2026-11-16', floor: 9000 });
  ok(fc.lowest.balance < 10000 && fc.expectedIn === 4750 && fc.expectedOut >= 9000, 'forecast: weighted inflow, payroll and recurring out');
  ok(fc.series[0].balance === 10000 && fc.series.length >= 13, 'forecast series');
  const tight = cashForecast({ balance: 1000, openInvoices: [], scores: {}, recurring: [], monthlyPayroll: 3000, todayISO: '2026-11-16', floor: 500 });
  ok(tight.belowFloor, 'floor breach detected');
}

// ---------- the owner view carries it, and Ella gets none of it ----------
{
  const base = { now: '2026-11-16T10:00:00Z', invoices: invoices.map(i => ({ ...i, amount: i.amount })), candidates: [], roles: [], audit: [], activity: [], comms: [], interviews: [], adSpend: [], placements: [], otherSales: [], settings: {}, snapshots: {}, vatMarkers: {}, kpiTargets: [], clientFirstSeen: [], employees: [], fin: { manualAd: 0, overheads: 0 } };
  const off = computeOwnerKpi(base);
  eq([off.money.bank.connected, off.cost.bank.connected, off.bank.connected], [false, false, false], 'not connected says so with no invented figures');
  ok(/STARLING_TOKEN/.test(off.bank.note), 'says how to connect');
  const withBank = computeOwnerKpi({ ...base, bank: { connected: true, mode: 'live', balance: { amount: 12000, at: '2026-11-16T09:00:00Z' }, rows: rows.map(r => ({ stripe_fee: '', ...r })), settings: { cash_floor: '2000' }, status: {} } });
  eq(withBank.money.bank.connected, true); eq(withBank.money.bank.balance, 12000);
  ok(withBank.money.bank.spendable <= 12000 && withBank.bank.forecast.series.length > 5 && withBank.bank.costBuckets.length >= 3, 'owner view has balance, spendable, forecast and cost buckets');
  const mine = JSON.stringify(computeMyKpi({ ...base, bank: { connected: true, balance: { amount: 12000 }, rows } }, 'ella'));
  ok(!/balance|spendable|forecast|bank|12000|taxReserve|HMRC/i.test(mine), 'Ella\'s response holds no bank word or value');
}
console.log(`bank: all ${n} checks passed`);
