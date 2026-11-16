/* Live 2 Help - build 63: Starling bank feed.

   Everything here is pure (no database, no network) except createStarlingClient, which can only ever
   make GET requests to three read-only Starling paths. Nothing in this file can move money.
   The server wires these functions to Postgres, the invoices and the daily job; the dashboard and the
   monthly reports (build 65) read the same figures through computeOwnerKpi, so they always agree.
   Tests: node scripts/test-bank.mjs */

const DAY = 86400000;
const round2 = n => Math.round((Number(n) || 0) * 100) / 100;
const num = v => { const x = parseFloat(String(v == null ? '' : v).replace(/[£,\s]/g, '')); return Number.isFinite(x) ? x : 0; };
const lc = s => String(s == null ? '' : s).trim().toLowerCase();
const isoDay = d => new Date(d).toISOString().slice(0, 10);
const dayMs = s => { const t = Date.parse(String(s || '').slice(0, 10) + 'T00:00:00Z'); return Number.isFinite(t) ? t : null; };
const addDaysISO = (iso, n) => isoDay(dayMs(iso) + n * DAY);
const monthKey = iso => String(iso || '').slice(0, 7);

/* ====================================================================
   Read-only Starling client
   ==================================================================== */
export const STARLING_LIVE = 'https://api.starlingbank.com';
export const STARLING_SANDBOX = 'https://api-sandbox.starlingbank.com';
// the only paths this client will ever call. No payment, payee, mandate or standing order path is on the list.
const ALLOWED_PATHS = [
  /^\/api\/v2\/accounts$/,
  /^\/api\/v2\/accounts\/[A-Za-z0-9-]+\/balance$/,
  /^\/api\/v2\/feed\/account\/[A-Za-z0-9-]+\/category\/[A-Za-z0-9-]+$/,
];
export function isAllowedStarlingPath(p) { return ALLOWED_PATHS.some(r => r.test(p)); }

export function createStarlingClient({ token, base = STARLING_LIVE, fetchImpl = globalThis.fetch } = {}) {
  if (!token) throw new Error('No Starling token');
  async function get(path, query) {
    if (!isAllowedStarlingPath(path)) throw new Error('Blocked: ' + path + ' is not a read-only Starling path');
    const qs = query ? '?' + new URLSearchParams(query).toString() : '';
    const r = await fetchImpl(base + path + qs, { method: 'GET', headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' } });
    if (!r.ok) {
      const body = await r.text().catch(() => '');
      throw new Error(`Starling ${r.status}${r.status === 403 ? ' (token missing a scope, or account not linked)' : r.status === 401 ? ' (token rejected - check STARLING_TOKEN)' : ''}: ${body.slice(0, 160)}`);
    }
    return r.json();
  }
  return {
    mode: base === STARLING_SANDBOX ? 'sandbox' : 'live',
    async accounts() { return (await get('/api/v2/accounts')).accounts || []; },
    async balance(accountUid) { return get(`/api/v2/accounts/${accountUid}/balance`); },
    async feed(accountUid, categoryUid, changesSinceISO) {
      return ((await get(`/api/v2/feed/account/${accountUid}/category/${categoryUid}`, { changesSince: changesSinceISO })).feedItems) || [];
    },
  };
}

/* A believable fake account for tests and for the /dashboard-next preview. Never used on the live workspace. */
export function createDemoStarling(nowISO) {
  const now = dayMs(nowISO || new Date().toISOString()) || Date.now();
  const at = (daysAgo, hh = 10) => new Date(now - daysAgo * DAY + hh * 3600000).toISOString();
  const item = (id, daysAgo, direction, pounds, name, reference, spendingCategory, source = 'FASTER_PAYMENTS_IN') => ({
    feedItemUid: id, categoryUid: 'demo-cat', amount: { currency: 'GBP', minorUnits: Math.round(pounds * 100) }, direction,
    transactionTime: at(daysAgo), settlementTime: at(daysAgo, 12), updatedAt: at(daysAgo, 12), counterPartyName: name, reference, spendingCategory, source, status: 'SETTLED',
  });
  const items = [
    item('demo-1', 3, 'IN', 4200, 'DEMO CLIENT LTD', 'DEMO0001 FEE', 'INCOME'),
    item('demo-2', 5, 'IN', 1250, 'STRIPE TECHNOLOGY EUROPE', 'STRIPE', 'INCOME'),
    item('demo-3', 6, 'OUT', 289, 'INDEED', 'INDEED SPONSORED JOB', 'MARKETING', 'FASTER_PAYMENTS_OUT'),
    item('demo-4', 9, 'OUT', 3100, 'ELLA SALARY', 'SALARY', 'PAYROLL', 'FASTER_PAYMENTS_OUT'),
    item('demo-5', 12, 'OUT', 38, 'MICROSOFT 365', 'MSFT', 'SOFTWARE', 'MASTER_CARD'),
    item('demo-6', 35, 'OUT', 289, 'INDEED', 'INDEED SPONSORED JOB', 'MARKETING', 'FASTER_PAYMENTS_OUT'),
    item('demo-7', 33, 'OUT', 38, 'MICROSOFT 365', 'MSFT', 'SOFTWARE', 'MASTER_CARD'),
    item('demo-8', 64, 'OUT', 38, 'MICROSOFT 365', 'MSFT', 'SOFTWARE', 'MASTER_CARD'),
  ];
  return {
    mode: 'demo',
    async accounts() { return [{ accountUid: 'demo-account', defaultCategory: 'demo-cat', currency: 'GBP', name: 'Demo business account' }]; },
    async balance() { return { effectiveBalance: { currency: 'GBP', minorUnits: 1845000 }, clearedBalance: { currency: 'GBP', minorUnits: 1845000 } }; },
    async feed(a, c, since) { return items.filter(i => i.updatedAt >= since); },
  };
}

/* ====================================================================
   Normalising Starling feed items into stored rows
   ==================================================================== */
export const BANK_HEADER = [
  'id', 'account', 'date', 'settled_at', 'direction', 'amount', 'counterparty', 'reference', 'category', 'source', 'status',
  'kind', 'match_status', 'invoice_numbers', 'matched_at', 'matched_by', 'cost_bucket', 'role_tag', 'adspend_id',
  'payout_id', 'stripe_gross', 'stripe_fee', 'note', 'updated_at',
];

export function toBankRow(item, accountUid) {
  const minor = item && item.amount ? Number(item.amount.minorUnits) || 0 : 0;
  return {
    id: String(item.feedItemUid),
    account: accountUid || '',
    date: String(item.transactionTime || item.settlementTime || item.updatedAt || '').slice(0, 10),
    settled_at: String(item.settlementTime || '').slice(0, 10),
    direction: String(item.direction || '').toUpperCase() === 'IN' ? 'IN' : 'OUT',
    amount: String(round2(Math.abs(minor) / 100)),
    counterparty: String(item.counterPartyName || '').trim(),
    reference: String(item.reference || '').trim(),
    category: String(item.spendingCategory || ''),
    source: String(item.source || ''),
    status: String(item.status || '').toUpperCase(),
    updated_at: String(item.updatedAt || ''),
  };
}

// only settled money counts in totals. Declined, reversed and upcoming items are kept but ignored.
export const counts = r => r && r.status === 'SETTLED';

export function isStripePayoutRow(r) {
  return r.direction === 'IN' && /stripe/i.test(r.counterparty + ' ' + r.reference);
}
export function isInternalTransfer(r) {
  return /INTERNAL_TRANSFER|SAVINGS_GOAL|SPACE|STARLING_PAY_STRIPE_OUT_/i.test(r.source || '') || /^(TRANSFER|SAVING)/i.test(r.category || '');
}

/* ====================================================================
   Cost rules (editable table "Bank Rules"; these are the starting rules)
   ==================================================================== */
export const DEFAULT_BANK_RULES = [
  { id: 'r01', pattern: 'INDEED', bucket: 'Advertising', channel: 'Indeed' },
  { id: 'r02', pattern: 'LINKEDIN', bucket: 'Advertising', channel: 'LinkedIn' },
  { id: 'r03', pattern: 'GOOGLE ?ADS|GOOGLE\\*ADS', bucket: 'Advertising', channel: 'Google Ads' },
  { id: 'r04', pattern: 'FACEBK|FACEBOOK|META PLATFORMS', bucket: 'Advertising', channel: 'Meta' },
  { id: 'r05', pattern: 'REED|TOTALJOBS|CV-?LIBRARY|JOBSITE|CWJOBS', bucket: 'Advertising', channel: 'Job board' },
  { id: 'r06', pattern: 'HMRC|H M REVENUE|HM REVENUE', bucket: 'Tax (HMRC)' },
  { id: 'r07', pattern: 'PEOPLES PENSION|PEOPLE\'S PENSION|NEST |SCOTTISH WIDOWS|NOW:? ?PENSIONS|AVIVA', bucket: 'Pension' },
  { id: 'r08', pattern: 'SALARY|PAYROLL|WAGES', bucket: 'Payroll', applies: 'reference' },
  { id: 'r09', pattern: 'STRIPE', bucket: 'Payment fees' },
  { id: 'r10', pattern: 'MICROSOFT|MSFT|GOOGLE|ZOOM|CANVA|ADOBE|OPENAI|ANTHROPIC|RENDER|GITHUB|BREVO|GODADDY|WISPR|ELEVENLABS|NOTION|TYPEFULLY|VIDIQ|OPUS', bucket: 'Software' },
  { id: 'r11', pattern: 'STARLING|BANK FEE|ACCOUNT FEE|MONTHLY FEE', bucket: 'Bank charges' },
  { id: 'r12', pattern: 'DIVIDEND|DRAWING|DIRECTOR', bucket: 'Director payments' },
];
function ruleHits(rule, row) {
  const hay = rule.applies === 'reference' ? row.reference : rule.applies === 'counterparty' ? row.counterparty : row.counterparty + ' ' + row.reference;
  try { return new RegExp(rule.pattern, 'i').test(hay); } catch (e) { return hay.toUpperCase().includes(String(rule.pattern).toUpperCase()); }
}
export function categoriseCost(row, rules) {
  for (const rule of (rules && rules.length ? rules : DEFAULT_BANK_RULES)) if (rule.pattern && ruleHits(rule, row)) return { bucket: rule.bucket || 'Other', channel: rule.channel || '' };
  return { bucket: 'Other', channel: '' };
}

/* The kind of every row: client payment, Stripe payout, other money in, internal transfer or cost. */
export function classifyRow(row, rules) {
  if (isInternalTransfer(row)) return { kind: 'transfer', cost_bucket: '' };
  if (row.direction === 'IN') return { kind: isStripePayoutRow(row) ? 'stripe_payout' : 'client_payment', cost_bucket: '' };
  const c = categoriseCost(row, rules);
  return { kind: 'cost', cost_bucket: c.bucket, channel: c.channel };
}

/* ====================================================================
   Matching incoming payments to invoices
   ==================================================================== */
const NAME_NOISE = new Set(['LTD', 'LIMITED', 'PLC', 'LLP', 'THE', 'AND', 'UK', 'GROUP', 'CO', 'COMPANY', 'T/A', 'TA', 'INC', 'SERVICES', 'HOLDINGS']);
export function nameTokens(s) {
  return String(s || '').toUpperCase().replace(/&/g, ' AND ').replace(/[^A-Z0-9 ]+/g, ' ').split(/\s+/).filter(t => t && !NAME_NOISE.has(t));
}
export function nameMatches(payer, company) {
  const a = nameTokens(payer), b = nameTokens(company);
  if (!a.length || !b.length) return false;
  const sa = a.join(' '), sb = b.join(' ');
  if (sa === sb) return true;
  if (sa.length >= 4 && sb.length >= 4 && (sa.includes(sb) || sb.includes(sa))) return true;
  const shared = a.filter(t => b.includes(t));
  return shared.length >= 2 || (shared.length === 1 && (a.length === 1 || b.length === 1) && shared[0].length >= 4);
}
export function referenceHasInvoice(reference, number) {
  const ref = String(reference || '').toUpperCase().replace(/[\s\-_/.]+/g, '');
  const n = String(number || '').toUpperCase().replace(/[\s\-_/.]+/g, '');
  if (!n || n.length < 5) return false;
  const i = ref.indexOf(n);
  if (i === -1) return false;
  const before = ref[i - 1], after = ref[i + n.length];
  return !(before && /[A-Z0-9]/.test(before) && /[A-Z0-9]/.test(n[0])) && !(after && /[0-9]/.test(after));
}
const same = (a, b) => Math.abs(round2(a) - round2(b)) <= 0.01;
const isOpen = i => !['paid', 'refunded', 'void', 'cancelled'].includes(lc(i.status));
const owed = i => num(i.amountDue) || num(i.amount);

/* txns: bank rows that still need a decision. invoices: every invoice (open and paid).
   Returns auto matches (safe to apply) and confirm items (one click for Daniel Brown). Nothing is ever applied here. */
export function matchPayments(txns, invoices) {
  const open = invoices.filter(isOpen);
  const auto = [], confirm = [];
  const claimed = new Map(); // invoice number -> tx ids that want it automatically
  for (const tx of txns) {
    if (tx.direction !== 'IN' || tx.kind !== 'client_payment' || !counts(tx)) continue;
    if (['matched', 'confirmed', 'ignored'].includes(tx.match_status)) continue;
    const amt = num(tx.amount);
    const refHits = open.filter(i => referenceHasInvoice(tx.reference, i.number));
    const paidRefHits = invoices.filter(i => !isOpen(i) && referenceHasInvoice(tx.reference, i.number));
    if (refHits.length === 1) {
      const inv = refHits[0];
      if (same(amt, owed(inv))) auto.push({ tx, invoice: inv, how: 'invoice number and amount' });
      else confirm.push({ tx, candidates: [inv], reason: amt < owed(inv) ? `Part payment: £${amt.toFixed(2)} against £${owed(inv).toFixed(2)}` : `Overpayment: £${amt.toFixed(2)} against £${owed(inv).toFixed(2)}` });
      continue;
    }
    if (refHits.length > 1) {
      confirm.push({ tx, candidates: refHits, reason: same(amt, refHits.reduce((s, i) => s + owed(i), 0)) ? 'One payment for several invoices' : 'Reference names several invoices' });
      continue;
    }
    if (paidRefHits.length) { confirm.push({ tx, candidates: paidRefHits, reason: 'Reference names an invoice already marked paid: duplicate or overpayment?' }); continue; }
    const byName = open.filter(i => nameMatches(tx.counterparty, i.company));
    const byAmount = byName.filter(i => same(amt, owed(i)));
    if (byAmount.length === 1) { auto.push({ tx, invoice: byAmount[0], how: 'payer name and amount' }); continue; }
    if (byAmount.length > 1) { confirm.push({ tx, candidates: byAmount, reason: 'Two invoices for this client have the same amount' }); continue; }
    if (byName.length) {
      const all = byName.reduce((s, i) => s + owed(i), 0);
      confirm.push({ tx, candidates: byName, reason: same(amt, all) ? 'Amount equals all open invoices for this client' : `Payer matches a client but £${amt.toFixed(2)} matches no invoice` });
      continue;
    }
    const anyAmount = amt >= 100 ? open.filter(i => same(amt, owed(i))) : [];
    if (anyAmount.length) confirm.push({ tx, candidates: anyAmount, reason: 'Amount matches an invoice but the payer name does not' });
  }
  // two payments wanting the same invoice is not exact and unique: both go to the confirm list
  auto.forEach(a => { const k = a.invoice.number; claimed.set(k, (claimed.get(k) || []).concat(a.tx.id)); });
  const clash = new Set([...claimed].filter(([, ids]) => ids.length > 1).map(([k]) => k));
  const safe = [];
  auto.forEach(a => { if (clash.has(a.invoice.number)) confirm.push({ tx: a.tx, candidates: [a.invoice], reason: 'Two payments match this invoice' }); else safe.push(a); });
  return { auto: safe, confirm };
}

/* ====================================================================
   Stripe payouts: each payout in the bank against the payments inside it, less fees
   ==================================================================== */
export function findPayoutFor(tx, payouts) {
  const amt = num(tx.amount), txMs = dayMs(tx.date);
  const cands = (payouts || []).filter(p => lc(p.currency || 'gbp') === 'gbp' && same(p.amount / 100, amt) && txMs != null && Math.abs((p.arrival_date * 1000) - txMs) <= 4 * DAY);
  cands.sort((a, b) => Math.abs(a.arrival_date * 1000 - txMs) - Math.abs(b.arrival_date * 1000 - txMs));
  return cands[0] || null;
}
export function reconcilePayout(payout, balanceTxns) {
  const items = (balanceTxns || []).filter(t => t.type !== 'payout' && t.type !== 'payout_cancel');
  const gross = items.reduce((s, t) => s + (Number(t.amount) || 0), 0) / 100;
  const fees = items.reduce((s, t) => s + (Number(t.fee) || 0), 0) / 100;
  const net = items.reduce((s, t) => s + (Number(t.net) || 0), 0) / 100;
  const payoutAmt = (Number(payout.amount) || 0) / 100;
  const refunds = items.filter(t => /refund|dispute/.test(t.type)).reduce((s, t) => s + (Number(t.amount) || 0), 0) / 100;
  return { payoutId: payout.id, count: items.length, gross: round2(gross), fees: round2(fees), net: round2(net), payout: round2(payoutAmt), refunds: round2(refunds), diff: round2(payoutAmt - net), ok: items.length > 0 && Math.abs(payoutAmt - net) <= 0.01 };
}

/* ====================================================================
   Late payer scoring (invoice date to bank date)
   ==================================================================== */
export function latePayerScores(invoices, now) {
  const by = new Map();
  invoices.forEach(i => {
    if (lc(i.status) !== 'paid') return;
    const d = dayMs(i.date), p = dayMs(i.paymentDate), due = dayMs(i.dueDate) != null ? dayMs(i.dueDate) : (d != null ? d + 14 * DAY : null);
    if (d == null || p == null) return;
    const k = lc(i.company);
    const g = by.get(k) || { company: i.company, n: 0, days: 0, late: 0, onTime: 0 };
    g.n++; g.days += Math.max(0, (p - d) / DAY); g.late += due != null ? (p - due) / DAY : 0; if (due == null || p <= due + DAY) g.onTime++;
    by.set(k, g);
  });
  const out = {};
  by.forEach((g, k) => {
    const avgLate = g.late / g.n;
    out[k] = { company: g.company, invoices: g.n, avgDaysToPay: Math.round(g.days / g.n * 10) / 10, avgDaysLate: Math.round(avgLate * 10) / 10, onTimePct: Math.round(g.onTime / g.n * 100),
      label: avgLate <= 2 ? 'Prompt' : avgLate <= 14 ? 'Slightly slow' : avgLate <= 30 ? 'Slow' : 'Very slow' };
  });
  return out;
}

/* ====================================================================
   Costs: recurring detection, monthly flows, top payers and payees
   ==================================================================== */
export function normCounterparty(s) { return nameTokens(s).slice(0, 3).join(' ') || String(s || '').toUpperCase().trim(); }
export function detectRecurring(rows, todayISO) {
  const by = new Map();
  rows.filter(r => counts(r) && r.kind === 'cost').forEach(r => { const k = normCounterparty(r.counterparty); const a = by.get(k) || { name: r.counterparty, bucket: r.cost_bucket, items: [] }; a.items.push(r); by.set(k, a); });
  const out = [];
  by.forEach(g => {
    if (['Tax (HMRC)', 'Director payments'].includes(g.bucket)) return;
    const items = g.items.slice().sort((a, b) => a.date.localeCompare(b.date));
    if (items.length < 2) return;
    const gaps = []; for (let i = 1; i < items.length; i++) gaps.push((dayMs(items[i].date) - dayMs(items[i - 1].date)) / DAY);
    const monthly = gaps.filter(x => x >= 25 && x <= 36).length >= Math.max(1, Math.ceil(gaps.length * 0.6));
    const amts = items.map(i => num(i.amount)), avg = amts.reduce((s, x) => s + x, 0) / amts.length;
    if (!monthly || amts.some(x => Math.abs(x - avg) > Math.max(2, avg * 0.1))) return;
    const last = items[items.length - 1];
    let next = addDaysISO(last.date, 30);
    while (todayISO && next < todayISO) next = addDaysISO(next, 30);
    out.push({ name: g.name, bucket: g.bucket, amount: round2(num(last.amount)), lastDate: last.date, nextDate: next, count: items.length });
  });
  return out.sort((a, b) => b.amount - a.amount);
}
export function monthlyFlows(rows, months, todayISO) {
  const keys = []; const t = new Date(todayISO + 'T00:00:00Z');
  for (let i = months - 1; i >= 0; i--) keys.push(isoDay(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() - i, 1)).slice(0, 7));
  const m = new Map(keys.map(k => [k, { month: k, in: 0, out: 0 }]));
  rows.filter(r => counts(r) && r.kind !== 'transfer').forEach(r => { const x = m.get(monthKey(r.date)); if (x) x[r.direction === 'IN' ? 'in' : 'out'] += num(r.amount); });
  return keys.map(k => { const x = m.get(k); return { month: k, in: round2(x.in), out: round2(x.out) }; });
}
export function topCounterparties(rows, direction, fromISO, limit = 5) {
  const by = new Map();
  rows.filter(r => counts(r) && r.kind !== 'transfer' && r.direction === direction && r.date >= fromISO).forEach(r => { const k = normCounterparty(r.counterparty); const g = by.get(k) || { name: r.counterparty, total: 0, count: 0 }; g.total += num(r.amount); g.count++; by.set(k, g); });
  return [...by.values()].map(g => ({ ...g, total: round2(g.total) })).sort((a, b) => b.total - a.total).slice(0, limit);
}

/* ====================================================================
   Corporation tax reserve (an estimate: the accountant's figure is the truth)
   2026/27: 19% to 50,000, 25% over 250,000, marginal relief in between (25% less 3/200 of the gap to 250,000)
   ==================================================================== */
export function corporationTax(profit, flatRatePct) {
  const p = Math.max(0, Number(profit) || 0);
  if (flatRatePct != null && flatRatePct !== '' && Number.isFinite(Number(flatRatePct))) return round2(p * Number(flatRatePct) / 100);
  if (p <= 50000) return round2(p * 0.19);
  if (p >= 250000) return round2(p * 0.25);
  return round2(p * 0.25 - (250000 - p) * 3 / 200);
}

/* ====================================================================
   Cash forecast: balance, plus invoices when each client is likely to pay, minus payroll and recurring costs
   ==================================================================== */
export function invoiceWeight(avgDaysLate, daysOverdue) {
  if (daysOverdue > 60) return 0.4;
  if (avgDaysLate == null || avgDaysLate <= 7) return 0.95;
  if (avgDaysLate <= 21) return 0.85;
  if (avgDaysLate <= 45) return 0.7;
  return 0.5;
}
export function cashForecast({ balance, openInvoices, scores, recurring, monthlyPayroll, todayISO, days = 90, floor }) {
  const start = dayMs(todayISO), end = start + days * DAY;
  const events = []; // {ms, amount, label}
  const lateVals = Object.values(scores || {});
  const overallLate = lateVals.length ? lateVals.reduce((s, x) => s + x.avgDaysLate * x.invoices, 0) / lateVals.reduce((s, x) => s + x.invoices, 0) : 0;
  (openInvoices || []).forEach(i => {
    const sc = (scores || {})[lc(i.company)];
    const late = sc && sc.invoices >= 2 ? sc.avgDaysLate : (sc ? sc.avgDaysLate : overallLate);
    const due = dayMs(i.dueDate) != null ? dayMs(i.dueDate) : (dayMs(i.date) || start) + 14 * DAY;
    const daysOverdue = Math.max(0, (start - due) / DAY);
    let when = due + Math.max(0, late) * DAY;
    if (when <= start) when = start + DAY * (late > 0 ? 3 : 2); // already due: expect it within a few days
    const w = invoiceWeight(sc ? sc.avgDaysLate : null, daysOverdue);
    if (when <= end) events.push({ ms: when, amount: round2(owed(i) * w), label: `${i.company} ${i.number}` });
  });
  // payroll on the last day of each month (the 1st is the next day, so the month end is the cautious date)
  if (monthlyPayroll > 0) for (let m = 0; m < 5; m++) { const d = new Date(start); const ms = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + m + 1, 0); if (ms >= start && ms <= end) events.push({ ms, amount: -round2(monthlyPayroll), label: 'Payroll and pension' }); }
  (recurring || []).filter(r => !['Payroll', 'Pension', 'Tax (HMRC)'].includes(r.bucket)).forEach(r => {
    for (let ms = dayMs(r.nextDate); ms != null && ms <= end; ms += 30 * DAY) if (ms >= start) events.push({ ms, amount: -round2(r.amount), label: r.name });
  });
  events.sort((a, b) => a.ms - b.ms);
  const series = []; let bal = Number(balance) || 0, min = { date: todayISO, balance: round2(bal) }, ev = 0;
  for (let d = 0; d <= days; d++) {
    const ms = start + d * DAY;
    while (ev < events.length && events[ev].ms <= ms + DAY - 1) { if (events[ev].ms >= start) bal += events[ev].amount; ev++; }
    if (d % 7 === 0 || d === days) series.push({ date: isoDay(ms), balance: round2(bal) });
    if (bal < min.balance) min = { date: isoDay(ms), balance: round2(bal) };
  }
  const inflow = events.filter(e => e.amount > 0).reduce((s, e) => s + e.amount, 0), outflow = events.filter(e => e.amount < 0).reduce((s, e) => s - e.amount, 0);
  const f = floor == null || floor === '' ? null : num(floor);
  return { days, series, lowest: min, endBalance: round2(bal), expectedIn: round2(inflow), expectedOut: round2(outflow), floor: f, belowFloor: f != null && min.balance < f, events: events.slice(0, 40).map(e => ({ date: isoDay(e.ms), amount: e.amount, label: e.label })) };
}

/* ====================================================================
   The bank figures the owner view and the reports show.
   input.bank = { connected, mode, balance:{amount, at}, rows:[...], settings:{cash_floor, tax_rate_pct}, status:{lastPoll, lastError, paused} }
   ctx = { todayISO, invoices, monthlyPayroll, profitYtd, monthlyOverheads, ytdStartISO }
   ==================================================================== */
export function bankKpi(bank, ctx) {
  const none = { connected: false, note: bank && bank.status && bank.status.paused ? 'Bank feed is paused (BANK_FEED_ON)' : 'Bank not connected yet: add STARLING_TOKEN in Render' };
  if (!bank || !bank.connected) return { tiles: none, panel: { ...none, status: (bank && bank.status) || {} } };
  const rows = (bank.rows || []).filter(counts), today = ctx.todayISO, monthStart = today.slice(0, 7) + '-01';
  const lastMonthStart = isoDay(Date.UTC(Number(today.slice(0, 4)), Number(today.slice(5, 7)) - 2, 1));
  const real = rows.filter(r => r.kind !== 'transfer');
  const sumRows = (arr, dir, from, to) => round2(arr.filter(r => r.direction === dir && r.date >= from && (!to || r.date < to)).reduce((s, r) => s + num(r.amount), 0));
  const inMonth = sumRows(real, 'IN', monthStart), outMonth = sumRows(real, 'OUT', monthStart);
  const inLast = sumRows(real, 'IN', lastMonthStart, monthStart), outLast = sumRows(real, 'OUT', lastMonthStart, monthStart);
  const balance = bank.balance ? num(bank.balance.amount) : 0;
  const scores = latePayerScores(ctx.invoices || [], today);
  const recurring = detectRecurring(rows, today);
  const ytdStart = ctx.ytdStartISO || today.slice(0, 4) + '-01-01';
  const overheadsYtd = real.filter(r => r.direction === 'OUT' && r.date >= ytdStart && !['Advertising', 'Payroll', 'Pension', 'Tax (HMRC)', 'Director payments'].includes(r.cost_bucket)).reduce((s, r) => s + num(r.amount), 0)
    + rows.filter(r => r.kind === 'stripe_payout' && r.date >= ytdStart).reduce((s, r) => s + num(r.stripe_fee), 0);
  const monthsElapsed = Number(today.slice(5, 7)) - 1 + Number(today.slice(8, 10)) / 31;
  const overheadsUsed = rows.length ? overheadsYtd : num(ctx.monthlyOverheads) * monthsElapsed;
  const taxableProfit = Math.max(0, num(ctx.profitYtd) - overheadsUsed);
  const taxReserve = corporationTax(taxableProfit, bank.settings && bank.settings.tax_rate_pct);
  const open = (ctx.invoices || []).filter(isOpen);
  const forecast = cashForecast({ balance, openInvoices: open, scores, recurring, monthlyPayroll: ctx.monthlyPayroll, todayISO: today, floor: bank.settings && bank.settings.cash_floor });
  const confirmCount = rows.filter(r => r.match_status === 'confirm').length;
  const costBuckets = {};
  real.filter(r => r.direction === 'OUT' && r.date >= ytdStart).forEach(r => { costBuckets[r.cost_bucket || 'Other'] = (costBuckets[r.cost_bucket || 'Other'] || 0) + num(r.amount); });
  const fees = rows.filter(r => r.kind === 'stripe_payout' && r.date >= ytdStart).reduce((s, r) => s + num(r.stripe_fee), 0);
  if (fees) costBuckets['Payment fees'] = (costBuckets['Payment fees'] || 0) + fees;
  const tiles = {
    connected: true, mode: bank.mode || 'live', balance: round2(balance), balanceAt: bank.balance ? bank.balance.at : '',
    taxReserve, spendable: round2(balance - taxReserve), inMonth, outMonth, inLast, outLast,
    forecastLowest: forecast.lowest, belowFloor: forecast.belowFloor, floor: forecast.floor, confirmCount,
    note: bank.mode === 'demo' ? 'DEMO data: not your real account' : '',
  };
  return {
    tiles,
    panel: {
      ...tiles, status: bank.status || {},
      flows: monthlyFlows(real, 12, today), topPayers: topCounterparties(real, 'IN', addDaysISO(today, -365)), topPayees: topCounterparties(real, 'OUT', addDaysISO(today, -365)),
      recurring, forecast, scores: Object.values(scores).sort((a, b) => b.avgDaysLate - a.avgDaysLate),
      tax: { profitYtd: round2(num(ctx.profitYtd)), overheadsYtd: round2(overheadsUsed), taxableProfit: round2(taxableProfit), reserve: taxReserve, flatRatePct: bank.settings && bank.settings.tax_rate_pct ? Number(bank.settings.tax_rate_pct) : null,
        note: 'Steering estimate of corporation tax on profit to date. Profit is invoiced revenue less salary, pension, commission and advertising, then less other costs from the bank. Your accountant\'s figure is the one that counts.' },
      costBuckets: Object.entries(costBuckets).map(([bucket, amount]) => ({ bucket, amount: round2(amount) })).sort((a, b) => b.amount - a.amount),
    },
  };
}
