/* ======================================================================
   Build 62: KPI owner view - the sums behind KPI Reporting.

   Pure functions only. Nothing in this file reads or writes a database, a sheet or the network,
   so the same figures can be used by the screen (GET /api/kpi/owner), by the monthly reports in
   build 65 and by the tests in scripts/test-kpi-owner.mjs.

   Money figures here are steering estimates. The accountant's numbers are the source of truth.
   ====================================================================== */

import { bankKpi } from './bank.js';

export const KPI_SETTING_DEFAULTS = {
  vat_threshold: '90000',          // HMRC registration threshold, checked 16 Nov 2026. Held as a setting, never hardcode elsewhere.
  vat_alert_pcts: '80,90',
  concentration_warn_pct: '40',
  role_stale_days: '7',
};
export const KPI_SETTING_KEYS = Object.keys(KPI_SETTING_DEFAULTS);

export const FORECAST_STAGES = ['submitted', 'interview_requested', 'interview_scheduled', 'interviewed', 'offer'];
export const FORECAST_DEFAULTS = { submitted: 10, interview_requested: 20, interview_scheduled: 30, interviewed: 40, offer: 75 };
const FILLED_STAGES = ['offer', 'start_date', 'day1', 'week1', 'month1'];
const PLACED_STAGES = ['start_date', 'day1', 'week1', 'month1'];
const INTERVIEW_STAGES = ['interview_requested', 'interview_scheduled', 'interviewed'];
const UNASSIGNED_LABEL = 'Unassigned - New Applications';
const DAY = 86400000;

/* ---------- small helpers ---------- */
const lc = s => String(s || '').trim().toLowerCase();
const num = v => { const n = parseFloat(v); return Number.isFinite(n) ? n : 0; };
const round2 = n => Math.round((n || 0) * 100) / 100;
const round1 = n => Math.round((n || 0) * 10) / 10;
const sum = (list, fn) => list.reduce((s, x) => s + (fn ? fn(x) : x), 0);
const normStage = s => String(s || '').trim().toLowerCase().replace(/\s+/g, '_') || 'applied';
const isTest = (name, notes) => /^\s*test\b/i.test(String(name || '')) || /\[test\]/i.test(String(notes || ''));

export function parseDate(s) {
  if (s instanceof Date) return isNaN(s.getTime()) ? null : s;
  const m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  const m2 = String(s || '').match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m2) return new Date(Date.UTC(+m2[3], +m2[2] - 1, +m2[1]));
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}
const iso = d => d.toISOString().slice(0, 10);
const dayOf = d => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
const monthStart = (d, offset = 0) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + offset, 1));
const quarterStart = (d, offset = 0) => new Date(Date.UTC(d.getUTCFullYear(), Math.floor(d.getUTCMonth() / 3) * 3 + offset * 3, 1));
const yearStart = (d, offset = 0) => new Date(Date.UTC(d.getUTCFullYear() + offset, 0, 1));
const within = (d, from, to) => !!d && d >= from && d < to;
export const monthKey = d => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
const monthName = d => d.toLocaleDateString('en-GB', { month: 'long', year: 'numeric', timeZone: 'UTC' });
const gbp = n => '£' + Math.round(n || 0).toLocaleString('en-GB');

// A figure with last month beside it. "better" says which direction is good news, so the screen can colour the arrow.
function trend(now, before, better = 'up') {
  const diff = round2((now || 0) - (before || 0));
  const pct = before ? Math.round((diff / Math.abs(before)) * 100) : null;
  return { now: round2(now), before: before == null ? null : round2(before), diff, pct, dir: before == null ? 'none' : diff > 0 ? 'up' : diff < 0 ? 'down' : 'same', better };
}

/* ---------- salary reading (same rules as the Forecast tab) ---------- */
const PAY_WEEKS = 52;
const looksHourly = text => /per\s*hour|an\s*hour|\/\s*h(?:ou)?r\b|\bp\/?h\b|hourly/i.test(String(text || ''));
function detectWeeklyHours(text) {
  const t = String(text || '');
  const m = t.match(/(\d{1,2}(?:\.\d{1,2})?)\s*(?:hours?|hrs?)\s*(?:per|a|each|\/)\s*week/i)
    || t.match(/(?:hours?|hrs?)\s*(?:per|a|each|\/)\s*week\s*[:\-]?\s*(\d{1,2}(?:\.\d{1,2})?)/i)
    || t.match(/(?:contracted|basic|working)\s+hours[^\d]{0,20}(\d{1,2}(?:\.\d{1,2})?)/i);
  const h = m ? parseFloat(m[1]) : 0;
  return h >= 8 && h <= 60 ? h : 0;
}
const hourlyAnnual = (rate, hours) => (rate > 0 && hours > 0 ? Math.round(rate * hours * PAY_WEEKS) : 0);
function hourlyValue(text, ctx) {
  const nums = [];
  text.replace(/(\d[\d,]*\.?\d*)/g, (m, n) => { const v = parseFloat(String(n).replace(/,/g, '')); if (Number.isFinite(v)) nums.push(v); return m; });
  if (!nums.length || Math.min(...nums.slice(0, 2)) >= 200) return null; // looks like an annual figure, not a rate
  const lo = Math.min(nums[0], nums.length > 1 ? nums[1] : nums[0]), hi = Math.max(nums[0], nums.length > 1 ? nums[1] : nums[0]);
  const hours = (ctx && ctx.hours) || detectWeeklyHours(text);
  return hourlyAnnual((lo + hi) / 2, hours);
}
export function salaryValue(raw, ctx) {
  const text = String(raw == null ? '' : raw).trim();
  if (!text) return 0;
  if (looksHourly(text) || (ctx && ctx.hourly)) {
    const h = hourlyValue(text, ctx);
    if (h !== null) return h;
  }
  const found = [];
  text.replace(/(\d[\d,]*\.?\d*)\s*(k)?/gi, (m, n, k, offset) => {
    const v = parseFloat(String(n).replace(/,/g, ''));
    if (Number.isFinite(v)) found.push({ v, k: !!k, at: offset, end: offset + m.length });
    return m;
  });
  if (!found.length) return 0;
  const anyK = found.some(f => f.k);
  const nums = found.map(f => ((f.k || (anyK && f.v < 1000)) ? f.v * 1000 : f.v));
  let low = nums[0], high = nums[0], isRange = false;
  if (nums.length >= 2) {
    const between = text.slice(found[0].end, found[1].at);
    if (/[-–—\/]|\bto\b|\bor\b|\bup to\b/i.test(between)) { low = Math.min(nums[0], nums[1]); high = Math.max(nums[0], nums[1]); isRange = low !== high; }
  }
  const value = isRange ? Math.round((low + high) / 2) : low;
  return value > 300000 || value < 1000 ? 0 : value;
}
function bandMidpoint(band) {
  const nums = (String(band || '').match(/\d[\d,]*(?:\.\d+)?\s*k?/gi) || []).map(x => {
    const k = /k\s*$/i.test(x);
    const n = parseFloat(x.replace(/[^0-9.]/g, ''));
    return k ? n * 1000 : n;
  }).filter(n => n > 0);
  if (!nums.length) return 0;
  return nums.length === 1 ? nums[0] : (nums[0] + nums[1]) / 2;
}
const roleCtx = r => ({ hourly: !!r && r.pay_basis === 'hourly', hours: num(r && r.hours_per_week) });
function roleAnnualMid(r) {
  const mid = bandMidpoint(r && r.salary_band);
  return r && r.pay_basis === 'hourly' ? hourlyAnnual(mid, num(r.hours_per_week)) : mid;
}
export function feeRateFor(salary) {
  if (salary <= 22000) return 12;
  if (salary <= 30000) return 15;
  if (salary <= 40000) return 20;
  return 25;
}

/* ---------- team cost (same sums as the old Business Health block) ---------- */
function weekdaysBetween(from, to) {
  if (to < from) return 0;
  const total = Math.round((to - from) / DAY) + 1;
  const fullWeeks = Math.floor(total / 7);
  let n = fullWeeks * 5;
  const d = new Date(from.getTime() + fullWeeks * 7 * DAY);
  for (let i = 0; i < total - fullWeeks * 7; i++) {
    const dow = new Date(d.getTime() + i * DAY).getUTCDay();
    if (dow !== 0 && dow !== 6) n++;
  }
  return n;
}
// Salary accrues per working day, Monday to Friday, between two dates (both included)
export function empCostBetween(emp, from, to) {
  const st = parseDate(emp.startDate);
  const en = emp.endDate ? parseDate(emp.endDate) : null;
  if (!st) return { salary: 0, pension: 0, total: 0, days: 0 };
  const a = st > from ? st : from;
  const b = en && en < to ? en : to;
  const days = weekdaysBetween(a, b);
  const annual = num(emp.salary);
  const sal = Math.min(annual, (annual / 260) * days);
  const pen = sal * (num(emp.pensionPct) / 100);
  return { salary: round2(sal), pension: round2(pen), total: round2(sal + pen), days };
}
function empMatches(emp, key) {
  const full = lc(emp.name), first = full.split(/\s+/)[0], kk = lc(key);
  if (!kk || kk === 'unassigned') return false;
  return kk === full || kk === first || full.startsWith(kk + ' ');
}
const sumFor = (emp, byName) => sum(Object.keys(byName || {}).filter(k => empMatches(emp, k)), k => byName[k]);

/* ---------- spend ---------- */
function addMonthsISO(isoDate, n) {
  const [y, m, d] = isoDate.split('-').map(Number);
  const last = new Date(Date.UTC(y, m - 1 + n + 1, 0)).getUTCDate();
  return iso(new Date(Date.UTC(y, m - 1 + n, Math.min(d, last))));
}
const dateOnly = v => { const d = parseDate(v); return d ? iso(d) : ''; };
export function spendOccurrences(entries, fromISO, toISO) {
  const out = [];
  (entries || []).forEach(e => {
    const amt = num(e.amount), start = dateOnly(e.date);
    if (!start || !amt) return;
    if (e.frequency !== 'monthly') { out.push({ e, date: start, amount: amt }); return; }
    const end = dateOnly(e.end_date) || toISO;
    for (let i = 0; i < 240; i++) {
      const d = addMonthsISO(start, i);
      if (d > end || d > toISO) break;
      out.push({ e, date: d, amount: amt });
    }
  });
  return out.filter(o => (!fromISO || o.date >= fromISO) && o.date <= toISO);
}

/* ---------- shared preparation ---------- */
function prepare(input) {
  const now = input.now ? new Date(input.now) : new Date();
  const today = dayOf(now);
  const invoices = (input.invoices || []).filter(i => i && i.number).map(i => ({
    ...i, amount: num(i.amount), commissionAmount: num(i.commissionAmount),
    d: parseDate(i.date), paid: lc(i.status) === 'paid',
  }));
  invoices.forEach(i => {
    i.pd = i.paid ? (parseDate(i.paymentDate) || i.d) : null;
    i.due = parseDate(i.dueDate) || (i.d ? new Date(i.d.getTime() + 14 * DAY) : null);
  });
  const cands = (input.candidates || []).filter(c => c && c.id && !isTest(c.name, c.notes))
    .map(c => ({ ...c, stage: normStage(c.stage), added: parseDate(c.date) }));
  // every stage each candidate has ever been moved to, from the audit trail ("x to y" on "Name - Role")
  const reached = new Map(), offerAt = new Map(), lastMove = new Map();
  (input.audit || []).filter(a => a.action === 'stage_changed').forEach(a => {
    const k = lc(a.entity), t = parseDate(a.timestamp);
    const m = String(a.detail || '').match(/^(.*?)\s+to\s+(.*)$/i);
    if (!m) return;
    if (!reached.has(k)) reached.set(k, new Set());
    reached.get(k).add(normStage(m[1])); reached.get(k).add(normStage(m[2]));
    if (t && normStage(m[2]) === 'offer' && (!offerAt.has(k) || t < offerAt.get(k))) offerAt.set(k, t);
    if (t && (!lastMove.has(k) || t > lastMove.get(k))) lastMove.set(k, t);
  });
  const storedRoles = (input.roles || []).filter(r => r && r.company && r.role);
  cands.forEach(c => {
    const k = lc(`${c.name} - ${c.role}`);
    c.reached = new Set([c.stage, ...(reached.get(k) || [])]);
    c.offerDate = offerAt.get(k) || c.added;
    c.lastMove = lastMove.get(k) || c.added;
    const role = storedRoles.find(r => lc(r.company) === lc(c.company) && lc(r.role) === lc(c.role));
    c.roleOpened = role ? parseDate(role.date_opened) : null;
  });
  // roles on the Roles tab plus any company and role that only exists on the pipeline (as the Roles tab shows them)
  const roles = storedRoles.map(r => ({ ...r }));
  cands.forEach(c => {
    if (!c.company || c.company === UNASSIGNED_LABEL) return;
    if (roles.some(r => lc(r.company) === lc(c.company) && lc(r.role) === lc(c.role))) return;
    const dates = cands.filter(x => lc(x.company) === lc(c.company) && lc(x.role) === lc(c.role)).map(x => x.added).filter(Boolean).sort((a, b) => a - b);
    roles.push({ id: '', company: c.company, role: c.role, status: 'open', date_opened: dates[0] ? iso(dates[0]) : '', positions: '1', salary_band: '', fee_percent: '', derived: true });
  });
  roles.forEach(r => { r.cands = cands.filter(c => lc(c.company) === lc(r.company) && lc(c.role) === lc(r.role)); });
  const settings = { ...KPI_SETTING_DEFAULTS, ...(input.settings || {}) };
  return { now, today, invoices, cands, roles, settings };
}

function forecast(p, weights) {
  const w = { ...FORECAST_DEFAULTS, ...(weights || {}) };
  let weighted = 0, best = 0, openPositions = 0, noSalary = 0;
  p.roles.filter(r => lc(r.status) === 'open' && r.company !== UNASSIGNED_LABEL).forEach(r => {
    const positions = Math.max(1, parseInt(r.positions, 10) || 1);
    const placed = r.cands.filter(c => PLACED_STAGES.includes(c.stage)).length;
    const openPos = Math.max(0, positions - placed);
    openPositions += openPos;
    const inPlay = [];
    r.cands.filter(c => FORECAST_STAGES.includes(c.stage)).forEach(c => {
      let salary = salaryValue(c.salary, roleCtx(r));
      if (!salary) salary = roleAnnualMid(r);
      if (!salary) { noSalary++; return; }
      const rate = num(r.fee_percent) > 0 ? num(r.fee_percent) : feeRateFor(salary);
      inPlay.push({ fee: salary * rate / 100, weight: w[c.stage] || 0 });
    });
    inPlay.sort((a, b) => (b.weight - a.weight) || (b.fee - a.fee)).slice(0, openPos).forEach(c => { best += c.fee; weighted += c.fee * c.weight / 100; });
  });
  return { weighted: round2(weighted), bestCase: round2(best), openPositions, candidatesWithNoSalary: noSalary };
}

/* ---------- the owner view ---------- */
export function computeOwnerKpi(input) {
  const p = prepare(input);
  const { now, today, invoices, cands, roles, settings } = p;
  const tomorrow = new Date(today.getTime() + DAY);
  const mS = monthStart(today), lmS = monthStart(today, -1), qS = quarterStart(today), lqS = quarterStart(today, -1);
  const yS = yearStart(today), lyS = yearStart(today, -1);
  const sameDayLastYear = new Date(Date.UTC(today.getUTCFullYear() - 1, today.getUTCMonth(), today.getUTCDate() + 1));
  const d365 = new Date(tomorrow.getTime() - 365 * DAY);
  const invoiced = (a, b) => sum(invoices.filter(i => within(i.d, a, b)), i => i.amount);
  const paidIn = (a, b) => sum(invoices.filter(i => i.paid && within(i.pd, a, b)), i => i.amount);

  /* ----- Money ----- */
  const unpaid = invoices.filter(i => !i.paid);
  const outstanding = sum(unpaid, i => i.amount);
  const overdueList = unpaid.filter(i => i.due && i.due < today);
  const overdue = sum(overdueList, i => i.amount);
  const last12 = invoiced(d365, tomorrow);
  const payDays = invoices.filter(i => i.paid && i.d && i.pd && within(i.pd, d365, tomorrow)).map(i => Math.max(0, Math.round((i.pd - i.d) / DAY)));
  const ytdInv = invoices.filter(i => within(i.d, yS, tomorrow));
  const ytdRevenue = sum(ytdInv, i => i.amount);
  const byClientMap = new Map();
  ytdInv.forEach(i => { const k = lc(i.company); const g = byClientMap.get(k) || { company: i.company, revenue: 0, invoices: 0 }; g.revenue += i.amount; g.invoices++; byClientMap.set(k, g); });
  const byClient = [...byClientMap.values()].map(g => ({ ...g, revenue: round2(g.revenue) })).sort((a, b) => b.revenue - a.revenue);
  const fc = forecast(p, input.forecastWeights);
  const placedNoInvoice = cands.filter(c => PLACED_STAGES.includes(c.stage) && !c.invoiceNumber);
  const awaitingInvoice = sum(placedNoInvoice, c => {
    const r = roles.find(x => lc(x.company) === lc(c.company) && lc(x.role) === lc(c.role));
    const sal = salaryValue(c.salary, roleCtx(r));
    return sal ? sal * feeRateFor(sal) / 100 : 0;
  });
  const snaps = input.snapshots || {};
  const openSnap = snaps[monthKey(today)] || null, prevSnap = snaps[monthKey(lmS)] || null;
  const money = {
    invoiced: {
      month: trend(invoiced(mS, tomorrow), invoiced(lmS, mS)),
      quarter: trend(invoiced(qS, tomorrow), invoiced(lqS, qS)),
      ytd: trend(ytdRevenue, invoiced(lyS, sameDayLastYear)),
    },
    paid: {
      month: trend(paidIn(mS, tomorrow), paidIn(lmS, mS)),
      quarter: trend(paidIn(qS, tomorrow), paidIn(lqS, qS)),
      ytd: trend(paidIn(yS, tomorrow), paidIn(lyS, sameDayLastYear)),
    },
    outstanding: trend(outstanding, openSnap ? openSnap.outstanding : null, 'down'),
    overdue: trend(overdue, openSnap ? openSnap.overdue : null, 'down'),
    overdueInvoices: overdueList.map(i => ({ number: i.number, company: i.company, amount: i.amount, dueDate: iso(i.due), daysOverdue: Math.round((today - i.due) / DAY) })).sort((a, b) => b.daysOverdue - a.daysOverdue),
    debtorDays: last12 > 0 ? Math.round((outstanding / last12) * 365) : null,
    avgDaysToPay: payDays.length ? Math.round(sum(payDays) / payDays.length) : null,
    avgFee: ytdInv.length ? round2(ytdRevenue / ytdInv.length) : 0,
    invoiceCountYtd: ytdInv.length,
    revenuePerClient: byClient.length ? round2(ytdRevenue / byClient.length) : 0,
    byClient,
    forecast: {
      ...fc, awaitingInvoice: round2(awaitingInvoice),
      // forecast as it stood when the month opened, against what has actually been invoiced since
      openingWeighted: openSnap ? openSnap.weightedForecast : null,
      invoicedThisMonth: round2(invoiced(mS, tomorrow)),
      lastMonth: prevSnap ? { openingWeighted: prevSnap.weightedForecast, invoiced: round2(invoiced(lmS, mS)) } : null,
    },
    bank: { connected: false, note: 'Connect bank in build 63' },
  };

  /* ----- Pipeline ----- */
  const staleDays = Math.max(1, parseInt(settings.role_stale_days, 10) || 7);
  const openRoles = roles.filter(r => lc(r.status) === 'open' && r.company !== UNASSIGNED_LABEL);
  const touch = new Map(); // "company|role" -> last activity
  const bump = (company, role, t) => { if (!t) return; const k = lc(company) + '|' + lc(role); if (!touch.has(k) || t > touch.get(k)) touch.set(k, t); };
  cands.forEach(c => { bump(c.company, c.role, c.added); bump(c.company, c.role, c.lastMove); });
  (input.activity || []).forEach(a => bump(a.company, a.role, parseDate(a.timestamp)));
  (input.interviews || []).forEach(a => { const t = parseDate(a.date); if (t && t <= today) bump(a.company, a.role, t); });
  (input.comms || []).filter(c => c.role).forEach(c => bump(c.company, c.role, parseDate(c.timestamp)));
  const roleRows = openRoles.map(r => {
    const last = touch.get(lc(r.company) + '|' + lc(r.role)) || null;
    const opened = parseDate(r.date_opened);
    const since = last || opened;
    const idle = since ? Math.floor((today - dayOf(since)) / DAY) : null;
    return {
      company: r.company, role: r.role, positions: Math.max(1, parseInt(r.positions, 10) || 1),
      daysOpen: opened ? Math.max(0, Math.round((today - opened) / DAY)) : null,
      active: r.cands.filter(c => c.stage !== 'rejected' && c.stage !== 'applied').length,
      lastActivity: last ? iso(last) : '', idleDays: idle, atRisk: idle === null || idle >= staleDays,
    };
  });
  const byCo = new Map();
  roleRows.forEach(r => { const g = byCo.get(lc(r.company)) || { company: r.company, roles: 0, positions: 0 }; g.roles++; g.positions += r.positions; byCo.set(lc(r.company), g); });
  const fillSpeed = (a, b) => {
    const s = cands.filter(c => FILLED_STAGES.includes(c.stage) && within(c.offerDate, a, b) && c.roleOpened).map(c => Math.max(0, Math.round((c.offerDate - c.roleOpened) / DAY)));
    return s.length ? round1(sum(s) / s.length) : null;
  };
  const filled = (a, b) => cands.filter(c => FILLED_STAGES.includes(c.stage) && within(c.offerDate, a, b)).length;
  // conversion over the last 12 months of candidates, from every stage each one has reached
  const hit = (c, list) => list.some(s => c.reached.has(s));
  const cohort = cands.filter(c => within(c.added, d365, tomorrow));
  const AFTER_SUB = ['submitted', ...INTERVIEW_STAGES, ...FILLED_STAGES], AFTER_INT = [...INTERVIEW_STAGES, ...FILLED_STAGES];
  const nSub = cohort.filter(c => hit(c, AFTER_SUB)).length, nInt = cohort.filter(c => hit(c, AFTER_INT)).length, nOff = cohort.filter(c => hit(c, FILLED_STAGES)).length;
  const movedTo = (stages, a, b) => (input.audit || []).filter(x => x.action === 'stage_changed' && within(parseDate(x.timestamp), a, b) && stages.includes(normStage((String(x.detail || '').match(/\sto\s+(.*)$/i) || [])[1]))).length;
  const pipeline = {
    openRoles: trend(openRoles.length, openSnap ? openSnap.openRoles : null),
    openPositions: fc.openPositions,
    byClient: [...byCo.values()].sort((a, b) => b.roles - a.roles),
    roles: roleRows.sort((a, b) => (b.idleDays ?? 9999) - (a.idleDays ?? 9999)),
    atRisk: roleRows.filter(r => r.atRisk).length,
    staleDays,
    timeToFillDays: { quarter: fillSpeed(qS, tomorrow), ytd: fillSpeed(yS, tomorrow), lastQuarter: fillSpeed(lqS, qS) },
    rolesFilled: { month: trend(filled(mS, tomorrow), filled(lmS, mS)), quarter: trend(filled(qS, tomorrow), filled(lqS, qS)), ytd: filled(yS, tomorrow) },
    submissions: trend(movedTo(['submitted'], mS, tomorrow), movedTo(['submitted'], lmS, mS)),
    interviews: trend(movedTo(['interview_scheduled'], mS, tomorrow), movedTo(['interview_scheduled'], lmS, mS)),
    offers: trend(movedTo(['offer'], mS, tomorrow), movedTo(['offer'], lmS, mS)),
    conversion: {
      basis: 'Candidates added in the last 12 months',
      submitted: nSub, interviewed: nInt, offered: nOff,
      submissionToInterviewPct: nSub ? Math.round((nInt / nSub) * 100) : null,
      interviewToOfferPct: nInt ? Math.round((nOff / nInt) * 100) : null,
    },
  };

  /* ----- Clients ----- */
  const firstSeen = (input.clientFirstSeen || []).map(c => ({ name: c.name, t: parseDate(c.date) })).filter(c => c.t);
  const won = (a, b) => firstSeen.filter(c => within(c.t, a, b));
  const r12 = new Map();
  invoices.filter(i => within(i.d, d365, tomorrow)).forEach(i => { const k = lc(i.company); const g = r12.get(k) || { company: i.company, revenue: 0 }; g.revenue += i.amount; r12.set(k, g); });
  const r12List = [...r12.values()].sort((a, b) => b.revenue - a.revenue);
  const warnPct = num(settings.concentration_warn_pct) || 40;
  const topShare = last12 > 0 && r12List.length ? round1((r12List[0].revenue / last12) * 100) : null;
  const invByNumber = new Map(invoices.map(i => [lc(i.number), i]));
  const guarantee = (input.placements || []).filter(pl => pl.status === 'active' && pl.guaranteeEnd && pl.daysLeft != null && pl.daysLeft >= 0 && pl.startDate && pl.startDate <= iso(today)).map(pl => {
    const inv = (pl.invoiceNumber && invByNumber.get(lc(pl.invoiceNumber))) || invoices.find(i => lc(i.candidateName) === lc(pl.name) && lc(i.company) === lc(pl.company)) || null;
    const r = roles.find(x => lc(x.company) === lc(pl.company) && lc(x.role) === lc(pl.role));
    const sal = salaryValue(pl.salary, roleCtx(r));
    const est = sal ? sal * feeRateFor(sal) / 100 : 0;
    return {
      name: pl.name, company: pl.company, role: pl.role, startDate: pl.startDate, guaranteeEnd: pl.guaranteeEnd, guaranteeWeeks: pl.guaranteeWeeks,
      daysLeft: pl.daysLeft, atRisk: round2(inv ? inv.amount : est), basis: inv ? 'invoice ' + inv.number : (est ? 'estimated fee, no invoice yet' : 'no fee data'),
    };
  }).sort((a, b) => a.daysLeft - b.daysLeft);
  const leftInGuarantee = (input.placements || []).filter(pl => pl.status === 'left');
  const clients = {
    newClients: { month: trend(won(mS, tomorrow).length, won(lmS, mS).length), quarter: trend(won(qS, tomorrow).length, won(lqS, qS).length), ytd: won(yS, tomorrow).length, namesThisMonth: won(mS, tomorrow).map(c => c.name) },
    invoicedClientsYtd: byClient.length,
    concentration: {
      basis: 'Invoiced in the last 12 months', warnPct, topClient: r12List[0] ? r12List[0].company : '', topSharePct: topShare,
      warn: topShare != null && topShare > warnPct,
      shares: r12List.slice(0, 5).map(g => ({ company: g.company, revenue: round2(g.revenue), sharePct: round1((g.revenue / last12) * 100) })),
    },
    guaranteeWatch: { count: guarantee.length, revenueAtRisk: round2(sum(guarantee, g => g.atRisk)), placements: guarantee, leftInGuarantee: leftInGuarantee.length },
  };

  /* ----- Cost and staff ----- */
  const employees = input.employees || [];
  const commissionBy = (a, b) => { const o = {}; invoices.filter(i => i.commissionAmount > 0 && i.paid && within(i.pd, a, b)).forEach(i => { const k = String(i.consultant || '').trim() || 'Unassigned'; o[k] = (o[k] || 0) + i.commissionAmount; }); return o; };
  const revenueBy = (a, b) => { const o = {}; invoices.filter(i => within(i.d, a, b)).forEach(i => { const k = String(i.consultant || '').trim() || 'Unassigned'; o[k] = (o[k] || 0) + i.amount; }); return o; };
  const teamCost = (a, bIncl) => {
    const comm = commissionBy(a, new Date(bIncl.getTime() + DAY));
    return employees.map(e => {
      const c = empCostBetween(e, a, bIncl);
      const cm = sumFor(e, comm);
      const cmPension = e.pensionOnComm === false ? 0 : cm * (num(e.pensionPct) / 100);
      return { e, salary: c.salary, pension: round2(c.pension + cmPension), commission: round2(cm), total: round2(c.total + cm + cmPension) };
    });
  };
  const lastMonthEnd = new Date(mS.getTime() - DAY);
  const ytdCosts = teamCost(yS, today), mCosts = teamCost(mS, today), lmCosts = teamCost(lmS, lastMonthEnd);
  const teamYtd = sum(ytdCosts, x => x.total);
  const adIn = (a, bIncl) => sum(spendOccurrences(input.adSpend, iso(a), iso(bIncl)), o => o.amount);
  const manualAd = num(input.fin && input.fin.manualAd);
  const adLogged = adIn(yS, today);
  const adTotal = adLogged + manualAd;
  const profit = ytdRevenue - teamYtd - adTotal; // same sum as the old Business Health "profit"
  const hiresYtd = filled(yS, tomorrow);
  // advertising by role: an entry for one role goes to that role, "all open roles" is split across the roles open that day
  const openOn = date => roles.filter(r => { const from = dateOnly(r.date_opened) || '0000-00-00'; const to = dateOnly(r.date_closed) || (['open', 'hold'].includes(lc(r.status)) ? '9999-12-31' : from); return from <= date && date <= to; });
  const perRole = new Map(); let generalSpend = 0;
  const addRole = (company, role, amt) => { const k = lc(company) + '|' + lc(role); const g = perRole.get(k) || { company, role, spend: 0 }; g.spend += amt; perRole.set(k, g); };
  spendOccurrences(input.adSpend, iso(yS), iso(today)).forEach(o => {
    const applies = o.e.applies_to || (o.e.role ? 'specific' : 'general');
    if (applies === 'specific' && o.e.role) {
      const m = roles.filter(r => lc(r.role) === lc(o.e.role));
      const r = m.find(x => o.e.company && lc(x.company) === lc(o.e.company)) || m[0];
      addRole(r ? r.company : (o.e.company || ''), o.e.role, o.amount);
    } else if (applies === 'open_roles') {
      const open = openOn(o.date);
      if (open.length) open.forEach(r => addRole(r.company, r.role, o.amount / open.length)); else generalSpend += o.amount;
    } else generalSpend += o.amount;
  });
  const todayISO = iso(today);
  const recurringAds = (input.adSpend || []).filter(e => e.frequency === 'monthly' && num(e.amount) && dateOnly(e.date) && dateOnly(e.date) <= todayISO && (!dateOnly(e.end_date) || dateOnly(e.end_date) >= todayISO))
    .map(e => ({ name: [e.channel, e.role].filter(Boolean).join(' - ') || 'Monthly spend', amount: num(e.amount) }));
  const monthlyPayroll = sum(employees.filter(e => (!e.endDate || e.endDate >= todayISO) && e.startDate && e.startDate <= todayISO), e => num(e.salary) * (1 + num(e.pensionPct) / 100)) / 12;
  const overheads = num(input.fin && input.fin.overheads);
  // build 65: commission still to go through payroll, with employer pension on it, for people on payroll only (the director takes dividends, not commission)
  const commissionItems = invoices.filter(i => i.commissionAmount > 0 && !i.commissionPaidDate).map(i => {
    const e = employees.find(x => empMatches(x, i.consultant));
    if (!e) return null;
    const pen = e.pensionOnComm === false ? 0 : num(e.pensionPct) / 100;
    return { number: i.number, company: i.company, amount: round2(i.commissionAmount * (1 + pen)), paid: i.paid, paidDate: i.paid && i.pd ? iso(i.pd) : '' };
  }).filter(Boolean);
  const recurringTotal = monthlyPayroll + sum(recurringAds, r => r.amount) + overheads;
  const cost = {
    teamCostYtd: round2(teamYtd), salaryYtd: round2(sum(ytdCosts, x => x.salary)), pensionYtd: round2(sum(ytdCosts, x => x.pension)), commissionYtd: round2(sum(ytdCosts, x => x.commission)),
    teamCostMonth: trend(sum(mCosts, x => x.total), sum(lmCosts, x => x.total), 'down'),
    adSpendYtd: round2(adTotal), adSpendLogged: round2(adLogged), adSpendManual: round2(manualAd),
    adSpendMonth: trend(adIn(mS, today), adIn(lmS, lastMonthEnd), 'down'),
    adSpendByRole: [...perRole.values()].map(g => ({ ...g, spend: round2(g.spend) })).sort((a, b) => b.spend - a.spend), adSpendGeneral: round2(generalSpend),
    hiresYtd, costPerHire: hiresYtd ? round2((teamYtd + adTotal) / hiresYtd) : null, adSpendPerHire: hiresYtd ? round2(adTotal / hiresYtd) : null,
    profitYtd: round2(profit), marginPct: ytdRevenue > 0 ? round1((profit / ytdRevenue) * 100) : null,
    marginNote: 'Revenue invoiced this year less salary, employer pension, commission and advertising. Other overheads and tax are not taken off.',
    recurring: { payroll: round2(monthlyPayroll), advertising: recurringAds, overheads: round2(overheads), totalPerMonth: round2(recurringTotal) },
    bank: { connected: false, note: 'Connect bank in build 63' },
  };

  const act = activityCounts(input, mS, tomorrow), actPrev = activityCounts(input, lmS, mS);
  const qLabel = `Q${Math.floor(today.getUTCMonth() / 3) + 1} ${today.getUTCFullYear()}`;
  const targetFor = owner => (input.kpiTargets || []).find(t => new RegExp(`^${qLabel}$`, 'i').test(String(t.quarter).trim().replace(/\s+/g, ' ')) && lc(t.owner) === lc(owner)) || null;
  const revYtdBy = revenueBy(yS, tomorrow), matched = new Set();
  const people = ytdCosts.map(x => {
    const key = lc(x.e.name).split(/\s+/)[0];
    Object.keys(revYtdBy).filter(k => empMatches(x.e, k)).forEach(k => matched.add(k));
    const rev = sumFor(x.e, revYtdBy);
    const mine = i => empMatches(x.e, i.consultant);
    return {
      name: x.e.name, role: x.e.role || '', key,
      activity: personActivity(act, actPrev, key), target: targetFor(key),
      placementsYtd: ytdInv.filter(mine).length, placementsQuarter: invoices.filter(i => within(i.d, qS, tomorrow) && mine(i)).length,
      revenueYtd: round2(rev), salaryAndPension: round2(x.salary + x.pension - (x.e.pensionOnComm === false ? 0 : x.commission * (num(x.e.pensionPct) / 100))),
      commission: x.commission, employmentCostYtd: x.total, roiPct: x.total > 0 ? Math.round(((rev - x.total) / x.total) * 100) : null,
    };
  });
  const others = Object.keys(revYtdBy).filter(k => !matched.has(k)).map(k => ({ name: k, note: k === 'Unassigned' ? 'No consultant chosen on the invoice' : 'Not on payroll', revenueYtd: round2(revYtdBy[k]), activity: personActivity(act, actPrev, lc(k).split(/\s+/)[0]) }));
  const staff = {
    quarter: qLabel, teamTarget: targetFor(''), people, others,
    teamRoiPct: teamYtd > 0 ? Math.round(((ytdRevenue - teamYtd) / teamYtd) * 100) : null,
    commission: commissionSummary(invoices, yS, tomorrow),
  };

  /* ----- VAT threshold watch ----- */
  const otherSales = (input.otherSales || []).map(s => ({ ...s, d: parseDate(s.date), amount: num(s.amount) })).filter(s => within(s.d, d365, tomorrow));
  const otherTotal = sum(otherSales, s => s.amount);
  const vat = vatWatch(last12 + otherTotal, settings);
  vat.invoices = round2(last12); vat.otherSales = round2(otherTotal);
  vat.periodFrom = iso(d365); vat.periodTo = iso(today);
  // rolling total month by month, so the direction of travel is visible
  vat.monthly = [];
  for (let i = 11; i >= 0; i--) {
    const a = monthStart(today, -i), b = monthStart(today, -i + 1);
    vat.monthly.push({ month: monthKey(a), amount: round2(invoiced(a, b) + sum((input.otherSales || []).filter(s => within(parseDate(s.date), a, b)), s => num(s.amount))) });
  }

  // build 63: the bank feed (balance, cash forecast, tax reserve, bank costs). Not connected means the tiles say so, with no invented numbers.
  const bk = bankKpi(input.bank, { todayISO, invoices: (input.invoices || []).filter(i => i && i.number), monthlyPayroll, commissionItems, commissionCutoffDay: input.fin && input.fin.payrollCutoff, profitYtd: profit, monthlyOverheads: overheads, ytdStartISO: iso(yS) });
  money.bank = bk.tiles; cost.bank = bk.tiles;

  const out = { generatedAt: now.toISOString(), month: monthName(today), comparedWith: monthName(lmS), dayOfMonth: today.getUTCDate(), money, pipeline, clients, cost, staff, vat, settings, bank: bk.panel };
  out.changes = whatChanged(out);
  out.snapshot = { month: monthKey(today), takenOn: iso(today), weightedForecast: fc.weighted, outstanding: round2(outstanding), overdue: round2(overdue), openRoles: openRoles.length };
  return out;
}

export function vatWatch(turnover, settings) {
  const threshold = num((settings || {}).vat_threshold) || num(KPI_SETTING_DEFAULTS.vat_threshold);
  const levels = String((settings || {}).vat_alert_pcts || KPI_SETTING_DEFAULTS.vat_alert_pcts).split(',').map(s => num(s)).filter(n => n > 0 && n <= 100).sort((a, b) => a - b);
  const pct = threshold > 0 ? round1((turnover / threshold) * 100) : 0;
  const reached = levels.filter(l => pct >= l);
  return {
    turnover12m: round2(turnover), threshold, pct, headroom: round2(threshold - turnover), levels, levelsReached: reached,
    status: pct >= 100 ? 'over' : reached.length ? 'warn' : 'ok', registered: false,
    note: 'Steering estimate from invoices raised and Talent Suite sales in the last 12 months. Confirm with the accountant before acting.',
  };
}

function commissionSummary(invoices, yS, yE) {
  const c = { recognised: 0, due: 0, paidOut: 0, pending: 0 };
  invoices.filter(i => i.commissionAmount > 0).forEach(i => {
    if (i.paid) {
      if (within(i.pd, yS, yE)) c.recognised += i.commissionAmount;
      if (i.commissionPaidDate) c.paidOut += i.commissionAmount; else c.due += i.commissionAmount;
    } else c.pending += i.commissionAmount;
  });
  Object.keys(c).forEach(k => { c[k] = round2(c[k]); });
  return c;
}

/* ---------- activity (counts only, never money) ---------- */
const ACTIVITY_KEYS = ['candidatesAdded', 'submissions', 'interviewsBooked', 'emails', 'calls', 'tasksDone', 'interviewsHeld', 'interviewsNoShow', 'interviewsAwaiting'];
// build 66.2: one person key however the user was stored (ella, Ella, Ella Pietrzak, ella@live2helprecruitment.co.uk all become ella)
export function personKey(u) { return lc(u).split('@')[0].split(/[\s.]+/)[0] || ''; }
function activityCounts(input, a, b) {
  const by = {};
  const g = u => { const k = personKey(u) || 'unknown'; if (!by[k]) { by[k] = {}; ACTIVITY_KEYS.forEach(x => { by[k][x] = 0; }); } return by[k]; };
  (input.activity || []).forEach(r => {
    if (!within(parseDate(r.timestamp), a, b)) return;
    const o = g(r.user);
    if (r.action === 'candidate_added') o.candidatesAdded++;
    else if (r.action === 'submitted') o.submissions++;
    else if (r.action === 'interview_booked') o.interviewsBooked++;
    else if (r.action === 'task_completed') o.tasksDone++;
  });
  (input.comms || []).forEach(c => {
    if (!within(parseDate(c.timestamp), a, b)) return;
    const ch = lc(c.channel), o = g(c.user);
    // build 66.3: only email the person sent counts. Mail received (logged by mailbox sync) and suggestion notes are inbound and do not.
    if (ch === 'email') { if (lc(c.direction) !== 'inbound') o.emails++; }
    else if (ch === 'call') o.calls++;
  });
  // build 66.2: interview attendance. Credited to the person who arranged the interview. Completed = attended, no show = did not attend.
  // Cancelled interviews are left out. A scheduled interview whose day has passed has no outcome recorded yet and is counted separately.
  const todayStart = dayOf(input.now ? new Date(input.now) : new Date());
  const rows = {};
  (input.interviews || []).forEach(iv => {
    const d = parseDate(iv.date);
    if (!within(d, a, b)) return;
    const st = lc(iv.status) || 'scheduled', o = g(iv.created_by);
    // build 66.4: interviews cancelled automatically only because the candidate was later rejected, whose day had passed, did go ahead.
    const autoCancelled = st === 'cancelled' && /cancelled automatically/i.test(String(iv.notes || '')) && d < todayStart;
    rows[personKey(iv.created_by) || 'unknown'] = (rows[personKey(iv.created_by) || 'unknown'] || 0) + (st === 'cancelled' && !autoCancelled ? 0 : 1);
    if (st === 'completed' || autoCancelled) o.interviewsHeld++;
    else if (st === 'no_show' || st === 'no show' || st === 'noshow') o.interviewsNoShow++;
    else if (st === 'scheduled' && d < todayStart) o.interviewsHeld++; // build 66.4: a past interview still marked Scheduled is counted as attended unless it was marked No show or Cancelled
  });
  // build 66.4: Interviews arranged is the larger of the activity log count and the interview rows, so an interview made without a log entry still counts.
  Object.keys(rows).forEach(k => { g(k); by[k].interviewsBooked = Math.max(by[k].interviewsBooked || 0, rows[k]); });
  return by;
}
function personActivity(now, before, key) {
  const a = now[key] || {}, b = before[key] || {}, out = {};
  ACTIVITY_KEYS.forEach(k => { out[k] = trend(a[k] || 0, b[k] || 0); });
  return out;
}

/* ---------- "What changed this month": the five biggest movements, in plain English ---------- */
function whatChanged(k) {
  const items = [];
  const add = (label, t, opts = {}) => {
    if (!t || t.before == null || t.diff === 0) return;
    const fmt = opts.money ? gbp : (n => String(Math.round(n * 10) / 10));
    const size = t.before ? Math.abs(t.diff / t.before) : 1;
    const good = t.better === 'down' ? t.diff < 0 : t.diff > 0;
    items.push({ label, good, weight: size * (opts.weight || 1) + (opts.money ? Math.min(1, Math.abs(t.diff) / 5000) : 0),
      text: `${label} ${t.diff > 0 ? 'rose' : 'fell'} from ${fmt(t.before)} to ${fmt(t.now)}${t.pct != null ? ` (${t.pct > 0 ? '+' : ''}${t.pct}%)` : ''}` });
  };
  add('Revenue invoiced', k.money.invoiced.month, { money: true, weight: 1.5 });
  add('Cash received from clients', k.money.paid.month, { money: true, weight: 1.4 });
  add('Overdue invoices', k.money.overdue, { money: true, weight: 1.3 });
  add('Roles filled', k.pipeline.rolesFilled.month, { weight: 1.3 });
  add('Open roles', k.pipeline.openRoles);
  add('Candidates submitted', k.pipeline.submissions);
  add('Interviews arranged', k.pipeline.interviews);
  add('Offers', k.pipeline.offers, { weight: 1.2 });
  add('New clients won', k.clients.newClients.month, { weight: 1.2 });
  add('Team cost', k.cost.teamCostMonth, { money: true, weight: 0.8 });
  add('Advertising spend', k.cost.adSpendMonth, { money: true, weight: 0.8 });
  const out = items.sort((a, b) => b.weight - a.weight).slice(0, 5).map(({ label, good, text }) => ({ label, good, text }));
  if (k.dayOfMonth < 28 && out.length) out.push({ label: 'Note', good: null, text: `${k.month} is part way through (day ${k.dayOfMonth}), so it is being compared with the whole of ${k.comparedWith}.` });
  return out;
}

/* ---------- Ella's view: her own activity only. No revenue, cost, commission or margin figure may be added here. ---------- */
export function computeMyKpi(input, userKey) {
  const p = prepare(input);
  const { now, today, cands } = p;
  const tomorrow = new Date(today.getTime() + DAY);
  const mS = monthStart(today), lmS = monthStart(today, -1), qS = quarterStart(today);
  const key = personKey(userKey);
  const act = activityCounts(input, mS, tomorrow), prev = activityCounts(input, lmS, mS), qAct = activityCounts(input, qS, tomorrow);
  const qLabel = `Q${Math.floor(today.getUTCMonth() / 3) + 1} ${today.getUTCFullYear()}`;
  const target = t => new RegExp(`^${qLabel}$`, 'i').test(String(t.quarter).trim().replace(/\s+/g, ' '));
  const targets = (input.kpiTargets || []).filter(target);
  const filledQ = cands.filter(c => FILLED_STAGES.includes(c.stage) && within(c.offerDate, qS, tomorrow)).length;
  const first = n => lc(n).split(/\s+/)[0];
  const myPlacements = (a, b) => (input.invoices || []).filter(i => i && i.number && first(i.consultant) === key && within(parseDate(i.date), a, b)).length;
  const t = targets.find(x => lc(x.owner) === key) || null, team = targets.find(x => !lc(x.owner)) || null;
  const strip = x => (x ? { quarter: x.quarter, targetRoles: x.targetRoles, targetNewClients: x.targetNewClients, targetAvgFillSpeedDays: x.targetAvgFillSpeedDays } : null);
  return {
    generatedAt: now.toISOString(), user: key, month: monthName(today), comparedWith: monthName(lmS), quarter: qLabel,
    activity: personActivity(act, prev, key),
    activityQuarter: qAct[key] || {},
    placements: { month: myPlacements(mS, tomorrow), quarter: myPlacements(qS, tomorrow), ytd: myPlacements(yearStart(today), tomorrow) },
    target: strip(t), teamTarget: strip(team), teamRolesFilledQuarter: filledQ,
  };
}

/* ---------- VAT alerts: which levels need an email today ----------
   markers: { "80": "2026-11-16", ... } = the date each level was last alerted. An alert is sent once per level.
   When turnover drops back under a level its marker is cleared, so crossing it again alerts again. */
export function vatAlertsDue(vat, markers) {
  const send = [], clear = [];
  (vat.levels || []).forEach(l => {
    const has = !!(markers && markers[String(l)]);
    if (vat.pct >= l && !has) send.push(l);
    if (vat.pct < l && has) clear.push(l);
  });
  return { send, clear };
}
export function vatAlertText(vat, level) {
  const g = n => '£' + Math.round(n || 0).toLocaleString('en-GB');
  return [
    `Turnover over the last 12 months is ${g(vat.turnover12m)}, which is ${vat.pct}% of the VAT registration threshold of ${g(vat.threshold)}.`,
    `This has passed the ${level}% alert level. Headroom left before registration is required: ${g(Math.max(0, vat.headroom))}.`,
    '',
    `Made up of invoices raised ${g(vat.invoices)} and Talent Suite sales ${g(vat.otherSales)}, from ${vat.periodFrom} to ${vat.periodTo}.`,
    '',
    'What to do: speak to the accountant about when to register and whether fees should be quoted plus VAT from now on. You must register within 30 days of the end of the month in which the 12 month total goes over the threshold.',
    '',
    'This is a steering estimate from the workspace. The accountant\'s figures are the source of truth. Open KPI Reporting > VAT threshold watch for the month by month picture.',
  ].join('\n');
}
