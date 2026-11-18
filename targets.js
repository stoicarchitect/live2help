// Build 67: targets that set themselves, service line reporting and role profitability.
// Pure functions only (no database, no network) so every sum can be tested and reused by reports.
// All money lives in the owner functions. targetsForPerson returns counts only and is the only thing Ella can be given.
import { parseDate, spendOccurrences, personKey } from './kpi-owner.js';

export const SERVICE_LINES = [
  { key: 'perm', label: 'Permanent placement' },
  { key: 'partnership', label: 'Talent Partnership' },
  { key: 'suite', label: 'Talent Suite' },
  { key: 'youth', label: 'Funded Youth Hire' },
];
const LINE_KEYS = SERVICE_LINES.map(l => l.key);
const DAY = 86400000;
const lc = s => String(s || '').trim().toLowerCase();
const num = v => { const n = parseFloat(v); return Number.isFinite(n) ? n : 0; };
const r2 = n => Math.round((n || 0) * 100) / 100;
const r1 = n => Math.round((n || 0) * 10) / 10;
const iso = d => d.toISOString().slice(0, 10);
const within = (d, a, b) => !!d && d >= a && d < b;
export const lineLabel = k => (SERVICE_LINES.find(l => l.key === k) || { label: k }).label;
export const cleanLine = v => { const k = lc(v); return LINE_KEYS.includes(k) ? k : ''; };

// When the business has too little history to measure a ratio, these steering defaults are used and shown as assumptions.
export const RATIO_DEFAULTS = { submissionsPerPlacement: 6, interviewsPerPlacement: 3, callsPerPlacement: 60, emailsPerPlacement: 90, candidatesPerPlacement: 15, avgFee: 3500 };
const MIN_PLACEMENTS_FOR_HISTORY = 3;
const WORKING_WEEKS = 46;

/* ---------- service lines ---------- */
// Every sale gets exactly one line, so the lines always add up to total revenue.
// Client invoices default to permanent placement unless tagged. Talent Suite orders and credit top-ups are Talent Suite.
export function salesByLine(input, fromD, toD) {
  const tags = input.serviceTags || {};
  const sales = [];
  (input.invoices || []).forEach(i => {
    const d = parseDate(i.date); if (!within(d, fromD, toD)) return;
    sales.push({ line: cleanLine(tags[i.number]) || 'perm', amount: num(i.amount), kind: 'invoice', ref: i.number, company: i.company });
  });
  (input.otherSales || []).forEach(s => {
    const d = parseDate(s.date); if (!within(d, fromD, toD)) return;
    sales.push({ line: 'suite', amount: num(s.amount), kind: s.kind || 'sale', ref: '', company: '' });
  });
  const by = {}; LINE_KEYS.forEach(k => { by[k] = 0; });
  sales.forEach(s => { by[s.line] += s.amount; });
  const total = sales.reduce((a, s) => a + s.amount, 0);
  LINE_KEYS.forEach(k => { by[k] = r2(by[k]); });
  return { byLine: by, total: r2(total), count: sales.length };
}

/* ---------- the business's own ratios ---------- */
export function historicalRatios(input, today) {
  const from = new Date(today.getTime() - 365 * DAY), to = new Date(today.getTime() + DAY);
  const invs = (input.invoices || []).filter(i => within(parseDate(i.date), from, to) && num(i.amount) > 0);
  const tags = input.serviceTags || {};
  const perm = invs.filter(i => (cleanLine(tags[i.number]) || 'perm') === 'perm');
  const placements = perm.length;
  const avgFeeSeen = placements ? perm.reduce((a, i) => a + num(i.amount), 0) / placements : 0;
  const act = (input.activity || []).filter(a => within(parseDate(a.timestamp), from, to));
  const comms = (input.comms || []).filter(c => within(parseDate(c.timestamp), from, to));
  const ivs = (input.interviews || []).filter(i => within(parseDate(i.date), from, to) && lc(i.status) !== 'cancelled');
  const counts = {
    submissions: act.filter(a => a.action === 'submitted').length,
    interviews: Math.max(ivs.length, act.filter(a => a.action === 'interview_booked').length),
    calls: comms.filter(c => lc(c.channel) === 'call').length,
    emails: comms.filter(c => lc(c.channel) === 'email' && lc(c.direction) !== 'inbound').length,
    candidates: act.filter(a => a.action === 'candidate_added').length,
  };
  const enough = placements >= MIN_PLACEMENTS_FOR_HISTORY;
  const per = (n, def) => (enough && n > 0) ? r1(n / placements) : def;
  const D = RATIO_DEFAULTS;
  const ratios = {
    avgFee: enough ? r2(avgFeeSeen) : D.avgFee,
    submissionsPerPlacement: per(counts.submissions, D.submissionsPerPlacement),
    interviewsPerPlacement: per(counts.interviews, D.interviewsPerPlacement),
    callsPerPlacement: per(counts.calls, D.callsPerPlacement),
    emailsPerPlacement: per(counts.emails, D.emailsPerPlacement),
    candidatesPerPlacement: per(counts.candidates, D.candidatesPerPlacement),
  };
  const source = {};
  Object.keys(ratios).forEach(k => {
    const measured = enough && (k === 'avgFee' ? avgFeeSeen > 0 : counts[{ submissionsPerPlacement: 'submissions', interviewsPerPlacement: 'interviews', callsPerPlacement: 'calls', emailsPerPlacement: 'emails', candidatesPerPlacement: 'candidates' }[k]] > 0);
    source[k] = measured ? 'measured' : 'default';
  });
  return { ratios, source, placementsLast12Months: placements, usedHistory: enough };
}

/* ---------- working backwards from the annual goal ---------- */
// goal = { year, total, lines: { perm, partnership, suite, youth } }. Line goals are optional: any money not given to a line goes to permanent placement.
export function normaliseGoal(g) {
  const year = parseInt(g && g.year, 10) || 0;
  const total = Math.max(0, num(g && g.total));
  const lines = {}; let given = 0;
  LINE_KEYS.forEach(k => { const v = Math.max(0, num(g && g.lines && g.lines[k])); lines[k] = v; given += v; });
  if (given > total) { // the lines may never add up to more than the goal
    const f = total / given; LINE_KEYS.forEach(k => { lines[k] = r2(lines[k] * f); }); given = total;
  }
  lines.perm = r2(lines.perm + (total - given));
  return { year, total, lines };
}

export function backwardsTargets(goalIn, hist) {
  const goal = normaliseGoal(goalIn);
  const R = hist.ratios;
  const perYear = goal.lines.perm;
  const placementsYear = R.avgFee > 0 ? perYear / R.avgFee : 0;
  const mk = n => ({ year: r1(n), month: r1(n / 12), week: r1(n / WORKING_WEEKS) });
  const placementsRounded = Math.ceil(placementsYear * 10) / 10;
  return {
    goal,
    revenue: { year: r2(goal.total), month: r2(goal.total / 12), week: r2(goal.total / WORKING_WEEKS) },
    byLine: LINE_KEYS.map(k => ({ key: k, label: lineLabel(k), year: r2(goal.lines[k]), month: r2(goal.lines[k] / 12) })),
    activity: {
      placements: mk(placementsRounded),
      candidatesAdded: mk(placementsYear * R.candidatesPerPlacement),
      submissions: mk(placementsYear * R.submissionsPerPlacement),
      interviews: mk(placementsYear * R.interviewsPerPlacement),
      calls: mk(placementsYear * R.callsPerPlacement),
      emails: mk(placementsYear * R.emailsPerPlacement),
    },
    assumptions: { ...R, source: hist.source, placementsLast12Months: hist.placementsLast12Months, usedHistory: hist.usedHistory, workingWeeksPerYear: WORKING_WEEKS, note: hist.usedHistory ? 'Ratios are measured from the last 12 months of placements.' : `Fewer than ${MIN_PLACEMENTS_FOR_HISTORY} placements in the last 12 months, so steering defaults are used until there is more history.` },
  };
}

/* ---------- progress against the goal ---------- */
export function goalProgress(input, goalIn, today) {
  const goal = normaliseGoal(goalIn);
  if (!goal.year || !goal.total) return { set: false };
  const ys = new Date(Date.UTC(goal.year, 0, 1)), ye = new Date(Date.UTC(goal.year + 1, 0, 1));
  if (today < ys) return { set: true, started: false, startsOn: iso(ys), goal: goal.total };
  const upTo = today < ye ? new Date(today.getTime() + DAY) : ye;
  const sold = salesByLine(input, ys, upTo);
  const daysIn = Math.max(1, Math.round((upTo - ys) / DAY)), daysYear = Math.round((ye - ys) / DAY);
  const expected = r2(goal.total * Math.min(1, daysIn / daysYear));
  const gap = r2(sold.total - expected);
  const status = expected <= 0 ? 'on_track' : sold.total >= expected * 1.1 ? 'ahead' : sold.total >= expected * 0.9 ? 'on_track' : 'behind';
  const remaining = Math.max(0, goal.total - sold.total);
  const monthsLeft = Math.max(1, 12 - (daysIn / daysYear) * 12);
  return {
    set: true, started: true, year: goal.year, goal: goal.total, soldToDate: sold.total, expectedToDate: expected, gap, status,
    needPerMonthFromNow: r2(remaining / monthsLeft),
    lines: LINE_KEYS.map(k => ({ key: k, label: lineLabel(k), goal: r2(goal.lines[k]), sold: sold.byLine[k] })),
  };
}

/* ---------- Ella's targets (counts only, no money anywhere) ---------- */
// Manual override: { month|week: { submissions, interviews, ... } } wins over the calculated figure.
export function targetsForPerson(back, share, override) {
  const s = Math.max(0, Math.min(1, num(share) || 1));
  const out = {};
  ['placements', 'candidatesAdded', 'submissions', 'interviews', 'calls', 'emails'].forEach(k => {
    const a = back.activity[k];
    out[k] = { month: r1(a.month * s), week: r1(a.week * s), manual: false };
    const o = override && override[k];
    if (o && (num(o.month) > 0 || num(o.week) > 0)) {
      if (num(o.month) > 0) out[k].month = num(o.month);
      if (num(o.week) > 0) out[k].week = num(o.week);
      out[k].manual = true;
    }
  });
  return out;
}

// Progress this month and this week against the person's own targets. Counts only.
export function personProgress(input, userKey, targets, today) {
  const ms = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1)), me = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() + 1, 1));
  const dow = (today.getUTCDay() + 6) % 7; const ws = new Date(today.getTime() - dow * DAY), we = new Date(ws.getTime() + 7 * DAY);
  const mine = u => personKey(u) === userKey;
  const count = (a, b) => {
    const act = (input.activity || []).filter(x => mine(x.user) && within(parseDate(x.timestamp), a, b));
    const comms = (input.comms || []).filter(x => mine(x.user) && within(parseDate(x.timestamp), a, b));
    const ivs = (input.interviews || []).filter(x => mine(x.created_by) && within(parseDate(x.date), a, b) && lc(x.status) !== 'cancelled');
    return {
      candidatesAdded: act.filter(x => x.action === 'candidate_added').length,
      submissions: act.filter(x => x.action === 'submitted').length,
      interviews: Math.max(ivs.length, act.filter(x => x.action === 'interview_booked').length),
      calls: comms.filter(x => lc(x.channel) === 'call').length,
      emails: comms.filter(x => lc(x.channel) === 'email' && lc(x.direction) !== 'inbound').length,
    };
  };
  const m = count(ms, me), w = count(ws, we);
  const dayOfMonth = today.getUTCDate(), daysInMonth = Math.round((me - ms) / DAY);
  const rows = ['candidatesAdded', 'submissions', 'interviews', 'calls', 'emails'].map(k => {
    const tm = targets[k].month, tw = targets[k].week;
    const expectedM = tm * (dayOfMonth / daysInMonth);
    const st = tm <= 0 ? 'none' : m[k] >= expectedM * 1.1 ? 'ahead' : m[k] >= expectedM * 0.9 ? 'on_track' : 'behind';
    return { key: k, monthDone: m[k], monthTarget: tm, weekDone: w[k], weekTarget: tw, status: st, gapMonth: r1(Math.max(0, tm - m[k])), manual: !!targets[k].manual };
  });
  return { rows, month: iso(ms).slice(0, 7), weekStarting: iso(ws) };
}

/* ---------- role and client profitability (owner only, money) ---------- */
// Cost is what is logged against the role (Ad Spend rows with that company and role). Shared advertising with no role is shown as unallocated, never guessed.
// Effort is counted from logged activity on the role's candidates. AI spend is not tracked per role, so it is not in the figure.
export function roleProfitability(input, today) {
  const from = new Date(today.getTime() - 365 * DAY), to = new Date(today.getTime() + DAY);
  const occ = spendOccurrences(input.adSpend || [], iso(from), iso(today));
  const spendFor = (company, role) => occ.filter(o => lc(o.e.company) === lc(company) && lc(o.e.role) === lc(role)).reduce((a, o) => a + o.amount, 0);
  const unallocated = occ.filter(o => !lc(o.e.role)).reduce((a, o) => a + o.amount, 0);
  const manualMonthly = num(input.fin && input.fin.manualAd);
  const invs = input.invoices || [];
  const stale = parseInt(input.settings && input.settings.role_stale_days, 10) || 7;
  const cands = input.candidates || [];
  const roles = (input.roles || []).filter(r => r && r.company && r.role);
  const rows = roles.map(r => {
    const fee = invs.filter(i => lc(i.company) === lc(r.company) && lc(i.role) === lc(r.role)).reduce((a, i) => a + num(i.amount), 0);
    const opened = parseDate(r.date_opened);
    const closed = ['filled', 'closed', 'placed', 'lost'].includes(lc(r.status));
    const daysOpen = opened ? Math.max(0, Math.round(((closed ? (parseDate(r.date_closed) || today) : today) - opened) / DAY)) : null;
    const rc = cands.filter(c => lc(c.company) === lc(r.company) && lc(c.role) === lc(r.role));
    const submitted = rc.filter(c => ['submitted', 'interview_requested', 'interview_scheduled', 'interviewed', 'offer', 'start_date', 'day1', 'week1', 'month1'].includes(lc(c.stage).replace(/\s+/g, '_'))).length;
    const spend = spendFor(r.company, r.role);
    const flags = [];
    if (spend > 0 && fee < spend && (closed || (daysOpen != null && daysOpen > 30))) flags.push('Costs more than it has returned');
    if (!closed && daysOpen != null && daysOpen >= Math.max(21, stale * 3) && submitted === 0) flags.push('Open ' + daysOpen + ' days with no candidate submitted');
    return { company: r.company, role: r.role, status: lc(r.status) || 'open', daysOpen, feeEarned: r2(fee), adSpend: r2(spend), net: r2(fee - spend), candidates: rc.length, submitted, flags };
  });
  const clientMap = new Map();
  rows.forEach(x => { const k = lc(x.company); const g = clientMap.get(k) || { company: x.company, roles: 0, feeEarned: 0, adSpend: 0, candidates: 0, submitted: 0 }; g.roles++; g.feeEarned += x.feeEarned; g.adSpend += x.adSpend; g.candidates += x.candidates; g.submitted += x.submitted; clientMap.set(k, g); });
  const clients = [...clientMap.values()].map(g => ({ ...g, feeEarned: r2(g.feeEarned), adSpend: r2(g.adSpend), net: r2(g.feeEarned - g.adSpend), worth: g.feeEarned > 0 ? (g.adSpend > g.feeEarned ? 'Not covering its advertising' : 'Earning') : (g.roles > 0 && g.submitted > 0 ? 'In progress' : 'No return yet') })).sort((a, b) => b.feeEarned - a.feeEarned);
  return {
    roles: rows.sort((a, b) => (b.flags.length - a.flags.length) || (b.feeEarned - a.feeEarned)),
    clients,
    unallocatedAdSpend12m: r2(unallocated), manualAdMonthly: r2(manualMonthly),
    notes: ['Advertising is counted only where it was logged against a company and role.', 'Advertising with no role is shown as unallocated and is not shared out by guesswork.', 'AI spend is not tracked per role, so it is not in these figures.', 'Effort is shown as candidates and submissions on the role. No timesheets are used.'],
  };
}

/* ---------- one owner view ---------- */
export function computeTargets(input, goalIn, opts = {}) {
  const today = input.now ? new Date(input.now) : new Date();
  const day = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
  const hist = historicalRatios(input, day);
  const back = backwardsTargets(goalIn, hist);
  const progress = goalProgress(input, goalIn, day);
  const ytd = salesByLine(input, new Date(Date.UTC(day.getUTCFullYear(), 0, 1)), new Date(day.getTime() + DAY));
  const ella = targetsForPerson(back, opts.ellaShare, opts.ellaOverride);
  return { asOf: iso(day), back, progress, thisYearByLine: SERVICE_LINES.map(l => ({ key: l.key, label: l.label, amount: ytd.byLine[l.key] })), thisYearTotal: ytd.total, ella, profitability: roleProfitability(input, day) };
}
