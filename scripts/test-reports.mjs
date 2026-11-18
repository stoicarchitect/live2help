// Build 65 tests: node scripts/test-reports.mjs
// Report figures equal the KPI screen, Ella's report holds nothing restricted, commission is in the cash forecast.
import assert from 'assert';
import {
  firstWorkingDay, reportPeriodDue, isMonday, monthEndDate, buildOwnerSnapshot, focusPoints, ownerReportMarkdown, ownerReportEmail,
  weeklyFacts, weeklyBriefEmail, buildEllaSnapshot, ellaReportMarkdown, ellaReportEmail, ellaViolations, assertEllaClean, tidy,
} from '../reports.js';
import { computeOwnerKpi, computeMyKpi } from '../kpi-owner.js';
import { cashForecast } from '../bank.js';

let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; }; const eq = (a, b, m) => { assert.deepStrictEqual(a, b, m); n++; };
const BANK = new Set(['2026-12-25', '2026-12-28', '2027-01-01', '2027-03-26', '2027-03-29']);
const NO_DASH = /[—–]/;

// ---------- when a report is due ----------
eq(firstWorkingDay('2026-12', BANK), '2026-12-01', 'Dec 2026 starts on a Tuesday');
eq(firstWorkingDay('2027-01', BANK), '2027-01-04', 'Jan 2027: the 1st is a bank holiday and the 2nd and 3rd are a weekend');
eq(reportPeriodDue({ today: '2026-12-01', holidays: BANK, startMonth: '2026-11' }), '2026-11', 'first working day of December reports November');
eq(reportPeriodDue({ today: '2026-12-02', holidays: BANK, startMonth: '2026-11' }), '2026-11', 'a missed day is caught up the next morning');
eq(reportPeriodDue({ today: '2026-11-17', holidays: BANK, startMonth: '2026-11' }), null, 'the first month ever reported is the month after this one starts, so no old month is sent late');
eq(reportPeriodDue({ today: '2027-01-02', holidays: BANK, startMonth: '2026-11' }), null, 'nothing on a non-working day before the first working day');
eq(reportPeriodDue({ today: '2027-01-04', holidays: BANK, startMonth: '2026-11' }), '2026-12', 'first working day of January reports December across the year end');
ok(isMonday('2026-11-23') && !isMonday('2026-11-24'), 'Mondays');
eq(monthEndDate('2026-11').toISOString().slice(0, 10), '2026-11-30', 'month end date');

// ---------- a month of data ----------
const inv = (number, date, company, amount, status, paymentDate, consultant, commissionAmount, dueDate, extra) =>
  ({ number, date, dueDate: dueDate || '', company, role: 'Welder', candidateName: 'Cand ' + number, amount, status, paymentDate: paymentDate || '', consultant: consultant || '', commissionAmount: commissionAmount || 0, commissionPaidDate: '', ...(extra || {}) });
const invoices = [
  inv('RS031126', '2026-11-03', 'Acme Ltd', 6100, 'paid', '2026-11-12', 'Ella', 915, '2026-11-17', { candidateName: 'Ann Placed' }),
  inv('RS101126', '2026-11-10', 'Barclays Bank Recruitment', 4700, 'pending', '', 'Dan', 0, '2026-11-24', { candidateName: 'Bob Hired' }),
  inv('RS051026', '2026-10-05', 'Acme Ltd', 8300, 'paid', '2026-10-20', 'Ella', 1245, '2026-10-19'),
  inv('RS201026', '2026-10-20', 'Gamma Ltd', 3100, 'pending', '', '', 0, '2026-11-03'),
  inv('RS150926', '2026-09-15', 'Acme Ltd', 9200, 'paid', '2026-09-30', 'Ella', 1380, '2026-09-29'),
];
const candidates = [
  { id: 'c1', company: 'Acme Ltd', role: 'Welder', name: 'Ann Placed', stage: 'day1', date: '2026-08-20', salary: '30000', invoiceNumber: 'RS150926', startDate: '2026-09-14' },
  { id: 'c2', company: 'Barclays Bank Recruitment', role: 'Fitter', name: 'Bob Offer', stage: 'offer', date: '2026-10-25', salary: '28000', invoiceNumber: '' },
  { id: 'c3', company: 'Barclays Bank Recruitment', role: 'Fitter', name: 'Cat Sub', stage: 'submitted', date: '2026-11-12', salary: '26000-30000' },
];
const roles = [
  { id: 'r2', company: 'Barclays Bank Recruitment', role: 'Fitter', status: 'open', date_opened: '2026-10-20', positions: '1', salary_band: '26000-30000' },
  { id: 'r3', company: 'Gamma Ltd', role: 'CAD Tech', status: 'open', date_opened: '2026-09-25', positions: '1', salary_band: '35k' },
];
const audit = [
  { timestamp: '2026-11-05T10:00:00Z', action: 'stage_changed', entity: 'Bob Offer - Fitter', detail: 'submitted to interview_scheduled' },
  { timestamp: '2026-11-11T10:00:00Z', action: 'stage_changed', entity: 'Bob Offer - Fitter', detail: 'interviewed to offer' },
  { timestamp: '2026-11-13T10:00:00Z', action: 'stage_changed', entity: 'Cat Sub - Fitter', detail: 'applied to submitted' },
];
const activity = [
  { timestamp: '2026-11-12T09:00:00Z', user: 'ella', action: 'candidate_added', company: 'Acme Ltd', role: 'Welder' },
  ...[3, 5, 9, 12, 18].map(d => ({ timestamp: `2026-11-${String(d).padStart(2, '0')}T09:00:00Z`, user: 'ella', action: 'submitted', company: 'Acme Ltd', role: 'Welder' })),
  ...[4, 11].map(d => ({ timestamp: `2026-11-${String(d).padStart(2, '0')}T09:00:00Z`, user: 'ella', action: 'interview_booked', company: 'Acme Ltd', role: 'Welder' })),
  ...[2, 4, 6, 8].map(d => ({ timestamp: `2026-10-${String(d).padStart(2, '0')}T09:00:00Z`, user: 'ella', action: 'submitted', company: 'Acme Ltd', role: 'Welder' })),
];
const comms = [
  ...Array.from({ length: 12 }, (_, i) => ({ timestamp: `2026-11-${String(2 + i).padStart(2, '0')}T09:00:00Z`, user: 'ella', channel: 'call', summary: i < 2 ? 'Cold call - spoke to them' : 'No answer', company: 'Zeta' })),
  { timestamp: '2026-11-03T09:00:00Z', user: 'ella', channel: 'email', summary: 'Intro', company: 'Zeta' },
];
const employees = [{ name: 'Ella Pietrzak', role: 'Consultant', salary: '26000', pensionPct: '3', commissionPct: '15', startDate: '2026-09-01', endDate: '', pensionOnComm: true }];
const base = {
  invoices, candidates, roles, audit, activity, comms, interviews: [], placements: [], employees, adSpend: [],
  fin: { manualAd: 0, overheads: 200, payrollCutoff: '' },
  kpiTargets: [{ quarter: 'Q4 2026', targetRoles: 4, targetNewClients: 3, targetAvgFillSpeedDays: 30, owner: 'ella' }, { quarter: 'Q4 2026', targetRoles: 6, targetNewClients: 4, targetAvgFillSpeedDays: 30, owner: '' }],
  clientFirstSeen: [{ date: '2026-11-04', name: 'Barclays Bank Recruitment' }], otherSales: [], settings: {}, snapshots: {}, vatMarkers: {},
  bank: { connected: true, mode: 'live', balance: { amount: 14250, at: '2026-12-02T06:00:00Z' }, rows: [], settings: { cash_floor: '2000' }, status: {} },
};
const NOW = new Date('2026-12-02T07:00:00Z');

// ---------- the owner report equals the KPI screen ----------
const kMonth = computeOwnerKpi({ ...base, now: monthEndDate('2026-11') });
const kNow = computeOwnerKpi({ ...base, now: NOW });
const screenAtMonthEnd = computeOwnerKpi({ ...base, now: new Date('2026-11-30T12:00:00Z') }); // what KPI Reporting shows with ?asOf=2026-11-30
eq(kMonth.money.invoiced.month, screenAtMonthEnd.money.invoiced.month, 'the report month equals the screen as at month end');
eq([kMonth.money.invoiced.month.now, kMonth.money.invoiced.month.before], [10800, 11400], 'November invoiced 6100 + 4700, October 8300 + 3100');
eq(kMonth.money.paid.month.now, 6100, 'November paid');
const payroll = { status: 'sent', monthName: 'November 2026', payDate: '2026-11-30', sentAt: '2026-11-27', salary: 2166.67, commission: 915, pension: 92.45, gross: 3081.67, employerCost: 3174.12 };
const snap = buildOwnerSnapshot({ period: '2026-11', kMonth, kNow, payroll, generatedAt: '2026-12-02T07:00:00.000Z', asAt: '2026-12-02' });
eq(snap.headline.invoiced, kMonth.money.invoiced.month, 'snapshot invoiced equals the KPI screen');
eq(snap.headline.paid, kMonth.money.paid.month, 'snapshot paid equals the KPI screen');
eq(snap.money.overdue, kNow.money.overdue, 'snapshot overdue equals the KPI screen');
eq(snap.money.outstanding, kNow.money.outstanding, 'snapshot unpaid equals the KPI screen');
eq(snap.cash.balance, kNow.bank.balance, 'snapshot balance equals the bank panel');
eq(snap.cash.lowest, kNow.bank.forecast.lowest, 'snapshot forecast low point equals the bank panel');
eq(snap.costs.profitYtd, kNow.cost.profitYtd, 'snapshot profit equals the cost section');
eq(snap.pipeline.atRisk, kNow.pipeline.atRisk, 'roles at risk equal the pipeline section');
const md = ownerReportMarkdown(snap), mail = ownerReportEmail(snap);
const g = v => '£' + Math.round(v).toLocaleString('en-GB');
ok(md.includes(g(kMonth.money.invoiced.month.now)) && md.includes(g(kNow.money.overdue.now)) && md.includes(g(kNow.bank.balance)), 'the PDF text shows the same figures as the screen');
ok(mail.text.includes(g(kMonth.money.invoiced.month.now)) && mail.text.includes(g(kNow.bank.balance)), 'the email summary shows the same figures as the screen');
for (const h of ['Headline numbers', 'Money', 'Cash position and 90 day forecast', 'Tax reserve', 'Pipeline and roles at risk', 'Clients', 'Costs and margin', 'Payroll', 'Team performance', 'Three focus points']) ok(md.includes('## ' + h), 'owner report has the section: ' + h);
eq(snap.focus.length, 3, 'exactly three focus points');
ok(!NO_DASH.test(md) && !NO_DASH.test(mail.text) && !NO_DASH.test(mail.subject), 'no em dash or en dash in the owner report');
// a frozen snapshot survives a round trip through storage and renders the same
eq(ownerReportMarkdown(JSON.parse(JSON.stringify(snap))), md, 'a stored snapshot renders identically when re-opened');
// bank not connected: says so, no invented figure
const kOff = computeOwnerKpi({ ...base, bank: undefined, now: NOW });
const snapOff = buildOwnerSnapshot({ period: '2026-11', kMonth, kNow: kOff, payroll: { status: 'unknown', monthName: 'November 2026' }, generatedAt: 'x', asAt: '2026-12-02' });
ok(/not connected|STARLING_TOKEN/i.test(ownerReportMarkdown(snapOff)) && !/Balance at the bank/.test(ownerReportMarkdown(snapOff)), 'no bank means no cash figure');
// focus points follow the numbers
const fp = focusPoints({ ...snap, money: { ...snap.money, overdue: { now: 5200 }, overdueInvoices: [{ company: 'Gamma Ltd', number: 'RS201026', daysOverdue: 29, amount: 3100 }] } });
ok(/5,200/.test(fp[0]) && /Gamma Ltd/.test(fp[0]), 'the overdue focus point names the amount and the oldest client');

// ---------- weekly brief ----------
const wf = weeklyFacts({ today: '2026-12-07', k: kNow, invoices, audit, roles, tasks: [{ user: 'ella', title: 'Call Zeta', dueDate: '2026-12-01' }], outboxPending: 2, payrollBanner: 'Payroll for December is due on 31 December.' });
const wb = weeklyBriefEmail(wf);
ok(/Balance/.test(wb.text) && /Due this week/.test(wb.text) && /NEEDS A DECISION/.test(wb.text) && /Call Zeta/.test(wb.text) && /2 emails waiting/.test(wb.text), 'weekly brief has cash, money, pipeline, tasks and decisions');
ok(!NO_DASH.test(wb.text) && !NO_DASH.test(wb.subject), 'no dashes in the weekly brief');

// ---------- Ella's report ----------
const myNov = computeMyKpi({ ...base, now: monthEndDate('2026-11') }, 'ella');
const wins = [{ company: 'Acme Ltd', role: 'Welder', candidate: 'Ann Placed' }, { company: 'Barclays Bank Recruitment', role: 'Bank Teller', candidate: 'Bob Hired' }];
const reviews = [{ kind: 'Mid-probation review', due_date: '2026-11-30', status: 'Due', objectives: 'Reach four placements and keep a daily call log', manager_notes: 'PRIVATE MANAGER NOTE' }, { kind: 'Final probation review', due_date: '2026-12-18', status: 'Upcoming', objectives: 'Hit the commission threshold' }];
const es = buildEllaSnapshot({ period: '2026-11', my: myNov, wins, reviews, firstName: 'Ella', generatedAt: '2026-12-02T07:00:00.000Z' });
const clean = assertEllaClean(es, '');
ok(clean.markdown.includes('## What went well') && clean.markdown.includes('## Your activity') && clean.markdown.includes('## Where to improve') && clean.markdown.includes('## Focus for next month') && clean.markdown.includes('## Reviews and goals'), 'Ella report has her sections');
ok(/Ann Placed/.test(clean.markdown) && /Barclays Bank Recruitment/.test(clean.markdown), 'wins are named, and a client with Bank in its name does not trip the scan');
ok(!/PRIVATE MANAGER NOTE/.test(clean.markdown + JSON.stringify(es)), 'manager notes are never carried into her report');
ok(/See People > Reviews/.test(JSON.stringify(es.reviews)), 'a review objective that mentions commission is not printed, she is pointed to her review page');
const everything = clean.markdown + '\n' + clean.email.text + '\n' + clean.email.subject + '\n' + JSON.stringify(es);
ok(!/£/.test(everything), 'no pound sign anywhere in Ella\'s report, email or stored snapshot');
const restricted = [10800, 11400, 6100, 4700, 8300, 3100, 915, 1245, 1380, 14250, 26000, 2000, 3174, 3081, 92.45].map(String);
restricted.forEach(v => ok(!new RegExp('(^|[^\\d.])' + v.replace('.', '\\.') + '([^\\d]|$)').test(everything), 'restricted figure ' + v + ' is not in Ella\'s report'));
eq(ellaViolations(clean.markdown, [...wins.flatMap(w => [w.company, w.role, w.candidate]), ...reviews.map(r => r.kind)]), [], 'the generated report passes the scan');
for (const w of ['commission', 'salary', 'pension', 'payroll', 'margin', 'profit', 'tax', 'bank', 'revenue', 'invoice', 'fee', 'cost', 'cash', '£300', 'VAT']) ok(ellaViolations(`Your ${w} this month`).length > 0, 'the scan catches: ' + w);
ok(ellaViolations('Great month. Keep the calls going.').length === 0, 'plain coaching text passes');
// Daniel Brown's own note is held to the same rule
let blocked = null; try { assertEllaClean(es, 'Well done. Your commission this month was strong.'); } catch (e) { blocked = e; }
ok(blocked && blocked.restricted.includes('commission'), 'a note that mentions commission is refused');
blocked = null; try { assertEllaClean(es, 'You brought in £6,100 for Acme.'); } catch (e) { blocked = e; }
ok(blocked && blocked.restricted.includes('£'), 'a note with a pound figure is refused');
const withNote = assertEllaClean(es, 'Really good effort on the calls this month.\n\nLet us talk through the submissions on Friday.');
ok(/Really good effort/.test(withNote.markdown) && /A note from Daniel/.test(withNote.markdown) && /Really good effort/.test(withNote.email.text), 'a clean note appears in the PDF text and the email');
ok(!NO_DASH.test(everything) && !NO_DASH.test(withNote.markdown), 'no dashes in Ella\'s report');
// the numbers mean something: ratios and what to improve come from her figures
eq(es.activity.find(a => a.key === 'submissions').now, 5, 'her 5 submissions in November');
eq(es.activity.find(a => a.key === 'calls').now, 12, 'her 12 calls');
ok(!es.improve.some(x => /spoke to someone/i.test(x)), 'no coaching on calls that reached someone (not measured since build 66.3)');
ok(!/spoke to someone|reached someone/i.test(ellaReportEmail(es, '').text + ellaReportMarkdown(es)), 'the report holds no spoke to someone figure');
ok(es.improve.length >= 1 && es.focus.length >= 2 && es.focus.length <= 3, 'improvement points and a focus for next month');
ok(es.highlights.some(x => /Placement: Ann Placed/.test(x)), 'wins listed');
// a fresh report for a quiet month still renders and still passes
const quiet = buildEllaSnapshot({ period: '2026-11', my: computeMyKpi({ ...base, activity: [], comms: [], now: monthEndDate('2026-11') }, 'ella'), wins: [], reviews: [], firstName: 'Ella', generatedAt: 'x' });
ok(/No calls or emails were logged/.test(assertEllaClean(quiet, '').markdown), 'a month with no logged activity says so');

// ---------- commission is in the 90 day cash forecast ----------
const open = [{ number: 'F1', company: 'Prompt Co', amount: 6000, status: 'pending', dueDate: '2026-12-10', date: '2026-11-26' }];
const scores = { 'prompt co': { invoices: 3, avgDaysLate: 0 } };
const plain = cashForecast({ balance: 20000, openInvoices: open, scores, recurring: [], monthlyPayroll: 3000, todayISO: '2026-12-02', floor: 0 });
const withCommission = cashForecast({ balance: 20000, openInvoices: open, scores, recurring: [], monthlyPayroll: 3000, todayISO: '2026-12-02', floor: 0,
  commissionItems: [{ number: 'F1', company: 'Prompt Co', amount: 927, paid: false, paidDate: '' }, { number: 'RS031126', company: 'Acme Ltd', amount: 942.45, paid: true, paidDate: '2026-11-12' }] });
const comm = withCommission.events.filter(e => /Commission/.test(e.label));
ok(comm.length >= 1, 'commission appears as a cash out');
eq(plain.expectedOut + 927 * 0.95 + 942.45 > withCommission.expectedOut - 0.1 && plain.expectedOut + 927 * 0.95 + 942.45 < withCommission.expectedOut + 1, true, 'commission adds the weighted amounts to money out');
eq(comm[0].date, '2026-12-31', 'commission is paid in the December payroll');
eq(Math.round(-comm[0].amount * 100) / 100, Math.round((927 * 0.95 + 942.45) * 100) / 100, 'an unpaid invoice counts at the weight the forecast trusts the client, an already paid one in full');
// the cut-off day pushes a late paid invoice into the next payroll
const cut = cashForecast({ balance: 20000, openInvoices: [], scores: {}, recurring: [], monthlyPayroll: 3000, todayISO: '2026-12-02', floor: 0, commissionCutoffDay: '15',
  commissionItems: [{ number: 'A', company: 'A', amount: 100, paid: true, paidDate: '2026-12-10' }, { number: 'B', company: 'B', amount: 200, paid: true, paidDate: '2026-12-20' }] });
eq(cut.events.filter(e => /Commission/.test(e.label)).map(e => [e.date, -e.amount]), [['2026-12-31', 100], ['2027-01-31', 200]], 'cut-off day 15: 10 Dec is paid in December, 20 Dec rolls to January');
// commission only for people on payroll
const kc = computeOwnerKpi({ ...base, now: NOW, invoices: [...invoices, inv('RS991126', '2026-11-20', 'Acme Ltd', 5000, 'paid', '2026-11-25', 'Ella', 750), inv('RS992226', '2026-11-21', 'Acme Ltd', 5000, 'paid', '2026-11-25', 'Dan', 750)] });
const kcl = kc.bank.forecast.events.filter(e => /Commission/.test(e.label)).reduce((s, e) => s - e.amount, 0);
ok(kcl > 0, 'owner view forecast includes commission for the person on payroll');
ok(Math.abs(kcl - (915 + 1245 + 1380 + 750) * 1.03) < 0.1, 'every unpaid commission of the person on payroll, with 3 percent employer pension on top, goes out in the December payroll (got ' + kcl + ')');
const kd = computeOwnerKpi({ ...base, now: NOW, invoices: [inv('RS992226', '2026-11-21', 'Acme Ltd', 5000, 'paid', '2026-11-25', 'Dan', 750)] });
eq(kd.bank.forecast.events.filter(e => /Commission/.test(e.label)).length, 0, 'the director takes dividends, so his commission is not in the forecast');
// build 67: targets in Ella's report are counts only and pass the money guard
const withT = buildEllaSnapshot({ period: '2026-11', my: myNov, wins, reviews, monthTargets: [{ key: 'submissions', done: 12, target: 10.4 }, { key: 'calls', done: 30, target: 60 }], firstName: 'Ella', generatedAt: 'x' });
const mdT = ellaReportMarkdown(withT, '');
ok(/Your targets for/.test(mdT) && /Candidates submitted \| 12 \| 10.4 \| Met/.test(mdT) && /50% of target/.test(mdT), 'Ella report shows month targets with done, target and result');
ok(assertEllaClean(withT, '').markdown.length > 0, 'report with targets passes the money guard');
ok(!/Your targets for/.test(ellaReportMarkdown(es, '')), 'no targets section when no goal is set');
// the tidy helper
eq(tidy('a — b – c -- d'), 'a - b - c - d', 'dashes become a plain hyphen');

console.log(`reports: all ${n} checks passed`);
