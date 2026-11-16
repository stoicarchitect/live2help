// Build 62: checks for the KPI owner view sums. Run with: node scripts/test-kpi-owner.mjs
import assert from 'node:assert/strict';
import { computeOwnerKpi, computeMyKpi, vatWatch, vatAlertsDue, vatAlertText, salaryValue, empCostBetween, spendOccurrences } from '../kpi-owner.js';

const now = new Date('2026-11-16T12:00:00Z');
const inv = (number, date, company, amount, status, paymentDate, consultant, commissionAmount, dueDate) =>
  ({ number, date, dueDate: dueDate || '', company, role: 'Welder', candidateName: 'Cand ' + number, amount, status, paymentDate: paymentDate || '', consultant: consultant || '', commissionAmount: commissionAmount || 0, commissionPaidDate: '' });
const invoices = [
  inv('RS011126', '2026-11-03', 'Acme Ltd', 6000, 'paid', '2026-11-10', 'Ella', 600),
  inv('RS101126', '2026-11-10', 'Beta Ltd', 4500, 'pending', '', 'Dan', 0, '2026-11-24'),
  inv('RS051026', '2026-10-05', 'Acme Ltd', 8000, 'paid', '2026-10-20', 'Ella', 800),
  inv('RS201026', '2026-10-20', 'Gamma Ltd', 3000, 'pending', '', '', 0, '2026-11-03'),   // overdue by 13 days
  inv('RS150926', '2026-09-15', 'Acme Ltd', 9000, 'paid', '2026-09-30', 'Ella', 900),
  inv('RS010625', '2025-06-01', 'Old Co', 5000, 'paid', '2025-06-20', 'Dan', 0),           // outside every current window
  inv('RS011225', '2025-12-01', 'Delta Ltd', 2000, 'paid', '2025-12-15', 'Dan', 0),         // inside the rolling 12 months only
];
const candidates = [
  { id: 'c1', company: 'Acme Ltd', role: 'Welder', name: 'Ann Placed', stage: 'day1', date: '2026-08-20', salary: '30000', invoiceNumber: 'RS150926', startDate: '2026-09-14' },
  { id: 'c2', company: 'Beta Ltd', role: 'Fitter', name: 'Bob Offer', stage: 'offer', date: '2026-10-25', salary: '£28k', invoiceNumber: '' },
  { id: 'c3', company: 'Beta Ltd', role: 'Fitter', name: 'Cat Sub', stage: 'submitted', date: '2026-11-12', salary: '26000-30000' },
  { id: 'c4', company: 'Gamma Ltd', role: 'CAD Tech', name: 'Dee Int', stage: 'interviewed', date: '2026-10-01', salary: '' },
  { id: 'c5', company: 'Gamma Ltd', role: 'CAD Tech', name: 'Eve Rej', stage: 'rejected', date: '2026-10-02', salary: '' },
  { id: 'c6', company: 'Acme Ltd', role: 'Welder', name: 'Test Person', stage: 'offer', date: '2026-11-01', salary: '99000' }, // test record, ignored
];
const roles = [
  { id: 'r1', company: 'Acme Ltd', role: 'Welder', status: 'filled', date_opened: '2026-08-01', date_closed: '2026-09-14', positions: '1', salary_band: '28-32k' },
  { id: 'r2', company: 'Beta Ltd', role: 'Fitter', status: 'open', date_opened: '2026-10-20', positions: '1', salary_band: '26000-30000', fee_percent: '' },
  { id: 'r3', company: 'Gamma Ltd', role: 'CAD Tech', status: 'open', date_opened: '2026-09-25', positions: '1', salary_band: '35k' },
];
const audit = [
  { timestamp: '2026-08-25T10:00:00Z', action: 'stage_changed', entity: 'Ann Placed - Welder', detail: 'applied to submitted' },
  { timestamp: '2026-09-01T10:00:00Z', action: 'stage_changed', entity: 'Ann Placed - Welder', detail: 'submitted to interview_scheduled' },
  { timestamp: '2026-09-08T10:00:00Z', action: 'stage_changed', entity: 'Ann Placed - Welder', detail: 'interviewed to offer' },
  { timestamp: '2026-10-28T10:00:00Z', action: 'stage_changed', entity: 'Bob Offer - Fitter', detail: 'applied to submitted' },
  { timestamp: '2026-11-05T10:00:00Z', action: 'stage_changed', entity: 'Bob Offer - Fitter', detail: 'submitted to interview_scheduled' },
  { timestamp: '2026-11-11T10:00:00Z', action: 'stage_changed', entity: 'Bob Offer - Fitter', detail: 'interviewed to offer' },
  { timestamp: '2026-11-13T10:00:00Z', action: 'stage_changed', entity: 'Cat Sub - Fitter', detail: 'applied to submitted' },
  { timestamp: '2026-10-06T10:00:00Z', action: 'stage_changed', entity: 'Dee Int - CAD Tech', detail: 'applied to submitted' },
  { timestamp: '2026-10-12T10:00:00Z', action: 'stage_changed', entity: 'Dee Int - CAD Tech', detail: 'interview_scheduled to interviewed' },
  { timestamp: '2026-10-07T10:00:00Z', action: 'stage_changed', entity: 'Eve Rej - CAD Tech', detail: 'applied to rejected' },
];
const activity = [
  { timestamp: '2026-11-12T09:00:00Z', user: 'ella', action: 'candidate_added', company: 'Beta Ltd', role: 'Fitter' },
  { timestamp: '2026-11-13T09:00:00Z', user: 'ella', action: 'submitted', company: 'Beta Ltd', role: 'Fitter' },
  { timestamp: '2026-10-06T09:00:00Z', user: 'ella', action: 'submitted', company: 'Gamma Ltd', role: 'CAD Tech' },
  { timestamp: '2026-11-04T09:00:00Z', user: 'dan', action: 'interview_booked', company: 'Beta Ltd', role: 'Fitter' },
];
const comms = [
  { timestamp: '2026-11-02T09:00:00Z', user: 'ella', channel: 'call', summary: 'Cold call - spoke to them', company: 'Zeta' },
  { timestamp: '2026-11-03T09:00:00Z', user: 'ella', channel: 'email', summary: 'Intro', company: 'Zeta' },
  { timestamp: '2026-10-03T09:00:00Z', user: 'ella', channel: 'call', summary: 'No answer', company: 'Zeta' },
];
const placements = [
  { id: 'p1', name: 'Ann Placed', company: 'Acme Ltd', role: 'Welder', salary: '30000', startDate: '2026-09-14', invoiceNumber: 'RS150926', guaranteeWeeks: 12, guaranteeEnd: '2026-12-07', daysLeft: 21, status: 'active' },
  { id: 'p2', name: 'Old Hire', company: 'Old Co', role: 'Welder', salary: '25000', startDate: '2025-06-01', invoiceNumber: 'RS010625', guaranteeWeeks: 12, guaranteeEnd: '2025-08-24', daysLeft: -449, status: 'active' },
];
const employees = [{ name: 'Ella Pietrzak', role: 'Consultant', salary: '26000', pensionPct: '3', startDate: '2026-09-01', endDate: '', pensionOnComm: true }];
const adSpend = [
  { id: 'a1', date: '2026-10-21', channel: 'Indeed', role: 'Fitter', company: 'Beta Ltd', amount: '120', frequency: '', applies_to: 'specific' },
  { id: 'a2', date: '2026-09-01', channel: 'LinkedIn', role: '', company: '', amount: '50', frequency: 'monthly', end_date: '', applies_to: 'general' },
  { id: 'a3', date: '2026-11-02', channel: 'Board', role: '', company: '', amount: '100', frequency: '', applies_to: 'open_roles' },
];
const base = {
  now, invoices, candidates, roles, audit, activity, comms, interviews: [], placements, employees, adSpend,
  fin: { manualAd: 0, overheads: 200 }, kpiTargets: [{ quarter: 'Q4 2026', targetRoles: 4, targetNewClients: 3, targetAvgFillSpeedDays: 30, owner: 'ella' }, { quarter: 'Q4 2026', targetRoles: 6, targetNewClients: 4, targetAvgFillSpeedDays: 30, owner: '' }],
  clientFirstSeen: [{ date: '2026-11-04', name: 'Beta Ltd' }, { date: '2026-10-02', name: 'Gamma Ltd' }, { date: '2026-08-01', name: 'Acme Ltd' }],
  otherSales: [{ date: '2026-10-10', amount: '49', kind: 'Talent Suite order' }, { date: '2025-01-01', amount: '500', kind: 'old' }],
  settings: {}, snapshots: { '2026-11': { weightedForecast: 3000, outstanding: 3000, overdue: 0, openRoles: 2 } },
};
const k = computeOwnerKpi(base);

/* 1. Money matches a hand check of the invoice list */
assert.equal(k.money.invoiced.month.now, 10500);            // 6000 + 4500 in November
assert.equal(k.money.invoiced.month.before, 11000);         // 8000 + 3000 in October
assert.equal(k.money.invoiced.month.dir, 'down');
assert.equal(k.money.invoiced.quarter.now, 21500);          // Oct + Nov
assert.equal(k.money.invoiced.quarter.before, 9000);        // Jul to Sep
assert.equal(k.money.invoiced.ytd.now, 30500);              // 2026 only
assert.equal(k.money.paid.month.now, 6000);
assert.equal(k.money.paid.month.before, 8000);
assert.equal(k.money.paid.ytd.now, 23000);
assert.equal(k.money.outstanding.now, 7500);
assert.equal(k.money.overdue.now, 3000);
assert.equal(k.money.overdueInvoices.length, 1);
assert.equal(k.money.overdueInvoices[0].daysOverdue, 13);
assert.equal(k.money.avgFee, 6100);                         // 30500 over 5 invoices
assert.equal(k.money.revenuePerClient, round(30500 / 3));
assert.equal(k.money.avgDaysToPay, Math.round((7 + 15 + 15 + 14) / 4));
assert.equal(k.money.debtorDays, Math.round(7500 / 32500 * 365));
assert.equal(k.money.bank.connected, false);                // placeholder until build 63, never an invented number
function round(n) { return Math.round(n * 100) / 100; }

/* 2. Forecast follows the Forecast tab rules: one open position, most advanced candidate counted */
// Beta Fitter: Bob at offer, 28000 at 15% = 4200, weight 75%. Cat is not counted (one position).
// Gamma CAD Tech: Dee interviewed, no salary so band 35000 at 20% = 7000, weight 40%.
assert.equal(k.money.forecast.bestCase, 11200);
assert.equal(k.money.forecast.weighted, round(4200 * 0.75 + 7000 * 0.4));
assert.equal(k.money.forecast.openingWeighted, 3000);
assert.equal(salaryValue('£28k'), 28000);
assert.equal(salaryValue('26000-30000'), 28000);
assert.equal(salaryValue('£13.50 per hour', { hourly: true, hours: 40 }), 28080);

/* 3. Pipeline */
assert.equal(k.pipeline.openRoles.now, 2);
const gamma = k.pipeline.roles.find(r => r.company === 'Gamma Ltd');
assert.equal(gamma.atRisk, true);                            // last activity 12 Oct, well over 7 days
const beta = k.pipeline.roles.find(r => r.company === 'Beta Ltd');
assert.equal(beta.atRisk, false);                            // submitted 13 Nov
assert.equal(k.pipeline.atRisk, 1);
assert.equal(computeOwnerKpi({ ...base, settings: { role_stale_days: '60' } }).pipeline.atRisk, 0);
assert.equal(k.pipeline.conversion.submitted, 4);            // Ann, Bob, Cat, Dee (Eve went straight to rejected)
assert.equal(k.pipeline.conversion.interviewed, 3);
assert.equal(k.pipeline.conversion.offered, 2);
assert.equal(k.pipeline.conversion.submissionToInterviewPct, 75);
assert.equal(k.pipeline.conversion.interviewToOfferPct, 67);
assert.equal(k.pipeline.timeToFillDays.quarter, 22);         // Bob: role opened 20 Oct, offer 11 Nov
assert.equal(k.pipeline.rolesFilled.month.now, 1);

/* 4. Clients: concentration and the guarantee watch */
assert.equal(k.clients.newClients.month.now, 1);
assert.equal(k.clients.newClients.month.before, 1);
assert.equal(k.clients.concentration.topClient, 'Acme Ltd');
assert.equal(k.clients.concentration.topSharePct, Math.round(23000 / 32500 * 1000) / 10);
assert.equal(k.clients.concentration.warn, true);            // 70.8% is above 40%
assert.equal(computeOwnerKpi({ ...base, settings: { concentration_warn_pct: '80' } }).clients.concentration.warn, false);
assert.equal(k.clients.guaranteeWatch.count, 1);             // the placement that started 2 months ago
assert.equal(k.clients.guaranteeWatch.placements[0].name, 'Ann Placed');
assert.equal(k.clients.guaranteeWatch.placements[0].daysLeft, 21);
assert.equal(k.clients.guaranteeWatch.revenueAtRisk, 9000);  // its invoice

/* 5. Cost: the same sums as the old Business Health block */
const ec = empCostBetween(employees[0], new Date('2026-01-01T00:00:00Z'), new Date('2026-11-16T00:00:00Z'));
assert.equal(ec.days, 55);                                    // working days 1 Sep to 16 Nov 2026
assert.equal(ec.salary, 5500);                                // 26000 / 260 x 55
assert.equal(ec.pension, 165);
const comm = 600 + 800 + 900, commPension = round(comm * 0.03);
assert.equal(k.cost.commissionYtd, comm);
assert.equal(k.cost.teamCostYtd, round(5500 + 165 + comm + commPension));
assert.equal(spendOccurrences(adSpend, '2026-01-01', '2026-11-16').length, 5); // 120, 100 and three monthly 50s
assert.equal(k.cost.adSpendYtd, 370);
assert.equal(k.cost.profitYtd, round(30500 - k.cost.teamCostYtd - 370));
assert.equal(k.cost.hiresYtd, 2);
assert.equal(k.cost.costPerHire, round((k.cost.teamCostYtd + 370) / 2));
assert.equal(k.cost.adSpendByRole.find(r => r.role === 'Fitter').spend, 170);   // 120 plus half of the 100 split across two open roles
assert.equal(k.cost.recurring.totalPerMonth, round(26000 * 1.03 / 12 + 50 + 200));
assert.equal(k.staff.people[0].revenueYtd, 23000);
assert.equal(k.staff.people[0].placementsYtd, 3);
assert.equal(k.staff.people[0].activity.calls.now, 1);
assert.equal(k.staff.people[0].target.targetRoles, 4);
assert.equal(k.staff.others.find(o => o.name === 'Dan').revenueYtd, 4500);

/* 6. VAT threshold watch and its alerts */
assert.equal(k.vat.turnover12m, 32549);                       // 32500 invoiced plus 49 Talent Suite
assert.equal(k.vat.threshold, 90000);
assert.equal(k.vat.status, 'ok');
assert.deepEqual(vatAlertsDue(k.vat, {}).send, []);
const low = computeOwnerKpi({ ...base, settings: { vat_threshold: '38000' } }).vat; // lowered threshold: 85.7%
assert.equal(low.status, 'warn');
assert.deepEqual(vatAlertsDue(low, {}).send, [80]);           // fires at 80, not yet at 90
assert.deepEqual(vatAlertsDue(low, { 80: '2026-11-16' }).send, []);           // and only once
assert.deepEqual(vatAlertsDue(computeOwnerKpi({ ...base, settings: { vat_threshold: '35000' } }).vat, { 80: '2026-11-16' }).send, [90]);
assert.deepEqual(vatAlertsDue(k.vat, { 80: '2026-01-01' }).clear, [80]);      // back under the level, marker cleared
assert.match(vatAlertText(low, 80), /85\.7% of the VAT registration threshold of £38,000/);
assert.equal(vatWatch(95000, {}).status, 'over');
assert.equal(k.vat.monthly.length, 12);
assert.equal(k.vat.monthly[11].amount, 10500);

/* 7. What changed: plain English, five at most plus the part-month note */
assert.ok(k.changes.length >= 3 && k.changes.length <= 6);
assert.ok(k.changes.some(c => /Overdue invoices rose from £0 to £3,000/.test(c.text)));
assert.ok(k.changes.some(c => /^Cash received from clients fell from £8,000 to £6,000 \(-25%\)$/.test(c.text)));
assert.ok(!JSON.stringify(k).includes('—'));             // no em dashes anywhere

/* 8. Ella's view carries no money at all */
const mine = computeMyKpi(base, 'ella');
assert.equal(mine.activity.submissions.now, 1);
assert.equal(mine.activity.submissions.before, 1);
assert.equal(mine.activity.calls.now, 1);
assert.equal(mine.placements.ytd, 3);
assert.equal(mine.target.targetRoles, 4);
const flat = JSON.stringify(mine).toLowerCase();
['revenue', 'amount', 'commission', 'salary', 'cost', 'margin', 'profit', 'invoice', 'fee', 'bank', 'payroll', 'vat', 'pension', 'turnover', '£'].forEach(w => assert.ok(!flat.includes(w), 'Ella response must not contain ' + w));
const moneyValues = new Set([6000, 4500, 8000, 3000, 9000, 26000, 600, 800, 900, 23000, 30500, 10500]);
(function walk(v) { if (typeof v === 'number') assert.ok(!moneyValues.has(v), 'money value leaked: ' + v); else if (v && typeof v === 'object') Object.values(v).forEach(walk); })(mine);

console.log('kpi-owner: all checks passed');
