// Build 64 tests: node scripts/test-payroll.mjs
import assert from 'assert';
import {
  londonToday, isWorkingDay, shiftWorkingDays, lastWorkingDay, readPayrollSettings, validOverride, payDateFor, reminderDates,
  reminderStage, payrollWatch, currentPayrollMonth, bannerFor, reminderFor, payrollPack, clawbackCheck, payrollBankCheck,
  payrollEmail, runRecords, nextMonth, prevMonth,
} from '../payroll.js';
import { computeMyKpi } from '../kpi-owner.js';

let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; }; const eq = (a, b, m) => { assert.deepStrictEqual(a, b, m); n++; };
const BANK = new Set(['2026-08-31', '2026-12-25', '2026-12-28', '2027-01-01', '2027-03-26', '2027-03-29', '2027-05-03', '2027-05-31', '2027-08-30', '2027-12-27', '2027-12-28']);

// ---------- London time ----------
eq(londonToday('2026-06-30T23:30:00Z'), '2026-07-01', 'BST: 23:30 UTC on 30 June is already 1 July in London');
eq(londonToday('2026-12-31T23:30:00Z'), '2026-12-31', 'GMT: 23:30 UTC is still 31 Dec in London');
eq([nextMonth('2026-12'), prevMonth('2027-01')], ['2027-01', '2026-12'], 'month arithmetic across the year end');

// ---------- pay dates ----------
eq(lastWorkingDay('2026-11', BANK), '2026-11-30', 'Nov 2026 ends on a Monday');
eq(lastWorkingDay('2027-01', BANK), '2027-01-29', 'Jan 2027 ends on a Sunday: Friday 29th');
eq(lastWorkingDay('2027-10', BANK), '2027-10-29', 'Oct 2027 ends on a Sunday');
eq(lastWorkingDay('2026-08', BANK), '2026-08-28', 'Aug 2026 ends on a bank holiday Monday: Friday 28th');
eq(lastWorkingDay('2027-05', BANK), '2027-05-28', 'May 2027 ends on a bank holiday Monday');
ok(!isWorkingDay('2026-12-25', BANK) && isWorkingDay('2026-12-31', BANK), 'Christmas is not a working day, 31 Dec 2026 is');
eq(shiftWorkingDays('2027-12-31', -3, BANK), '2027-12-24', 'three working days before 31 Dec 2027 skips the weekend and both bank holidays');
eq(shiftWorkingDays('2027-01-04', -1, BANK), '2026-12-31', 'the working day before Mon 4 Jan 2027 is 31 Dec (1 Jan bank holiday, weekend)');
eq(reminderDates('2026-11-30', BANK), { threeDays: '2026-11-25', dayBefore: '2026-11-27', onDay: '2026-11-30' }, 'Nov 2026 reminders skip the weekend');
eq(reminderDates('2027-01-29', BANK), { threeDays: '2027-01-26', dayBefore: '2027-01-28', onDay: '2027-01-29' }, 'Jan 2027 reminders');
eq(reminderDates('2026-12-31', BANK), { threeDays: '2026-12-24', dayBefore: '2026-12-30', onDay: '2026-12-31' }, 'Dec 2026 reminders skip Christmas and Boxing Day substitute');

// ---------- settings and overrides ----------
const settings = readPayrollSettings([{ id: 'start_month', value: '2026-11' }, { id: 'override:2026-12', value: '2027-01-01' }, { id: 'override:bad', value: 'x' }, { id: 'override:2027-02', value: '' }]);
eq(settings, { startMonth: '2026-11', overrides: { '2026-12': '2027-01-01' } }, 'settings read, blanks and bad keys ignored');
eq(payDateFor('2026-12', settings, BANK), { date: '2027-01-01', source: 'override' }, 'override wins');
eq(payDateFor('2026-11', settings, BANK), { date: '2026-11-30', source: 'last working day' }, 'default is the last working day');
ok(validOverride('2026-12', '2027-01-01') && validOverride('2026-11', '2026-11-30'), 'the 1st and the last day are valid');
ok(!validOverride('2026-12', '2027-02-01') && !validOverride('2026-12', '2026-12-01'), 'dates far from the month are refused');

// ---------- stages ----------
const st = t => reminderStage(t, '2026-11-30', BANK, false).stage;
eq(['2026-11-24', '2026-11-25', '2026-11-26', '2026-11-27', '2026-11-28', '2026-11-30'].map(st), ['not_yet', 'three_days', 'three_days', 'day_before', 'day_before', 'on_day'], 'stages through the week');
eq(reminderStage('2026-12-03', '2026-11-30', BANK, false), { stage: 'overdue', daysOverdue: 3 }, 'overdue counts days');
eq(reminderStage('2026-12-03', '2026-11-30', BANK, true).stage, 'sent', 'a sent month never reminds');

// ---------- watch, banner and reminders ----------
{
  let w = payrollWatch({ today: '2026-11-27', settings, bank: BANK, sentMonths: [] });
  eq(w.map(x => x.month), ['2026-11', '2026-12'], 'watches from the start month to next month');
  let cur = currentPayrollMonth(w);
  eq([cur.month, cur.stage], ['2026-11', 'day_before'], 'November is current');
  ok(bannerFor(cur) && /tomorrow/.test(bannerFor(cur).text), 'banner shows the day before');
  const r = reminderFor(cur, '2026-11-27');
  eq([r.key, r.priority], ['payroll-2026-11-day_before', 'High'], 'reminder key is per month and stage');
  // missed: overdue escalates daily, with a new key each day
  w = payrollWatch({ today: '2026-12-02', settings, bank: BANK, sentMonths: [] });
  cur = currentPayrollMonth(w);
  eq([cur.month, cur.stage, cur.daysOverdue], ['2026-11', 'overdue', 2], 'missed November is overdue');
  ok(reminderFor(cur, '2026-12-02').key !== reminderFor(cur, '2026-12-03').key, 'overdue escalates each day');
  eq(bannerFor(cur).level, 'overdue', 'banner turns to overdue');
  // the banner clears only once marked sent
  w = payrollWatch({ today: '2026-12-02', settings, bank: BANK, sentMonths: ['2026-11'] });
  cur = currentPayrollMonth(w);
  eq([cur.month, cur.stage], ['2026-12', 'not_yet'], 'after Mark as sent the next month is shown');
  eq(bannerFor(cur), null, 'no banner after Mark as sent');
  eq(reminderFor(cur, '2026-12-02'), null, 'no reminder for a month not yet due');
  ok(!payrollWatch({ today: '2026-12-31', settings, bank: BANK, sentMonths: ['2026-11', '2026-12'] }).some(x => reminderFor(x, '2026-12-31')), 'no reminders fire for months already sent');
  // December paid on the 1st of January by override
  w = payrollWatch({ today: '2026-12-31', settings, bank: BANK, sentMonths: ['2026-11'] });
  cur = currentPayrollMonth(w);
  eq([cur.month, cur.payDate, cur.stage], ['2026-12', '2027-01-01', 'day_before'], 'override to the 1st: the day before is 31 Dec');
}

// ---------- the payroll pack ----------
const ella = { name: 'Ella Pietrzak', role: 'Consultant', salary: 25000, startDate: '2026-09-28', pensionPct: 3, commissionPct: 15, pensionOnComm: true };
const inv = (number, amount, status, paymentDate, extra = {}) => ({ number, company: 'Acme Ltd', candidateName: 'Test Candidate ' + number, amount, status, paymentDate, consultant: 'Ella', commissionPct: '15', commissionAmount: Math.round(amount * 15) / 100, commissionPaidDate: '', ...extra });
const invoices = [
  inv('RS001', 4000, 'paid', '2026-11-10'),                                     // in
  inv('RS002', 3000, 'paid', '2026-11-29'),                                     // after cut-off 25th -> next month
  inv('RS003', 5000, 'pending', ''),                                            // waiting on client
  inv('RS004', 2000, 'paid', '2026-10-15', { commissionPaidDate: '2026-10-31' }), // already paid out
  inv('RS005', 6000, 'paid', '2026-11-12', { consultant: 'Unassigned' }),       // no consultant
  inv('RS006', 1000, 'paid', '2026-11-05'),                                     // already in the ledger
];
const ledger = [{ id: 'RS006', invoice: 'RS006', employee: 'Ella Pietrzak', amount: '150', payroll_month: '2026-10', status: 'paid' }];
{
  const p = payrollPack({ month: '2026-11', payDate: '2026-11-30', employees: [ella], invoices, ledger, cutoffDay: 25 });
  const e = p.people[0];
  eq(e.salary, 2083.33, 'monthly salary is 25,000 / 12');
  eq(e.lines.map(l => [l.invoice, l.amount]), [['RS001', 600]], 'commission is 15% of the paid invoice, counted once (ledger and paid flag respected)');
  eq(e.later.map(l => l.invoice), ['RS002'], 'paid after the cut-off moves to next month');
  eq([e.waitingCount, e.waitingAmount], [1, 750], 'unpaid invoice is waiting');
  eq(e.pension, 80.5, 'employer pension 3% on salary and commission');
  eq(p.totals, { salary: 2083.33, commission: 600, pension: 80.5, gross: 2683.33, employerCost: 2763.83 }, 'totals and employer cost');
  eq(p.invoices, ['RS001'], 'invoices to flag as paid');
  eq(p.warnings, [], 'no warnings');
  // counted once: after the run, the same invoice never comes back
  const { run, ledger: newLedger } = runRecords(p, { by: 'dan', at: '2026-11-30T10:00:00Z', to: 'payroll@example.com' });
  eq([run.id, run.status, run.gross, run.invoices], ['2026-11', 'sent', '2683.33', 'RS001'], 'run record');
  eq(newLedger.map(l => [l.id, l.amount, l.payroll_month]), [['RS001', '600', '2026-11']], 'ledger record');
  const next = payrollPack({ month: '2026-12', payDate: '2026-12-31', employees: [ella], invoices, ledger: [...ledger, ...newLedger], cutoffDay: 25 });
  eq(next.people[0].lines.map(l => l.invoice), ['RS002'], 'December has RS002 only; RS001 is not counted twice');
  // no cut-off set: the pay date is the cut-off
  const nc = payrollPack({ month: '2026-11', payDate: '2026-11-30', employees: [ella], invoices, ledger });
  eq([nc.cutoff, nc.people[0].lines.map(l => l.invoice)], ['2026-11-30', ['RS001', 'RS002']], 'without a cut-off day, commission up to the pay date');
  // wrong commission on an invoice is flagged, not changed
  const bad = payrollPack({ month: '2026-11', payDate: '2026-11-30', employees: [ella], invoices: [inv('RS009', 1000, 'paid', '2026-11-02', { commissionAmount: 100 })], ledger: [] });
  ok(bad.warnings.length === 1 && bad.people[0].commission === 100, 'a commission that is not 15% is flagged and left as recorded');
  // part month
  const pm = payrollPack({ month: '2026-11', payDate: '2026-11-30', employees: [{ ...ella, startDate: '2026-11-16' }], invoices: [], ledger: [] });
  eq([pm.people[0].partMonth, pm.people[0].activeDays, pm.people[0].salary], [true, 15, 1041.67], 'part month is pro rata by calendar days');
  eq(payrollPack({ month: '2026-11', payDate: '2026-11-30', employees: [{ ...ella, endDate: '2026-10-31' }], invoices, ledger }).people, [], 'a leaver from before the month is not paid');
  // email text
  const em = payrollEmail(p, 'Daniel Brown');
  ok(em.subject === 'Payroll for November 2026' && /RS001/.test(em.body) && /£2,683\.33/.test(em.body) && !/\u2014/.test(em.body), 'email text has the invoice and total, no em dash');
}

// ---------- clawback ----------
{
  const placements = [{ invoiceNumber: 'RS001', company: 'Acme Ltd', name: 'Test Candidate RS001', guaranteeEnd: '2027-01-15', status: 'active' }, { invoiceNumber: 'RS006', company: 'Acme Ltd', name: 'Test Candidate RS006', guaranteeEnd: '2026-11-01', status: 'completed' }];
  const p = payrollPack({ month: '2026-11', payDate: '2026-11-30', employees: [ella], invoices, ledger, cutoffDay: 25 });
  eq(clawbackCheck({ pack: p, employees: [ella], hrEmployees: [{ full_name: 'Elzbieta Pietrzak', known_as: 'Ella', status: 'Active' }], ledger, placements, today: '2026-11-27', bank: BANK, settings }), [], 'no notice, no clawback flag');
  const leaving = { ...ella, endDate: '2026-12-15' };
  const f = clawbackCheck({ pack: p, employees: [leaving], hrEmployees: [], ledger, placements, today: '2026-11-27', bank: BANK, settings });
  eq([f.length, f[0].finalPayDate, f[0].rows.map(r => r.invoice)], [1, '2027-01-01', ['RS001']], 'in notice: flags commission still inside its guarantee, nothing deducted');
  ok(/Nothing has been deducted/.test(f[0].text), 'flag says nothing was deducted');
  eq(clawbackCheck({ pack: p, employees: [leaving], hrEmployees: [], ledger, placements, today: '2027-01-02', bank: BANK, settings }), [], 'after final pay, no flag');
  eq(clawbackCheck({ pack: p, employees: [ella], hrEmployees: [{ known_as: 'Ella', full_name: 'Elzbieta Pietrzak', status: 'Notice given' }], ledger, placements, today: '2026-11-27', bank: BANK, settings }).length, 1, 'HR status "Notice given" also triggers the check');
}

// ---------- bank check ----------
{
  const rows = [
    { date: '2026-11-30', direction: 'OUT', amount: '-1850.20', cost_bucket: 'Payroll', counterparty: 'E PIETRZAK', reference: 'SALARY NOV', status: 'SETTLED' },
    { date: '2026-11-30', direction: 'OUT', amount: '-50', cost_bucket: 'Software' },
    { date: '2026-10-31', direction: 'OUT', amount: '-1800', cost_bucket: 'Payroll' },
  ];
  const b = payrollBankCheck(rows, '2026-11-30');
  eq([b.connected, b.rows.length, b.total], [true, 1, 1850.2], 'payroll rows near the pay date are found');
  eq(payrollBankCheck(null, '2026-11-30').connected, false, 'no bank, nothing shown');
}

// ---------- Ella sees nothing ----------
{
  const k = computeMyKpi({ invoices, candidates: [], roles: [], activity: [], comms: [], interviews: [], audit: [], now: new Date('2026-11-27T10:00:00Z') }, 'ella');
  const s = JSON.stringify(k).toLowerCase();
  ok(!/payroll|commission|pension|salary/.test(s), "Ella's KPI response holds no payroll, commission, pension or salary data");
}

console.log(`test-payroll: ${n} checks passed`);
