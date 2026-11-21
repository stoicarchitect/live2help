/* Live 2 Help - build 64: payroll control.

   Pure functions only (no database, no network, no email). The server wires them to the daily job,
   the invoices, the bank rows from build 63 and the payroll tables. Nothing here sends anything:
   the payroll email is always opened for Daniel Brown to review and send himself.
   Dates are plain YYYY-MM-DD strings in London time. Tests: node scripts/test-payroll.mjs */

import { pensionActive, pensionStatusOf, niExemptOf, employerNiMonth, autoEnrolDue } from './employee-pay.js'; // build 70

const DAY = 86400000;
const round2 = n => Math.round((Number(n) || 0) * 100) / 100;
const num = v => { const x = parseFloat(String(v == null ? '' : v).replace(/[£,\s]/g, '')); return Number.isFinite(x) ? x : 0; };
const lc = s => String(s == null ? '' : s).trim().toLowerCase();
const ISO = /^\d{4}-\d{2}-\d{2}$/;
const MONTH = /^\d{4}-\d{2}$/;
const ms = iso => Date.parse(String(iso).slice(0, 10) + 'T00:00:00Z');
const isoOf = t => new Date(t).toISOString().slice(0, 10);
const addDays = (iso, n) => isoOf(ms(iso) + n * DAY);
const daysBetween = (a, b) => Math.round((ms(b) - ms(a)) / DAY);

export const PAYROLL_STAGES = ['not_yet', 'three_days', 'day_before', 'on_day', 'overdue', 'sent'];

// Today's date in London, whatever the server clock's zone is
export function londonToday(now = new Date()) {
  const p = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/London', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(now));
  const g = t => p.find(x => x.type === t).value;
  return `${g('year')}-${g('month')}-${g('day')}`;
}
export function monthOf(iso) { return String(iso || '').slice(0, 7); }
export function nextMonth(m) { const [y, mo] = m.split('-').map(Number); return mo === 12 ? `${y + 1}-01` : `${y}-${String(mo + 1).padStart(2, '0')}`; }
export function prevMonth(m) { const [y, mo] = m.split('-').map(Number); return mo === 1 ? `${y - 1}-12` : `${y}-${String(mo - 1).padStart(2, '0')}`; }
export function monthEnd(m) { const [y, mo] = m.split('-').map(Number); return isoOf(Date.UTC(y, mo, 0)); }
export function monthName(m) { const [y, mo] = m.split('-').map(Number); return new Date(Date.UTC(y, mo - 1, 1)).toLocaleDateString('en-GB', { month: 'long', year: 'numeric', timeZone: 'UTC' }); }

const holidaySet = bank => bank instanceof Set ? bank : new Set(bank instanceof Map ? bank.keys() : (bank || []));
export function isWorkingDay(iso, bank) {
  const w = new Date(ms(iso)).getUTCDay();
  return w !== 0 && w !== 6 && !holidaySet(bank).has(iso);
}
// n working days before (n < 0) or after (n > 0) a date, skipping weekends and bank holidays
export function shiftWorkingDays(iso, n, bank) {
  const set = holidaySet(bank);
  let d = iso, left = Math.abs(n);
  const step = n < 0 ? -1 : 1;
  while (left > 0) { d = addDays(d, step); if (isWorkingDay(d, set)) left--; }
  return d;
}
export function lastWorkingDay(month, bank) {
  let d = monthEnd(month);
  while (!isWorkingDay(d, bank)) d = addDays(d, -1);
  return d;
}

/* ---------- settings ----------
   rows from the Payroll Settings table: { id, value }. Keys: start_month (first month the dashboard watches),
   override:YYYY-MM (that month's pay date, e.g. the 1st of the next month). Default is the last working day. */
export function readPayrollSettings(rows) {
  const out = { startMonth: '', overrides: {} };
  (rows || []).forEach(r => {
    const id = String(r.id || ''), v = String(r.value == null ? '' : r.value).trim();
    if (id === 'start_month' && MONTH.test(v)) out.startMonth = v;
    if (id.startsWith('override:') && MONTH.test(id.slice(9)) && ISO.test(v)) out.overrides[id.slice(9)] = v;
  });
  return out;
}
// an override must stay close to the month it pays: from the 20th of the month to the 7th of the next one
export function validOverride(month, date) {
  if (!MONTH.test(month) || !ISO.test(date)) return false;
  const lo = `${month}-20`, hi = `${nextMonth(month)}-07`;
  return date >= lo && date <= hi;
}
export function payDateFor(month, settings, bank) {
  const o = settings && settings.overrides && settings.overrides[month];
  return o ? { date: o, source: 'override' } : { date: lastWorkingDay(month, bank), source: 'last working day' };
}
export function reminderDates(payDate, bank) {
  return { threeDays: shiftWorkingDays(payDate, -3, bank), dayBefore: shiftWorkingDays(payDate, -1, bank), onDay: payDate };
}
export function reminderStage(today, payDate, bank, sent) {
  if (sent) return { stage: 'sent', daysOverdue: 0 };
  const r = reminderDates(payDate, bank);
  if (today > payDate) return { stage: 'overdue', daysOverdue: daysBetween(payDate, today) };
  if (today === payDate) return { stage: 'on_day', daysOverdue: 0 };
  if (today >= r.dayBefore) return { stage: 'day_before', daysOverdue: 0 };
  if (today >= r.threeDays) return { stage: 'three_days', daysOverdue: 0 };
  return { stage: 'not_yet', daysOverdue: 0 };
}

/* Which payroll months need attention today. A month is watched from start_month onwards, and never once it is
   marked sent. Returns the months in order, oldest first, each with its pay date, reminder dates and stage. */
export function payrollWatch({ today, settings, bank, sentMonths }) {
  const sent = new Set(sentMonths || []);
  const start = (settings && settings.startMonth) || monthOf(today);
  const out = [];
  // the month after today's month is included because a 1st-of-month pay date can fall in it
  for (let m = start, guard = 0; m <= nextMonth(monthOf(today)) && guard < 36; m = nextMonth(m), guard++) {
    const pd = payDateFor(m, settings, bank);
    const st = reminderStage(today, pd.date, bank, sent.has(m));
    out.push({ month: m, payDate: pd.date, payDateSource: pd.source, reminders: reminderDates(pd.date, bank), ...st });
  }
  return out;
}
// The month the Today banner and the payroll panel should show: the oldest unsent month that is due or overdue,
// else the next month coming up.
export function currentPayrollMonth(watch) {
  const due = watch.filter(w => w.stage !== 'sent' && w.stage !== 'not_yet');
  if (due.length) return due[0];
  return watch.find(w => w.stage === 'not_yet') || watch[watch.length - 1] || null;
}
export function bannerFor(w) {
  if (!w || w.stage === 'sent' || w.stage === 'not_yet') return null;
  const name = monthName(w.month);
  if (w.stage === 'overdue') return { level: 'overdue', text: `Payroll for ${name} is ${w.daysOverdue} day${w.daysOverdue === 1 ? '' : 's'} overdue. The pay date was ${ukDate(w.payDate)}. Review and send the payroll email, then mark it as sent.` };
  if (w.stage === 'on_day') return { level: 'today', text: `Payroll for ${name} is due today. Review and send the payroll email, then mark it as sent.` };
  if (w.stage === 'day_before') return { level: 'soon', text: `Payroll for ${name} is due tomorrow (${ukDate(w.payDate)}). Review and send the payroll email.` };
  return { level: 'soon', text: `Payroll for ${name} is due on ${ukDate(w.payDate)}. Review the payroll pack and send the payroll email.` };
}
// The reminder (task and alert email) each stage raises, with a key that makes it fire once.
// Overdue escalates every day, so its key carries today's date.
export function reminderFor(w, today) {
  if (!w || w.stage === 'sent' || w.stage === 'not_yet') return null;
  const name = monthName(w.month);
  const key = w.stage === 'overdue' ? `payroll-${w.month}-overdue-${today}` : `payroll-${w.month}-${w.stage}`;
  const title = w.stage === 'overdue' ? `OVERDUE: send the payroll email for ${name} (${w.daysOverdue} day${w.daysOverdue === 1 ? '' : 's'} late)`
    : w.stage === 'on_day' ? `Send the payroll email for ${name} today`
      : w.stage === 'day_before' ? `Payroll for ${name} is due tomorrow`
        : `Payroll for ${name} is due on ${ukDate(w.payDate)}`;
  return { key, title, subject: `Live 2 Help: ${title}`, priority: w.stage === 'three_days' ? 'Medium' : 'High', dueDate: w.payDate };
}

/* ---------- the payroll pack ---------- */
function empMatches(emp, key) {
  const full = lc(emp.name), first = full.split(/\s+/)[0], k = lc(key);
  if (!k || k === 'unassigned') return false;
  return k === full || k === first || full.startsWith(k + ' ');
}
const paidOn = i => String(i.paymentDate || i.date || '').slice(0, 10);

/* employees: the dashboard employee list (name, salary a year, startDate, endDate, pensionPct, commissionPct, pensionOnComm)
   invoices: rowToInvoice shapes. ledger: Commission Ledger rows. cutoffDay: optional day of the month for commission. */
export function payrollPack({ month, payDate, employees, invoices, ledger, cutoffDay, niRates, today }) {
  const mStart = `${month}-01`, mEnd = monthEnd(month), days = Number(mEnd.slice(8));
  const cd = parseInt(cutoffDay, 10);
  const cutoff = cd >= 1 && cd <= 31 ? `${month}-${String(Math.min(cd, days)).padStart(2, '0')}` : (payDate && payDate < mEnd ? payDate : mEnd);
  const counted = new Set((ledger || []).filter(l => lc(l.status) !== 'reversed').map(l => String(l.invoice || l.id)));
  const people = [];
  const warnings = [];
  (employees || []).forEach(e => {
    if (!e || !e.name) return;
    const start = ISO.test(e.startDate || '') ? e.startDate : '';
    const end = ISO.test(e.endDate || '') ? e.endDate : '';
    if (!start || start > mEnd || (end && end < mStart)) return;
    const from = start > mStart ? start : mStart, to = end && end < mEnd ? end : mEnd;
    const activeDays = daysBetween(from, to) + 1;
    const monthly = num(e.salary) / 12;
    const salary = round2(activeDays >= days ? monthly : monthly * activeDays / days);
    const rate = num(e.commissionPct);
    const mine = (invoices || []).filter(i => i && i.number && num(i.commissionAmount) > 0 && empMatches(e, i.consultant));
    const unpaidCommission = mine.filter(i => lc(i.status) === 'paid' && !i.commissionPaidDate && !counted.has(String(i.number)));
    const lines = unpaidCommission.filter(i => paidOn(i) && paidOn(i) <= cutoff).map(i => {
      const amount = round2(num(i.commissionAmount));
      const expected = rate ? round2(num(i.amount) * rate / 100) : amount;
      if (rate && Math.abs(expected - amount) > 0.01) warnings.push(`Invoice ${i.number}: commission on the invoice is ${amount.toFixed(2)}, but ${rate}% of ${num(i.amount).toFixed(2)} is ${expected.toFixed(2)}. Check it before sending.`);
      return { invoice: String(i.number), company: i.company || '', candidate: i.candidateName || '', invoiceAmount: round2(num(i.amount)), clientPaid: paidOn(i), rate: num(i.commissionPct) || rate, amount };
    });
    const later = unpaidCommission.filter(i => !paidOn(i) || paidOn(i) > cutoff).map(i => ({ invoice: String(i.number), company: i.company || '', candidate: i.candidateName || '', clientPaid: paidOn(i), amount: round2(num(i.commissionAmount)) }));
    const waiting = mine.filter(i => lc(i.status) !== 'paid');
    const commission = round2(lines.reduce((s, l) => s + l.amount, 0));
    const pensionPct = num(e.pensionPct);
    // build 70: employer pension only counts once the person is enrolled (auto-enrolment is usually after three months)
    const pensionOn = pensionActive(e, mEnd);
    const pension = pensionOn ? round2(pensionPct / 100 * (salary + (e.pensionOnComm === false ? 0 : commission))) : 0;
    const gross = round2(salary + commission);
    const niExempt = niExemptOf(e);
    const employerNi = employerNiMonth(e, gross, niRates);
    const due = autoEnrolDue(e);
    const status = pensionStatusOf(e);
    if (status === 'not_enrolled' && due && today) {
      const left = daysBetween(today, due);
      if (left < 0) warnings.push(`${e.name} is not enrolled in the pension and auto-enrolment was due by ${due}. Check the date on the team list.`);
      else if (left <= 30) warnings.push(`${e.name}: auto-enrolment into the pension is due by ${due} (${left} day${left === 1 ? '' : 's'} away). Set them as enrolled on the team list from that month.`);
    }
    people.push({
      name: e.name, role: e.role || '', salaryYear: num(e.salary), salary, partMonth: activeDays < days, activeDays,
      commissionRate: rate, commission, lines, later, waitingCount: waiting.length, waitingAmount: round2(waiting.reduce((s, i) => s + num(i.commissionAmount), 0)),
      pensionPct, pensionOnCommission: e.pensionOnComm !== false, pension, gross, endDate: end,
      pensionStatus: status, pensionActive: pensionOn, pensionStart: ISO.test(e.pensionStart || '') ? e.pensionStart : '', pensionDue: due,
      niExempt, employerNi, employerCost: round2(gross + pension + employerNi),
    });
  });
  const tot = k => round2(people.reduce((s, p) => s + p[k], 0));
  return {
    month, monthName: monthName(month), payDate, cutoff, people, warnings,
    totals: { salary: tot('salary'), commission: tot('commission'), pension: tot('pension'), employerNi: tot('employerNi'), gross: tot('gross'), employerCost: tot('employerCost') },
    invoices: people.flatMap(p => p.lines.map(l => l.invoice)),
  };
}

/* ---------- clawback check (flag only, never calculated) ----------
   Only while someone is in their notice period and before their final pay date. Lists the commission in this pack
   and any already paid commission whose placement guarantee has not finished, so Daniel Brown can check the
   Commission Scheme terms himself. */
export function clawbackCheck({ pack, employees, hrEmployees, ledger, placements, today, bank, settings }) {
  const flags = [];
  (employees || []).forEach(e => {
    const p = (pack.people || []).find(x => x.name === e.name);
    const hr = (hrEmployees || []).find(h => empMatches(e, h.known_as) || empMatches(e, h.full_name) || lc(h.full_name) === lc(e.name));
    const end = ISO.test(e.endDate || '') ? e.endDate : '';
    const hrNotice = hr && /notice|leaving/i.test(hr.status || '');
    if (!end && !hrNotice) return;
    const finalPay = end ? payDateFor(monthOf(end), settings || {}, bank).date : '';
    if (finalPay && today > finalPay) return; // final pay has gone, nothing left to check
    const inPlay = new Set();
    const rows = [];
    const guaranteeOf = inv => (placements || []).find(pl => (pl.invoiceNumber && String(pl.invoiceNumber) === String(inv.invoice))
      || (lc(pl.company) === lc(inv.company) && lc(pl.name) === lc(inv.candidate)));
    const consider = (inv, when) => {
      if (inPlay.has(inv.invoice)) return; inPlay.add(inv.invoice);
      const pl = guaranteeOf(inv);
      const open = pl && (pl.status === 'left' || !pl.guaranteeEnd || pl.guaranteeEnd >= today);
      if (open) rows.push({ invoice: inv.invoice, company: inv.company, candidate: inv.candidate, amount: inv.amount, when, guaranteeEnd: pl.guaranteeEnd || '', placementStatus: pl.status || 'active' });
    };
    (p ? p.lines : []).forEach(l => consider(l, 'in this payroll'));
    (ledger || []).filter(l => empMatches(e, l.employee) && lc(l.status) === 'paid').forEach(l => consider({ invoice: String(l.invoice || l.id), company: l.company, candidate: l.candidate, amount: num(l.amount) }, 'paid in ' + (l.payroll_month || 'an earlier payroll')));
    flags.push({
      employee: e.name, endDate: end, finalPayDate: finalPay, rows,
      text: `${e.name} is in their notice period${end ? ` (leaving ${end}, final pay ${finalPay})` : ''}. Check the Commission Scheme clawback terms before final pay. ` +
        (rows.length ? `${rows.length} commission${rows.length === 1 ? ' is' : 's are'} on placements still inside their guarantee or marked as left. Nothing has been deducted.` : 'No commission is on a placement still inside its guarantee.'),
    });
  });
  return flags;
}

/* ---------- bank check (build 63 rows) ----------
   The Starling feed files payroll payments under the Payroll cost bucket. Lists those for the pay window so the run can
   be compared with what actually left the account. Information only. */
export function payrollBankCheck(bankRows, payDate) {
  if (!Array.isArray(bankRows)) return { connected: false, rows: [], total: 0 };
  const lo = addDays(payDate, -7), hi = addDays(payDate, 7);
  const rows = bankRows.filter(r => r && lc(r.direction) === 'out' && /payroll/i.test(String(r.bucket || r.cost_bucket || ''))
    && String(r.date || '') >= lo && String(r.date || '') <= hi && lc(r.status) !== 'declined')
    .map(r => ({ date: r.date, amount: round2(Math.abs(num(r.amount))), counterparty: r.counterparty || '', reference: r.reference || '' }));
  const total = round2(rows.reduce((s, r) => s + r.amount, 0));
  return { connected: true, rows, total, note: rows.length ? `Bank shows ${rows.length} payroll payment${rows.length === 1 ? '' : 's'} totalling ${total.toFixed(2)} around the pay date. Net pay after tax and deductions is normally lower than gross pay.` : 'No payroll payment seen in the bank within a week of the pay date yet.' };
}

/* ---------- the email text (opened for review, never sent from here) ---------- */
const gbp = n => '£' + (Number(n) || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const ukDate = iso => ISO.test(iso || '') ? new Date(ms(iso)).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : '';
export function payrollEmail(pack, signer) {
  const lines = [`Please process the payroll for ${pack.monthName}, to be paid on ${ukDate(pack.payDate)}. Commission is included where the client paid on or before ${ukDate(pack.cutoff)}.`, ''];
  pack.people.forEach(p => {
    lines.push(`${p.name}${p.role ? ' (' + p.role + ')' : ''}`);
    lines.push(`- Salary: ${gbp(p.salary)} gross${p.partMonth ? ` (part month, ${p.activeDays} days)` : ` (${gbp(p.salaryYear)} a year, paid monthly)`}`);
    if (p.lines.length) {
      lines.push(`- Commission (${p.commissionRate || ''}% of invoice amount, client has paid):`);
      p.lines.forEach(l => lines.push(`    ${l.candidate}, ${l.company}, invoice ${l.invoice}: invoice ${gbp(l.invoiceAmount)}, client paid ${ukDate(l.clientPaid)}, commission ${gbp(l.amount)}`));
      lines.push(`  Commission total: ${gbp(p.commission)} gross`);
    } else if (p.commissionRate) lines.push('- Commission: none this month');
    lines.push(`- Total gross pay: ${gbp(p.gross)}`);
    if (p.pensionActive && p.pensionPct) lines.push(`- Pension: enrolled. Employer pension (${p.pensionPct}%${p.pensionOnCommission ? ' on salary and commission' : ' on salary only'}): ${gbp(p.pension)}`);
    else if (p.pensionStatus === 'not_enrolled') lines.push(`- Pension: not enrolled, so no pension deduction or employer pension this month${p.pensionDue ? ` (auto-enrolment due by ${ukDate(p.pensionDue)})` : ''}`);
    else if (p.pensionStart && !p.pensionActive) lines.push(`- Pension: enrolled from ${ukDate(p.pensionStart)}, so no employer pension this month`);
    lines.push(p.niExempt ? '- National Insurance: employer NI exempt' : `- Employer National Insurance: ${gbp(p.employerNi)}`);
    if (p.later.length) {
      lines.push('- Commission moving to next month (client paid after the cut-off):');
      p.later.forEach(l => lines.push(`    ${l.candidate}, ${l.company}, invoice ${l.invoice}: ${gbp(l.amount)}${l.clientPaid ? ', client paid ' + ukDate(l.clientPaid) : ''}`));
    }
    lines.push('');
  });
  lines.push(`Total gross pay for the month: ${gbp(pack.totals.gross)}`);
  lines.push('', 'Thank you,', signer || 'Daniel Brown', 'Live 2 Help Recruitment');
  return { subject: `Payroll for ${pack.monthName}`, body: lines.join('\n') };
}

/* What Mark as sent stores: one Payroll Runs row and one Commission Ledger row per invoice */
export function runRecords(pack, { by, at, to, bankCheck }) {
  const run = {
    id: pack.month, month: pack.month, pay_date: pack.payDate, status: 'sent', sent_at: at, sent_by: by, to: to || '',
    salary: String(pack.totals.salary), commission: String(pack.totals.commission), pension: String(pack.totals.pension), note: pack.totals.employerNi ? `employer NI ${pack.totals.employerNi}` : '',
    gross: String(pack.totals.gross), employer_cost: String(pack.totals.employerCost), invoices: pack.invoices.join(' '),
    people: pack.people.map(p => p.name).join(', '), bank_check: bankCheck && bankCheck.connected ? String(bankCheck.total) : '',
  };
  const ledger = pack.people.flatMap(p => p.lines.map(l => ({
    id: l.invoice, invoice: l.invoice, employee: p.name, company: l.company, candidate: l.candidate, invoice_amount: String(l.invoiceAmount),
    rate: String(l.rate), amount: String(l.amount), client_paid: l.clientPaid, payroll_month: pack.month, status: 'paid', recorded_at: at, recorded_by: by,
  })));
  return { run, ledger };
}
