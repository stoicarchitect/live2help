/* ======================================================================
   Build 70 - pension status and employer NI per employee. Pure functions, no database or network.
   Used by payroll.js (the payroll pack and email) and kpi-owner.js (cost reporting).
   The page (dashboard/index.html) holds a matching inline copy: keep the two in step.

   Employee fields (the dashboard team list, stored in fin:l2h-employees):
   - pensionStatus: 'enrolled' or 'not_enrolled'. Missing means enrolled, so people added before build 70 do not change
   - pensionStart: ISO date employer pension begins (the enrolment date). Blank means from the start of employment
   - niExempt: false means employer NI is calculated. Missing or true means exempt, so people added before build 70 do not change
   Employer NI (2026/27, checked 21 Nov 2026): 15 percent of pay above the secondary threshold of 5,000 a year (416.67 a month).
   The Employment Allowance is not taken off, so a person marked as not exempt shows the full cost.
   ====================================================================== */
const ISO = /^\d{4}-\d{2}-\d{2}$/;
const num = v => { const n = parseFloat(String(v == null ? '' : v).replace(/[£,\s]/g, '')); return Number.isFinite(n) ? n : 0; };
const round2 = n => Math.round((Number(n) || 0) * 100) / 100;

export const NI_DEFAULTS = { ratePct: 15, thresholdYear: 5000 };

/* rates from the dashboard settings (fin:l2h-ni-rate-pct, fin:l2h-ni-threshold-year), falling back to the defaults */
export function niRatesFrom(get) {
  const rate = num(get && get('fin:l2h-ni-rate-pct')), thr = num(get && get('fin:l2h-ni-threshold-year'));
  return { ratePct: rate > 0 && rate < 100 ? rate : NI_DEFAULTS.ratePct, thresholdYear: thr > 0 ? thr : NI_DEFAULTS.thresholdYear };
}

/* the date three months after a date, clamped to the end of a shorter month (2 Nov 2026 gives 2 Feb 2027) */
export function addMonthsISO(iso, n) {
  if (!ISO.test(iso || '')) return '';
  const [y, m, d] = iso.split('-').map(Number);
  const t = (m - 1) + n, yy = y + Math.floor(t / 12), mm = ((t % 12) + 12) % 12;
  const last = new Date(Date.UTC(yy, mm + 1, 0)).getUTCDate();
  return `${yy}-${String(mm + 1).padStart(2, '0')}-${String(Math.min(d, last)).padStart(2, '0')}`;
}

/* auto-enrolment is due by three months after the start of employment */
export const autoEnrolDue = emp => addMonthsISO(emp && emp.startDate, 3);

export const pensionStatusOf = emp => (emp && emp.pensionStatus === 'not_enrolled' ? 'not_enrolled' : 'enrolled');

/* is employer pension payable for a pay period that ends on periodEndISO? The month holding the enrolment date counts in full */
export function pensionActive(emp, periodEndISO) {
  if (pensionStatusOf(emp) !== 'enrolled') return false;
  const from = ISO.test((emp && emp.pensionStart) || '') ? emp.pensionStart : '';
  return !from || from <= periodEndISO;
}

export const niExemptOf = emp => !(emp && (emp.niExempt === false || emp.niExempt === 'no'));

/* employer NI for one monthly pay period on a gross figure */
export function employerNiMonth(emp, gross, rates) {
  if (niExemptOf(emp)) return 0;
  const r = rates || NI_DEFAULTS;
  return round2(Math.max(0, num(gross) - r.thresholdYear / 12) * r.ratePct / 100);
}

/* employer NI for a stretch of weekdays (used for year to date cost): the threshold accrues per weekday like salary */
export function employerNiDays(emp, gross, weekdays, rates) {
  if (niExemptOf(emp)) return 0;
  const r = rates || NI_DEFAULTS;
  return round2(Math.max(0, num(gross) - r.thresholdYear / 260 * weekdays) * r.ratePct / 100);
}

/* one line for the screen and the email: where this person stands on pension */
export function pensionNote(emp, periodEndISO, gbpText) {
  if (pensionStatusOf(emp) === 'enrolled') {
    const from = ISO.test((emp && emp.pensionStart) || '') ? emp.pensionStart : '';
    return from && from > periodEndISO ? `Enrolled from ${from}, no employer pension this month` : 'Enrolled';
  }
  const due = autoEnrolDue(emp);
  return due ? `Not enrolled, auto-enrolment due by ${due}` : 'Not enrolled';
}
