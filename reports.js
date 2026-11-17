/* Live 2 Help - build 65: monthly and weekly reports.

   Pure functions only (no database, no network, no email). The server wires them to the morning job, the KPI
   figures from build 62, the bank figures from build 63 and the payroll figures from build 64.
   Every report is built from a frozen snapshot, saved once in Report Runs, so opening it later shows the same
   numbers. The owner report and the weekly brief are internal and go to Daniel Brown only. Ella's performance
   report is built from her own activity figures only: it never receives any bank, payroll, commission, tax,
   cost or margin figure, and a scan refuses to produce it if one slips in.
   Tests: node scripts/test-reports.mjs */

import { isWorkingDay, prevMonth, monthName as periodName } from './payroll.js';

const DAY = 86400000;
const round1 = n => Math.round((Number(n) || 0) * 10) / 10;
const lc = s => String(s == null ? '' : s).trim().toLowerCase();
const isoOf = t => new Date(t).toISOString().slice(0, 10);
const addDays = (iso, n) => isoOf(Date.parse(iso + 'T00:00:00Z') + n * DAY);

export const REPORT_VERSION = 1;

/* ---------- text helpers: no em dashes, no en dashes, ever ---------- */
export function tidy(s) {
  return String(s == null ? '' : s).replace(/\s*[—–]\s*/g, ' - ').replace(/ -- /g, ' - ');
}
const gbp = n => { const v = Math.round(Number(n) || 0); return (v < 0 ? '-' : '') + '£' + Math.abs(v).toLocaleString('en-GB'); };
const cell = s => tidy(s).replace(/\|/g, '/').replace(/\n/g, ' ');
export const ukDate = iso => (iso ? new Date(String(iso).slice(0, 10) + 'T12:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }) : '');
const pctTxt = t => (t && t.pct != null ? `${t.pct > 0 ? '+' : ''}${t.pct}%` : '');
const num1 = n => String(round1(n));
function vs(t, fmt = num1) {
  if (!t) return '';
  if (t.before == null) return fmt(t.now);
  const p = pctTxt(t);
  return `${fmt(t.now)} (last month ${fmt(t.before)}${p ? ', ' + p : ''})`;
}
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;

/* ---------- when a report is due ---------- */
export function firstWorkingDay(month, bank) {
  let d = `${month}-01`;
  while (!isWorkingDay(d, bank)) d = addDays(d, 1);
  return d;
}
// The monthly reports cover the month that has just finished and go out on the first working day of the next month.
// startMonth is the first month ever reported, set when the reports first run, so no old month is sent late.
export function reportPeriodDue({ today, holidays, startMonth }) {
  const month = String(today).slice(0, 7);
  if (today < firstWorkingDay(month, holidays)) return null;
  const period = prevMonth(month);
  if (startMonth && period < startMonth) return null;
  return period;
}
export const isMonday = today => new Date(String(today).slice(0, 10) + 'T12:00:00Z').getUTCDay() === 1;
// The last day of a month as a Date at noon UTC, used to ask the KPI sums "as at the end of that month"
export function monthEndDate(period) {
  const [y, m] = period.split('-').map(Number);
  return new Date(Date.UTC(y, m, 0, 12, 0, 0));
}

/* ======================================================================
   OWNER REPORT (Daniel Brown only)
   kMonth: computeOwnerKpi as at the last day of the reported month (flow figures for that month, against the month before)
   kNow:   computeOwnerKpi as at generation (position figures: money owed, cash, pipeline, guarantees)
   payroll: { monthName, status: 'sent' | 'not_sent' | 'unknown', payDate, sentAt, salary, commission, pension, gross, employerCost }
   ====================================================================== */
export function buildOwnerSnapshot({ period, kMonth, kNow, payroll, generatedAt, asAt }) {
  const bank = kNow.bank || {};
  const connected = !!bank.connected;
  const snap = {
    version: REPORT_VERSION, kind: 'owner', period, periodName: periodName(period), generatedAt, asAt,
    headline: {
      invoiced: kMonth.money.invoiced.month, paid: kMonth.money.paid.month,
      rolesFilled: kMonth.pipeline.rolesFilled.month, submissions: kMonth.pipeline.submissions,
      interviews: kMonth.pipeline.interviews, offers: kMonth.pipeline.offers,
      newClients: kMonth.clients.newClients.month, teamCost: kMonth.cost.teamCostMonth, adSpend: kMonth.cost.adSpendMonth,
      changes: (kMonth.changes || []).map(c => ({ good: c.good, text: c.text })),
    },
    money: {
      outstanding: kNow.money.outstanding, overdue: kNow.money.overdue,
      overdueInvoices: kNow.money.overdueInvoices.slice(0, 6),
      debtorDays: kNow.money.debtorDays, avgDaysToPay: kNow.money.avgDaysToPay,
      ytdInvoiced: kNow.money.invoiced.ytd, ytdPaid: kNow.money.paid.ytd,
      forecast: { weighted: kNow.money.forecast.weighted, bestCase: kNow.money.forecast.bestCase, awaitingInvoice: kNow.money.forecast.awaitingInvoice },
    },
    cash: connected ? {
      connected: true, balance: bank.balance, spendable: bank.spendable, taxReserve: bank.taxReserve,
      lowest: bank.forecast.lowest, endBalance: bank.forecast.endBalance, expectedIn: bank.forecast.expectedIn, expectedOut: bank.forecast.expectedOut,
      floor: bank.floor, belowFloor: !!bank.belowFloor, confirmCount: bank.confirmCount || 0,
      tax: bank.tax ? { profitYtd: bank.tax.profitYtd, overheadsYtd: bank.tax.overheadsYtd, taxableProfit: bank.tax.taxableProfit, reserve: bank.tax.reserve, flatRatePct: bank.tax.flatRatePct } : null,
      lateClients: (bank.scores || []).filter(s => s.avgDaysLate > 7).slice(0, 4).map(s => ({ company: s.company, avgDaysLate: s.avgDaysLate, rating: s.rating })),
    } : { connected: false, note: bank.note || 'Bank not connected yet' },
    pipeline: {
      openRoles: kNow.pipeline.openRoles, openPositions: kNow.pipeline.openPositions, atRisk: kNow.pipeline.atRisk, staleDays: kNow.pipeline.staleDays,
      atRiskRoles: kNow.pipeline.roles.filter(r => r.atRisk).slice(0, 6).map(r => ({ company: r.company, role: r.role, idleDays: r.idleDays })),
      timeToFillDays: kNow.pipeline.timeToFillDays, conversion: kNow.pipeline.conversion,
    },
    clients: {
      newNames: kMonth.clients.newClients.namesThisMonth || [], concentration: kNow.clients.concentration, guarantee: {
        count: kNow.clients.guaranteeWatch.count, revenueAtRisk: kNow.clients.guaranteeWatch.revenueAtRisk, leftInGuarantee: kNow.clients.guaranteeWatch.leftInGuarantee,
        soonest: kNow.clients.guaranteeWatch.placements.slice(0, 3).map(p => ({ name: p.name, company: p.company, daysLeft: p.daysLeft, atRisk: p.atRisk })),
      },
    },
    costs: {
      profitYtd: kNow.cost.profitYtd, marginPct: kNow.cost.marginPct, teamCostYtd: kNow.cost.teamCostYtd, adSpendYtd: kNow.cost.adSpendYtd,
      costPerHire: kNow.cost.costPerHire, hiresYtd: kNow.cost.hiresYtd, recurring: kNow.cost.recurring,
    },
    vat: { pct: kNow.vat.pct, turnover12m: kNow.vat.turnover12m, threshold: kNow.vat.threshold, headroom: kNow.vat.headroom, status: kNow.vat.status },
    payroll: payroll || { status: 'unknown' },
    team: (kMonth.staff.people || []).map(p => ({
      name: p.name, role: p.role, activity: p.activity, placementsQuarter: p.placementsQuarter, placementsYtd: p.placementsYtd,
      revenueYtd: p.revenueYtd, employmentCostYtd: p.employmentCostYtd, roiPct: p.roiPct, target: p.target,
    })),
  };
  snap.focus = focusPoints(snap);
  return snap;
}

// Three specific things to do next, chosen by what the numbers say, most pressing first
export function focusPoints(s) {
  const c = [];
  const add = (score, text) => c.push({ score, text: tidy(text) });
  const od = s.money.overdueInvoices || [];
  if (s.money.overdue && s.money.overdue.now > 0) {
    const top = od[0];
    add(90 + Math.min(9, Math.round(s.money.overdue.now / 2000)), `Collect the ${gbp(s.money.overdue.now)} that is overdue${top ? `, starting with ${top.company} (${top.number}, ${top.daysOverdue} days late)` : ''}.`);
  }
  if (s.cash && s.cash.connected && s.cash.belowFloor) add(95, `Protect cash: the 90 day forecast drops to ${gbp(s.cash.lowest.balance)} on ${ukDate(s.cash.lowest.date)}, under your floor of ${gbp(s.cash.floor)}. Chase receipts and hold back non-essential spend.`);
  if (s.pipeline.atRisk > 0) {
    const r = s.pipeline.atRiskRoles[0];
    add(70 + Math.min(10, s.pipeline.atRisk * 2), `Restart ${plural(s.pipeline.atRisk, 'role')} with no activity for ${s.pipeline.staleDays} days or more${r ? `, starting with ${r.company} - ${r.role}` : ''}.`);
  }
  if (s.money.forecast.awaitingInvoice > 0) add(75, `Raise invoices for placements not yet billed, worth about ${gbp(s.money.forecast.awaitingInvoice)}.`);
  const con = s.clients.concentration;
  if (con && con.warn) add(65, `Spread the risk: ${con.topClient} is ${con.topSharePct}% of the last 12 months of billing, above your ${con.warnPct}% warning level. Win work from other clients.`);
  if (s.vat.status !== 'ok') add(80, `Speak to your accountant about VAT: turnover is ${s.vat.pct}% of the ${gbp(s.vat.threshold)} threshold.`);
  const g = s.clients.guarantee;
  if (g.soonest && g.soonest[0] && g.soonest[0].daysLeft <= 14) add(55, `Check in with ${g.soonest[0].company} about ${g.soonest[0].name}: the placement guarantee ends in ${g.soonest[0].daysLeft} days.`);
  if (s.cash && s.cash.connected && s.cash.confirmCount > 0) add(50, `Clear ${plural(s.cash.confirmCount, 'bank payment')} waiting on your confirmation in KPI Reporting > Bank.`);
  if (s.payroll && s.payroll.status === 'not_sent') add(85, `Payroll for ${s.payroll.monthName} is not marked as sent. Open KPI Reporting > Payroll.`);
  const sub = s.headline.submissions;
  if (sub && sub.before > 0 && sub.diff < 0) add(45, `Lift submissions back up: they fell from ${sub.before} to ${sub.now}. More good submissions are the start of every placement.`);
  const roles = s.headline.rolesFilled;
  if (roles && roles.now === 0) add(40, 'No roles were filled this month. Review the roles furthest along and decide what each needs to reach an offer.');
  const conv = s.pipeline.conversion;
  if (conv && conv.submissionToInterviewPct != null && conv.submissionToInterviewPct < 30 && conv.submitted >= 5) add(35, `Only ${conv.submissionToInterviewPct}% of submissions reach interview. Tighten the match before submitting and ask clients what stopped the rest.`);
  add(5, 'Keep the pipeline moving: every open role should have a next step booked this week.');
  add(4, 'Log every call and email in the workspace the same day so the next report shows the whole picture.');
  add(3, 'Review next month\'s targets against the roles now open and adjust them if the plan has changed.');
  return c.sort((a, b) => b.score - a.score).slice(0, 3).map(x => x.text);
}

export function ownerReportMarkdown(s) {
  const L = [];
  const h = t => L.push('', `## ${t}`, '');
  const table = (head, rows) => { L.push(`| ${head.map(cell).join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map(r => `| ${r.map(cell).join(' | ')} |`), ''); };
  L.push('---', `title: Owner report: ${s.periodName}`, 'subtitle: Prepared for Daniel Brown', `version: Month figures for ${s.periodName}. Cash, money owed and pipeline are as at ${ukDate(s.asAt)}. Confidential.`, '---', '');
  L.push(`This report covers ${s.periodName}. Figures for the month are set beside the month before. Cash, money owed, pipeline and cost figures are as at ${ukDate(s.asAt)}. They are steering estimates from the workspace, and your accountant's figures are the source of truth.`);
  h('Three focus points for the month ahead');
  L.push(...s.focus.map((f, i) => `${i + 1}. ${tidy(f)}`), '');

  h('Headline numbers');
  const H = s.headline;
  table(['Measure', `${s.periodName}`], [
    ['Invoiced', vs(H.invoiced, gbp)], ['Cash received from clients', vs(H.paid, gbp)],
    ['Roles filled', vs(H.rolesFilled)], ['Candidates submitted', vs(H.submissions)], ['Interviews arranged', vs(H.interviews)], ['Offers', vs(H.offers)],
    ['New clients won', vs(H.newClients)], ['Team cost', vs(H.teamCost, gbp)], ['Advertising spend', vs(H.adSpend, gbp)],
  ]);
  if (H.changes.length) L.push('What moved most:', '', ...H.changes.map(c => `- ${tidy(c.text)}`), '');

  h('Money');
  const M = s.money;
  table(['Measure', 'Figure'], [
    ['Unpaid invoices', vs(M.outstanding, gbp)], ['Overdue invoices', vs(M.overdue, gbp)],
    ['Debtor days', M.debtorDays == null ? 'Not enough data yet' : `${M.debtorDays} days`], ['Average days for a client to pay', M.avgDaysToPay == null ? 'Not enough data yet' : `${M.avgDaysToPay} days`],
    ['Invoiced this year', vs(M.ytdInvoiced, gbp)], ['Paid this year', vs(M.ytdPaid, gbp)],
    ['Fees expected from the pipeline (weighted)', gbp(M.forecast.weighted)], ['Placements not yet invoiced', gbp(M.forecast.awaitingInvoice)],
  ]);
  if (M.overdueInvoices.length) table(['Overdue invoice', 'Client', 'Amount', 'Days late'], M.overdueInvoices.map(i => [i.number, i.company, gbp(i.amount), String(i.daysOverdue)]));

  h('Cash position and 90 day forecast');
  const C = s.cash;
  if (!C.connected) L.push(tidy(C.note || 'The bank is not connected yet, so there is no cash figure in this report.'), '');
  else {
    table(['Measure', 'Figure'], [
      ['Balance at the bank', gbp(C.balance)], ['Set aside for corporation tax', gbp(C.taxReserve)], ['Spendable cash after tax', gbp(C.spendable)],
      ['Lowest point in the next 90 days', `${gbp(C.lowest.balance)} on ${ukDate(C.lowest.date)}`], ['Expected balance in 90 days', gbp(C.endBalance)],
      ['Expected in', gbp(C.expectedIn)], ['Expected out (payroll with commission, costs)', gbp(C.expectedOut)],
      ['Your cash floor', C.floor == null ? 'Not set' : gbp(C.floor)],
    ]);
    if (C.belowFloor) L.push(`**The forecast goes below your cash floor.** Lowest point ${gbp(C.lowest.balance)} on ${ukDate(C.lowest.date)}.`, '');
    if (C.lateClients.length) { L.push('Clients who usually pay late:', '', ...C.lateClients.map(l => `- ${tidy(l.company)}: ${l.avgDaysLate} days late on average (${tidy(l.rating)})`), ''); }
  }

  h('Tax reserve');
  if (C.connected && C.tax) table(['Measure', 'Figure'], [['Profit to date', gbp(C.tax.profitYtd)], ['Other costs from the bank', gbp(C.tax.overheadsYtd)], ['Taxable profit (estimate)', gbp(C.tax.taxableProfit)], ['Corporation tax to set aside', gbp(C.tax.reserve)]]);
  else L.push('The tax reserve is worked out from the bank costs, so it appears once the bank is connected.', '');
  table(['VAT threshold watch', 'Figure'], [['Turnover, last 12 months', gbp(s.vat.turnover12m)], ['Threshold', gbp(s.vat.threshold)], ['Used', `${s.vat.pct}%`], ['Headroom', gbp(s.vat.headroom)]]);

  h('Pipeline and roles at risk');
  const P = s.pipeline;
  table(['Measure', 'Figure'], [
    ['Open roles', vs(P.openRoles)], ['Open positions', String(P.openPositions)], [`Roles with no activity for ${P.staleDays} days or more`, String(P.atRisk)],
    ['Time to fill, this quarter', P.timeToFillDays.quarter == null ? 'No fills yet' : `${P.timeToFillDays.quarter} days`],
    ['Submissions that reached interview', P.conversion.submissionToInterviewPct == null ? 'Not enough data yet' : `${P.conversion.submissionToInterviewPct}%`],
    ['Interviews that reached offer', P.conversion.interviewToOfferPct == null ? 'Not enough data yet' : `${P.conversion.interviewToOfferPct}%`],
  ]);
  if (P.atRiskRoles.length) table(['Role at risk', 'Client', 'Days idle'], P.atRiskRoles.map(r => [r.role, r.company, r.idleDays == null ? 'No activity yet' : String(r.idleDays)]));

  h('Clients');
  const K = s.clients;
  L.push(K.newNames.length ? `New clients this month: ${K.newNames.map(tidy).join(', ')}.` : 'No new clients were added this month.', '');
  if (K.concentration.topClient) L.push(`Biggest client over the last 12 months: ${tidy(K.concentration.topClient)}, ${K.concentration.topSharePct}% of billing${K.concentration.warn ? ` (above your ${K.concentration.warnPct}% warning level)` : ''}.`, '');
  L.push(`Placement guarantees running: ${K.guarantee.count}, with ${gbp(K.guarantee.revenueAtRisk)} of fees still inside a guarantee period.`, '');
  if (K.guarantee.soonest.length) table(['Candidate', 'Client', 'Days of guarantee left', 'Fee at risk'], K.guarantee.soonest.map(g => [g.name, g.company, String(g.daysLeft), gbp(g.atRisk)]));

  h('Costs and margin');
  const O = s.costs;
  table(['Measure', 'Figure'], [
    ['Profit this year so far', gbp(O.profitYtd)], ['Margin', O.marginPct == null ? 'Not enough data yet' : `${O.marginPct}%`], ['Team cost this year', gbp(O.teamCostYtd)], ['Advertising this year', gbp(O.adSpendYtd)],
    ['Hires this year', String(O.hiresYtd)], ['Cost per hire', O.costPerHire == null ? 'No hires yet' : gbp(O.costPerHire)], ['Regular costs each month', gbp(O.recurring.totalPerMonth)],
  ]);
  L.push('Margin is revenue invoiced this year less salary, employer pension, commission and advertising. Other overheads and tax are not taken off.', '');

  h('Payroll');
  const Y = s.payroll;
  if (Y.status === 'sent') table(['Payroll', Y.monthName], [['Status', `Sent on ${ukDate(Y.sentAt)}`], ['Pay date', ukDate(Y.payDate)], ['Salary', gbp(Y.salary)], ['Commission', gbp(Y.commission)], ['Employer pension', gbp(Y.pension)], ['Gross pay', gbp(Y.gross)], ['Employer cost', gbp(Y.employerCost)]]);
  else if (Y.status === 'not_sent') L.push(`Payroll for ${tidy(Y.monthName)} is not marked as sent. Pay date ${ukDate(Y.payDate)}.`, '');
  else L.push('No payroll record is held for this month.', '');

  h('Team performance');
  if (!s.team.length) L.push('No one is on the payroll list yet.', '');
  else table(['Person', 'Submissions', 'Interviews', 'Interviews attended', 'Calls', 'Emails', 'Placements this quarter', 'Revenue this year', 'Cost this year', 'Return'],
    s.team.map(p => [p.name, String(p.activity.submissions.now), String(p.activity.interviewsBooked.now), attendTxt(p.activity), String(p.activity.calls.now), String(p.activity.emails.now), String(p.placementsQuarter), gbp(p.revenueYtd), gbp(p.employmentCostYtd), p.roiPct == null ? 'n/a' : `${p.roiPct}%`]));
  return tidy(L.join('\n'));
}

export function ownerReportEmail(s) {
  const H = s.headline, C = s.cash;
  const lines = [
    `Invoiced ${vs(H.invoiced, gbp)}`, `Cash received ${vs(H.paid, gbp)}`,
    `Overdue ${gbp(s.money.overdue.now)} across ${plural(s.money.overdueInvoices.length, 'invoice')}${s.money.overdueInvoices.length >= 6 ? ' or more' : ''}`,
    C.connected ? `Cash at the bank ${gbp(C.balance)}, ${gbp(C.spendable)} spendable after tax. Lowest point in 90 days ${gbp(C.lowest.balance)} on ${ukDate(C.lowest.date)}` : 'Bank not connected yet, so no cash figure',
    `Roles filled ${vs(H.rolesFilled)}. Open roles ${s.pipeline.openRoles.now}, ${s.pipeline.atRisk} with no recent activity`,
    `Profit this year so far ${gbp(s.costs.profitYtd)}${s.costs.marginPct == null ? '' : ` (margin ${s.costs.marginPct}%)`}`,
    s.payroll.status === 'sent' ? `Payroll for ${s.payroll.monthName} was sent on ${ukDate(s.payroll.sentAt)}, gross ${gbp(s.payroll.gross)}` : s.payroll.status === 'not_sent' ? `Payroll for ${s.payroll.monthName} is NOT marked as sent` : 'No payroll record for the month',
  ];
  const text = [
    'Daniel,', '', `Your owner report for ${s.periodName} is attached as a PDF. The headlines:`, '', ...lines.map(l => `- ${l}`), '',
    `Three focus points for ${nextMonthName(s.period)}:`, ...s.focus.map((f, i) => `${i + 1}. ${f}`), '',
    `Figures for ${s.periodName} are for the month. Cash, money owed and pipeline are as at ${ukDate(s.asAt)}. These are steering estimates, and your accountant's figures are the source of truth.`, '',
    'You can open the same report again from KPI Reporting > Reports in the workspace.',
  ].join('\n');
  return { subject: tidy(`Live 2 Help owner report: ${s.periodName}`), text: tidy(text) };
}
function nextMonthName(period) { const [y, m] = period.split('-').map(Number); return periodName(m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, '0')}`).replace(/ \d{4}$/, ''); }

/* ======================================================================
   WEEKLY BRIEF (Mondays, Daniel Brown only)
   facts come from weeklyFacts(), which the server fills in
   ====================================================================== */
export function weeklyFacts({ today, k, invoices, audit, roles, tasks, outboxPending, payrollBanner }) {
  const from = addDays(today, -7), to = addDays(today, 7);
  const paidLast = (invoices || []).filter(i => lc(i.status) === 'paid' && String(i.paymentDate || '').slice(0, 10) >= from && String(i.paymentDate || '').slice(0, 10) <= today);
  const unpaid = (invoices || []).filter(i => lc(i.status) !== 'paid' && i.number);
  const dueDate = i => String(i.dueDate || '').slice(0, 10) || (i.date ? addDays(String(i.date).slice(0, 10), 14) : '');
  const dueWeek = unpaid.filter(i => dueDate(i) >= today && dueDate(i) <= to);
  const moves = stage => (audit || []).filter(a => a.action === 'stage_changed' && String(a.timestamp || '').slice(0, 10) >= from && lc((String(a.detail || '').match(/\sto\s+(.*)$/i) || [])[1]).replace(/\s+/g, '_') === stage).length;
  const rolesOpened = (roles || []).filter(r => String(r.date_opened || '').slice(0, 10) >= from).length;
  const decisions = [];
  if (payrollBanner) decisions.push(payrollBanner);
  const bank = k.bank || {};
  if (bank.connected && bank.belowFloor) decisions.push(`The cash forecast drops to ${gbp(bank.forecast.lowest.balance)} on ${ukDate(bank.forecast.lowest.date)}, below your floor of ${gbp(bank.floor)}.`);
  if (bank.connected && bank.confirmCount > 0) decisions.push(`${plural(bank.confirmCount, 'bank payment')} waiting for you to confirm which invoice it pays.`);
  if (outboxPending > 0) decisions.push(`${plural(outboxPending, 'email')} waiting in Emails to review.`);
  if (k.vat.status !== 'ok') decisions.push(`Turnover is ${k.vat.pct}% of the VAT threshold.`);
  if (k.pipeline.atRisk > 0) decisions.push(`${plural(k.pipeline.atRisk, 'open role')} with no activity for ${k.pipeline.staleDays} days or more.`);
  const soon = k.clients.guaranteeWatch.placements.filter(p => p.daysLeft <= 14);
  if (soon.length) decisions.push(`${soon.map(p => `${p.name} at ${p.company} (${p.daysLeft} days)`).join(', ')}: placement guarantee ending soon.`);
  return {
    today, weekFrom: from,
    cash: bank.connected ? { balance: bank.balance, spendable: bank.spendable, lowest: bank.forecast.lowest, floor: bank.floor } : { connected: false },
    moneyIn: { amount: Math.round(paidLast.reduce((s, i) => s + (Number(i.amount) || 0), 0) * 100) / 100, count: paidLast.length },
    dueThisWeek: { amount: Math.round(dueWeek.reduce((s, i) => s + (Number(i.amount) || 0), 0) * 100) / 100, count: dueWeek.length, items: dueWeek.slice(0, 5).map(i => ({ company: i.company, number: i.number, amount: Number(i.amount) || 0, dueDate: dueDate(i) })) },
    overdue: { amount: k.money.overdue.now, count: k.money.overdueInvoices.length },
    pipeline: { submitted: moves('submitted'), interviews: moves('interview_scheduled'), offers: moves('offer'), rolesOpened, openRoles: k.pipeline.openRoles.now, atRisk: k.pipeline.atRisk },
    tasks: { count: (tasks || []).length, top: (tasks || []).slice(0, 5).map(t => ({ user: t.user, title: t.title, dueDate: t.dueDate })) },
    decisions,
  };
}
export function weeklyBriefEmail(f) {
  const L = ['Daniel,', '', `Your week ahead, Monday ${ukDate(f.today)}.`, ''];
  L.push('CASH');
  L.push(f.cash.connected === false ? '- Bank not connected yet, so no cash figure.' : `- Balance ${gbp(f.cash.balance)}, ${gbp(f.cash.spendable)} spendable after the tax reserve. Lowest point in 90 days ${gbp(f.cash.lowest.balance)} on ${ukDate(f.cash.lowest.date)}.`, '');
  L.push('MONEY');
  L.push(`- In over the last 7 days: ${gbp(f.moneyIn.amount)} from ${plural(f.moneyIn.count, 'invoice')}.`);
  L.push(`- Due this week: ${gbp(f.dueThisWeek.amount)} from ${plural(f.dueThisWeek.count, 'invoice')}.`);
  f.dueThisWeek.items.forEach(i => L.push(`  ${i.company} ${i.number}: ${gbp(i.amount)} due ${ukDate(i.dueDate)}`));
  L.push(`- Overdue now: ${gbp(f.overdue.amount)} across ${plural(f.overdue.count, 'invoice')}.`, '');
  L.push('PIPELINE, LAST 7 DAYS');
  L.push(`- Candidates submitted ${f.pipeline.submitted}, interviews arranged ${f.pipeline.interviews}, offers ${f.pipeline.offers}, new roles opened ${f.pipeline.rolesOpened}.`);
  L.push(`- Open roles ${f.pipeline.openRoles}, of which ${f.pipeline.atRisk} with no recent activity.`, '');
  L.push('TASKS');
  L.push(f.tasks.count ? `- ${plural(f.tasks.count, 'task')} overdue across the team.` : '- No overdue tasks.');
  f.tasks.top.forEach(t => L.push(`  ${t.user}: ${t.title} (due ${t.dueDate})`));
  L.push('', 'NEEDS A DECISION');
  L.push(...(f.decisions.length ? f.decisions.map(d => `- ${d}`) : ['- Nothing needs a decision this week.']));
  L.push('', 'Live 2 Help dashboard');
  return { subject: tidy(`Live 2 Help week ahead: ${ukDate(f.today)}`), text: tidy(L.join('\n')) };
}

/* ======================================================================
   ELLA'S PERFORMANCE REPORT
   Built only from her own activity (computeMyKpi, which holds no money figure), the names of her placements and her review
   objectives. It never receives a pound figure, so none can appear.
   ====================================================================== */
const ACT_LABELS = [['candidatesAdded', 'Candidates added'], ['submissions', 'Candidates submitted'], ['interviewsBooked', 'Interviews arranged'], ['emails', 'Emails to clients and candidates'], ['calls', 'Calls made'], ['callsSpoke', 'Calls where you spoke to someone'], ['tasksDone', 'Tasks completed'], ['interviewsHeld', 'Interviews attended'], ['interviewsNoShow', 'Interviews missed (did not attend)']];

// my: computeMyKpi as at the last day of the month. wins: [{company, role, candidate}] placements in the month. reviews: her review rows.
export function buildEllaSnapshot({ period, my, wins, reviews, firstName, generatedAt }) {
  const A = my.activity, q = my.activityQuarter || {};
  const cur = k => (A[k] ? A[k].now : 0), prev = k => (A[k] ? A[k].before || 0 : 0);
  const ratio = (n, d) => (d > 0 ? Math.round((n / d) * 100) : null);
  const ratios = {
    interviewPerSubmission: { now: ratio(cur('interviewsBooked'), cur('submissions')), before: ratio(prev('interviewsBooked'), prev('submissions')) },
    connectRate: { now: ratio(cur('callsSpoke'), cur('calls')), before: ratio(prev('callsSpoke'), prev('calls')) },
    attendanceRate: { now: ratio(cur('interviewsHeld'), cur('interviewsHeld') + cur('interviewsNoShow')), before: ratio(prev('interviewsHeld'), prev('interviewsHeld') + prev('interviewsNoShow')) },
  };
  const qMonth = Number(period.slice(5, 7)) - 1, monthsIn = (qMonth % 3) + 1, quarterGone = Math.round((monthsIn / 3) * 100);
  const snap = {
    version: REPORT_VERSION, kind: 'ella', period, periodName: periodName(period), generatedAt, firstName: firstName || 'Ella',
    quarter: my.quarter, quarterGonePct: quarterGone,
    activity: ACT_LABELS.map(([key, label]) => ({ key, label, now: cur(key), before: A[key] ? A[key].before : null, diff: A[key] ? A[key].diff : 0, pct: A[key] ? A[key].pct : null })),
    quarterActivity: { submissions: q.submissions || 0, interviewsBooked: q.interviewsBooked || 0, calls: q.calls || 0, emails: q.emails || 0 },
    interviewsAwaiting: cur('interviewsAwaiting'),
    placements: my.placements, ratios,
    target: my.target, teamTarget: my.teamTarget, teamRolesFilledQuarter: my.teamRolesFilledQuarter,
    wins: (wins || []).map(w => ({ company: w.company, role: w.role, candidate: w.candidate || 'A candidate' })),
    // objectives are shown only when they hold nothing restricted: otherwise she is pointed to her own review page
    reviews: (reviews || []).map(r => ({ kind: r.kind, dueDate: r.due_date, status: r.status, objectives: ellaViolations(r.objectives || '').length ? 'See People > Reviews for the full objectives.' : String(r.objectives || '').slice(0, 400) })),
  };
  snap.highlights = ellaHighlights(snap);
  snap.improve = ellaImprove(snap);
  snap.focus = ellaFocus(snap);
  return snap;
}
// build 66.2: attended / (attended + did not attend), for the owner report team table
function attendTxt(a) {
  const h = a && a.interviewsHeld ? a.interviewsHeld.now : 0, m = a && a.interviewsNoShow ? a.interviewsNoShow.now : 0;
  return h + m > 0 ? `${h} of ${h + m} (${Math.round((h / (h + m)) * 100)}%)` : 'none recorded';
}
function ellaHighlights(s) {
  const out = [];
  s.wins.forEach(w => out.push(`Placement: ${w.candidate} at ${w.company} as ${w.role}.`));
  s.activity.filter(a => a.diff > 0 && a.now >= 3 && a.key !== 'tasksDone').forEach(a => out.push(`${a.label} rose from ${a.before} to ${a.now}${a.pct != null ? ` (${a.pct > 0 ? '+' : ''}${a.pct}%)` : ''}.`));
  const r = s.ratios.connectRate;
  if (r.now != null && r.before != null && r.now > r.before && s.activity.find(a => a.key === 'calls').now >= 10) out.push(`More of your calls reached someone: ${r.now}% against ${r.before}% the month before.`);
  const ar = s.ratios.attendanceRate, held = s.activity.find(a => a.key === 'interviewsHeld'), miss = s.activity.find(a => a.key === 'interviewsNoShow');
  if (ar.now != null && held && miss && held.now + miss.now >= 3 && ar.now >= 80) out.push(`Candidates turned up for ${ar.now}% of interviews (${held.now} of ${held.now + miss.now}).`);
  if (!out.length) out.push('A steady month. The figures below show where the effort went.');
  return out.map(tidy).slice(0, 6);
}
function ellaImprove(s) {
  const out = [];
  const get = k => s.activity.find(a => a.key === k);
  const sub = get('submissions'), calls = get('calls'), ints = get('interviewsBooked'), emails = get('emails');
  if (sub.before >= 3 && sub.now < sub.before * 0.8) out.push(`Submissions fell from ${sub.before} to ${sub.now}. Aim to get back to ${sub.before} next month by keeping two or three strong candidates ready for each open role.`);
  const cr = s.ratios.connectRate.now;
  if (calls.now >= 10 && cr != null && cr < 30) out.push(`You spoke to someone on ${get('callsSpoke').now} of ${calls.now} calls (${cr}%). Try different times of day, and follow each missed call with a short email the same day.`);
  const ip = s.ratios.interviewPerSubmission.now;
  if (sub.now >= 4 && ip != null && ip < 25) out.push(`Fewer than one in four submissions led to an interview (${ints.now} from ${sub.now}). Check the match against the role requirements before submitting, and ask the client what held the others back.`);
  const ar = s.ratios.attendanceRate, held = get('interviewsHeld'), miss = get('interviewsNoShow');
  if (held && miss && held.now + miss.now >= 3 && ar.now != null && ar.now < 70) out.push(`Candidates attended ${held.now} of ${held.now + miss.now} interviews (${ar.now}%). Confirm each interview with the candidate the day before, and share the address and who to ask for.`);
  if (s.interviewsAwaiting > 0) out.push(`${s.interviewsAwaiting} interview${s.interviewsAwaiting === 1 ? ' has' : 's have'} no outcome recorded. Mark each one Completed or No show so the attendance figure is right.`);
  if (calls.now + emails.now === 0) out.push('No calls or emails were logged. If you did the work outside the workspace, log it there so the figures show your real effort.');
  const t = s.target && Number(s.target.targetRoles);
  if (t > 0 && s.placements.quarter < t * (s.quarterGonePct / 100) - 0.5) out.push(`You have ${s.placements.quarter} of ${t} placements for ${s.quarter} with ${s.quarterGonePct}% of the quarter gone. Decide which roles are closest to an offer and put the most time there.`);
  if (!out.length) out.push('Nothing stands out as a gap this month. Keep the same pace, and look for the next role that can move from interview to offer.');
  return out.map(tidy).slice(0, 4);
}
function ellaFocus(s) {
  const out = [];
  const first = s.improve[0];
  if (first && !/^Nothing stands out/.test(first)) out.push(first);
  const t = s.target && Number(s.target.targetRoles);
  if (t > 0) out.push(`Move towards ${t} placements for ${s.quarter}: you are on ${s.placements.quarter} so far.`);
  else out.push('Agree a placement target for the quarter with Daniel so progress can be measured.');
  out.push('Log every call and email in the workspace on the day, so the report shows the whole picture.');
  const nextReview = s.reviews.find(r => lc(r.status) !== 'completed' && lc(r.status) !== 'done');
  if (nextReview) out.push(`Prepare for your ${tidy(nextReview.kind)} on ${ukDate(nextReview.dueDate)}.`);
  return out.map(tidy).slice(0, 3);
}

const fmtTrendRow = a => [a.label, String(a.now), a.before == null ? '' : String(a.before), a.pct == null ? '' : `${a.pct > 0 ? '+' : ''}${a.pct}%`];
export function ellaReportMarkdown(s, note) {
  const L = [];
  const h = t => L.push('', `## ${t}`, '');
  const table = (head, rows) => { L.push(`| ${head.map(cell).join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map(r => `| ${r.map(cell).join(' | ')} |`), ''); };
  L.push('---', `title: Performance report: ${s.periodName}`, `subtitle: ${s.firstName}`, `version: ${s.periodName}. Private to ${s.firstName} and Daniel Brown.`, '---', '');
  L.push(`This report looks at your activity in ${s.periodName} against the month before. The aim is to show what went well, where there is room to improve, and what to focus on next.`);
  if (note) { h('A note from Daniel'); L.push(...String(note).trim().split(/\n{2,}/).map(p => tidy(p.replace(/\n/g, ' '))).flatMap(p => [p, '']), ''); }
  h('What went well');
  L.push(...s.highlights.map(x => `- ${x}`), '');
  h('Your activity');
  table(['Measure', s.periodName, 'Month before', 'Change'], s.activity.map(fmtTrendRow));
  const r = s.ratios;
  table(['What the numbers mean', s.periodName, 'Month before'], [
    ['Interviews arranged for every 100 submissions', r.interviewPerSubmission.now == null ? 'n/a' : String(r.interviewPerSubmission.now), r.interviewPerSubmission.before == null ? 'n/a' : String(r.interviewPerSubmission.before)],
    ['Calls that reached someone', r.connectRate.now == null ? 'n/a' : `${r.connectRate.now}%`, r.connectRate.before == null ? 'n/a' : `${r.connectRate.before}%`],
    ['Interviews attended, out of those with an outcome', r.attendanceRate.now == null ? 'n/a' : `${r.attendanceRate.now}%`, r.attendanceRate.before == null ? 'n/a' : `${r.attendanceRate.before}%`],
  ]);
  h(`Placements and targets for ${s.quarter}`);
  table(['Measure', 'Figure'], [
    ['Your placements this month', String(s.placements.month)], [`Your placements this quarter`, String(s.placements.quarter)], ['Your placements this year', String(s.placements.ytd)],
    ['Your placement target for the quarter', s.target && s.target.targetRoles ? String(s.target.targetRoles) : 'Not set'],
    ['Team roles filled this quarter', String(s.teamRolesFilledQuarter)], ['Share of the quarter gone', `${s.quarterGonePct}%`],
  ]);
  if (s.wins.length) table(['Placement', 'Client', 'Role'], s.wins.map(w => [w.candidate, w.company, w.role]));
  h('Where to improve');
  L.push(...s.improve.map(x => `- ${x}`), '');
  h('Focus for next month');
  L.push(...s.focus.map((x, i) => `${i + 1}. ${x}`), '');
  if (s.reviews.length) {
    h('Reviews and goals');
    table(['Review', 'Due', 'Status', 'Objectives'], s.reviews.map(x => [x.kind, ukDate(x.dueDate), x.status, x.objectives || 'To be agreed']));
  }
  return tidy(L.join('\n'));
}
export function ellaReportEmail(s, note) {
  const parts = [`Hi ${s.firstName},`, '', `Your performance report for ${s.periodName} is attached.`, ''];
  const get = k => s.activity.find(a => a.key === k);
  parts.push('The headlines:', `- Candidates submitted: ${vs({ now: get('submissions').now, before: get('submissions').before, pct: get('submissions').pct })}`,
    `- Interviews arranged: ${get('interviewsBooked').now}`, `- Calls made: ${get('calls').now}, and you spoke to someone on ${get('callsSpoke').now}`,
    `- Placements this month: ${s.placements.month}, this quarter: ${s.placements.quarter}`, '');
  if (note && String(note).trim()) parts.push(tidy(String(note).trim()), '');
  parts.push('Have a read, and we will talk it through at our next catch up.', '', 'Daniel', 'Daniel Brown', 'Managing Director, Live 2 Help Recruitment');
  return { subject: tidy(`Your performance report: ${s.periodName}`), text: tidy(parts.join('\n')) };
}

/* ---------- the guard: nothing about money, pay, tax or cost may be in Ella's report ---------- */
export const ELLA_BLOCKED = /[£$€]|commission|salary|salaries|pension|payroll|\bpay\b|\bwages?\b|margin|profit|corporation|\btax\b|\bvat\b|overhead|\bbank\b|revenue|turnover|invoice|\bfees?\b|\bcosts?\b|dividend|\bbonus|\bbilling|\bcash\b/i;
// allow: strings that may contain a blocked word legitimately (client names, role titles, candidate names). They are removed before the scan.
export function ellaViolations(text, allow = []) {
  let t = String(text || '');
  [...new Set(allow.filter(Boolean).map(String))].sort((a, b) => b.length - a.length).forEach(a => { t = t.split(a).join(' '); });
  const bad = [];
  const re = new RegExp(ELLA_BLOCKED.source, 'gi');
  let m;
  while ((m = re.exec(t))) bad.push(m[0]);
  return [...new Set(bad.map(b => b.toLowerCase()))];
}
export function ellaAllowList(snap) {
  return [...snap.wins.flatMap(w => [w.company, w.role, w.candidate]), ...snap.reviews.map(r => r.kind)];
}
// Throws if anything restricted is in the generated report (markdown and email text). The note is checked too.
export function assertEllaClean(snap, note) {
  const allow = ellaAllowList(snap);
  const md = ellaReportMarkdown(snap, note), mail = ellaReportEmail(snap, note);
  const bad = [...ellaViolations(md, allow), ...ellaViolations(mail.text + ' ' + mail.subject, allow)];
  if (bad.length) { const e = new Error(`The report mentions ${[...new Set(bad)].join(', ')}. Keep pay, commission and company money figures out of Ella's report.`); e.restricted = [...new Set(bad)]; throw e; }
  return { markdown: md, email: mail };
}
