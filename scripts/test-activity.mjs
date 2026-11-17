// Build 66.2: calls counted under one person key, and interview attendance. Run: node scripts/test-activity.mjs
import { computeMyKpi, computeOwnerKpi, personKey } from '../kpi-owner.js';
import { buildEllaSnapshot, ellaReportMarkdown } from '../reports.js';
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

ok(personKey('Ella') === 'ella' && personKey('ella@live2helprecruitment.co.uk') === 'ella' && personKey('Ella Pietrzak') === 'ella' && personKey('dan.brown@live2helprecruitment.co.uk') === 'dan' && personKey('') === '', 'personKey variants');

const now = new Date('2026-10-31T12:00:00Z');
const comms = [
  { timestamp: '2026-10-05T09:00:00Z', user: 'ella', channel: 'call', summary: 'Call - spoke to them: ok' },
  { timestamp: '2026-10-06T09:00:00Z', user: 'Ella', channel: 'Call', summary: 'Call - no answer' },
  { timestamp: '2026-10-07T09:00:00Z', user: 'ella@live2helprecruitment.co.uk', channel: 'call', summary: 'Cold call - attempt' },
  { timestamp: '2026-10-08T09:00:00Z', user: 'dan', channel: 'call', summary: 'x' },
  { timestamp: '2026-09-08T09:00:00Z', user: 'ella', channel: 'call', summary: 'last month' },
];
const iv = (date, status, by) => ({ id: date + status + by, date, status, created_by: by });
const interviews = [
  iv('2026-10-02', 'completed', 'ella'), iv('2026-10-03', 'completed', 'Ella'), iv('2026-10-09', 'completed', 'ella'),
  iv('2026-10-10', 'no_show', 'ella'), iv('2026-10-12', 'cancelled', 'ella'), iv('2026-10-20', 'scheduled', 'ella'),
  iv('2026-10-31', 'scheduled', 'ella'), iv('2026-10-11', 'completed', 'dan'),
  iv('2026-09-10', 'completed', 'ella'), iv('2026-09-11', 'no_show', 'ella'),
];
const my = computeMyKpi({ now, comms, interviews, invoices: [], candidates: [] }, 'ella');
const A = my.activity;
ok(A.calls.now === 3, 'three Ella calls counted whatever the user was stored as: ' + A.calls.now);
ok(A.callsSpoke.now === 1, 'spoke to them counted');
ok(A.calls.before === 1, 'last month calls');
ok(A.interviewsHeld.now === 3 && A.interviewsNoShow.now === 1, 'attended 3, did not attend 1');
ok(A.interviewsAwaiting.now === 1, 'only the past scheduled interview has no outcome (the one on the 31st is today)');
ok(A.interviewsHeld.before === 1 && A.interviewsNoShow.before === 1, 'month before');
const dan = computeMyKpi({ now, comms, interviews, invoices: [], candidates: [] }, 'dan');
ok(dan.activity.interviewsHeld.now === 1 && dan.activity.calls.now === 1, 'dan is separate');

const snap = buildEllaSnapshot({ period: '2026-10', my, wins: [], reviews: [], firstName: 'Ella', generatedAt: '2026-11-01T08:00:00Z' });
ok(snap.ratios.attendanceRate.now === 75 && snap.ratios.attendanceRate.before === 50, 'attendance 75 percent, 50 before');
ok(snap.interviewsAwaiting === 1, 'awaiting carried');
const md = ellaReportMarkdown(snap, '');
ok(/Interviews attended/.test(md) && /75%/.test(md), 'report shows attendance');
ok(/no outcome recorded/.test(md), 'report asks for the missing outcome');
ok(!/[£$]|commission|salary|margin|revenue/i.test(md), 'no money wording in Ella report');
ok(!/[–—]/.test(md), 'no dashes');

// low attendance advice
const low = computeMyKpi({ now, comms: [], interviews: [iv('2026-10-02', 'completed', 'ella'), iv('2026-10-03', 'no_show', 'ella'), iv('2026-10-04', 'no_show', 'ella')], invoices: [], candidates: [] }, 'ella');
const lowSnap = buildEllaSnapshot({ period: '2026-10', my: low, wins: [], reviews: [], firstName: 'Ella', generatedAt: '2026-11-01T08:00:00Z' });
ok(lowSnap.improve.some(x => /attended 1 of 3/.test(x)), 'low attendance advice');

console.log(bad ? `${bad} of ${n} checks failed` : `activity: all ${n} checks passed`);
process.exit(bad ? 1 : 0);
