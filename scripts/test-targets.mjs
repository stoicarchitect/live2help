// Build 67: targets, service lines, role profitability. Run: node scripts/test-targets.mjs
import { salesByLine, historicalRatios, normaliseGoal, backwardsTargets, goalProgress, targetsForPerson, personProgress, roleProfitability, computeTargets, RATIO_DEFAULTS } from '../targets.js';
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const near = (a, b, t = 0.01) => Math.abs(a - b) <= t;

const now = new Date('2027-07-02T12:00:00Z');
const inv = (number, date, amount, company = 'Acme', role = 'Engineer') => ({ number, date, amount, company, role });
const invoices = [inv('A1', '2027-01-10', 4000), inv('A2', '2027-02-10', 3000), inv('A3', '2027-03-10', 5000), inv('A4', '2027-04-10', 3000), inv('A5', '2027-05-10', 5000, 'Beta', 'Fitter'), inv('P1', '2027-05-20', 2000, 'Beta', 'Workshop')];
const otherSales = [{ date: '2027-03-01', amount: 99, kind: 'Talent Suite order' }, { date: '2027-04-01', amount: 49, kind: 'Credit top-up' }];
const serviceTags = { P1: 'partnership' };
const input = { invoices, otherSales, serviceTags, now };

// service lines always add up to total revenue
const s = salesByLine(input, new Date('2027-01-01T00:00:00Z'), new Date('2028-01-01T00:00:00Z'));
ok(s.byLine.perm === 20000 && s.byLine.partnership === 2000 && s.byLine.suite === 148 && s.byLine.youth === 0, 'lines: ' + JSON.stringify(s.byLine));
ok(near(Object.values(s.byLine).reduce((a, b) => a + b, 0), s.total), 'service lines sum to total revenue');
ok(s.total === 22148, 'total ' + s.total);
ok(salesByLine({ invoices: [inv('Z', '2027-01-01', 10)], serviceTags: { Z: 'nonsense' } }, new Date('2027-01-01T00:00:00Z'), new Date('2028-01-01T00:00:00Z')).byLine.perm === 10, 'unknown tag falls back to permanent');

// goal normalising: unallocated money goes to permanent, lines never exceed the goal
const g1 = normaliseGoal({ year: 2027, total: 100000, lines: { suite: 10000, youth: 5000 } });
ok(g1.lines.perm === 85000 && g1.lines.suite === 10000 && g1.lines.youth === 5000, 'goal split: ' + JSON.stringify(g1.lines));
const g2 = normaliseGoal({ year: 2027, total: 100000, lines: { perm: 90000, suite: 90000 } });
ok(near(Object.values(g2.lines).reduce((a, b) => a + b, 0), 100000, 0.1), 'lines never exceed the goal');
ok(normaliseGoal({ year: 2027, total: 100000 }).lines.perm === 100000, 'no lines means all permanent');

// ratios: too little history uses defaults and says so
const hist0 = historicalRatios({ invoices: [inv('A1', '2027-01-10', 4000)], now }, new Date('2027-07-02T00:00:00Z'));
ok(!hist0.usedHistory && hist0.ratios.avgFee === RATIO_DEFAULTS.avgFee && hist0.source.avgFee === 'default', 'defaults when fewer than 3 placements');
// enough history measures the average fee and per placement activity
const activity = [];
for (let i = 0; i < 25; i++) activity.push({ timestamp: '2027-03-0' + (1 + (i % 9)) + 'T09:00:00Z', user: 'ella', action: 'submitted' });
for (let i = 0; i < 10; i++) activity.push({ timestamp: '2027-04-0' + (1 + (i % 9)) + 'T09:00:00Z', user: 'ella', action: 'interview_booked' });
const hist = historicalRatios({ invoices, serviceTags, activity, comms: [{ timestamp: '2027-03-03T09:00:00Z', user: 'ella', channel: 'call' }, { timestamp: '2027-03-04T09:00:00Z', user: 'ella', channel: 'email', direction: 'inbound' }], now }, new Date('2027-07-02T00:00:00Z'));
ok(hist.usedHistory && hist.placementsLast12Months === 5, 'five permanent placements, the partnership invoice is not one');
ok(near(hist.ratios.avgFee, 4000), 'average fee ' + hist.ratios.avgFee);
ok(hist.ratios.submissionsPerPlacement === 5 && hist.ratios.interviewsPerPlacement === 2, 'per placement ratios ' + hist.ratios.submissionsPerPlacement + ' ' + hist.ratios.interviewsPerPlacement);
ok(hist.ratios.emailsPerPlacement === RATIO_DEFAULTS.emailsPerPlacement && hist.source.emailsPerPlacement === 'default', 'received email does not count, so the default is shown as a default');

// hand check of the working backwards maths: 100000 goal, all permanent, average fee 4000 -> 25 placements a year
const back = backwardsTargets({ year: 2027, total: 100000 }, hist);
ok(back.revenue.month === 8333.33 && near(back.revenue.week, 100000 / 46), 'revenue per month and week');
ok(back.activity.placements.year === 25 && back.activity.placements.month === 2.1, 'placements ' + JSON.stringify(back.activity.placements));
ok(back.activity.submissions.year === 125 && back.activity.submissions.month === 10.4, 'submissions 25 x 5 = 125 a year: ' + JSON.stringify(back.activity.submissions));
ok(back.activity.interviews.year === 50, 'interviews 25 x 2 = 50 a year');
// with a line goal for Talent Suite the permanent goal drops and so do the placements
const back2 = backwardsTargets({ year: 2027, total: 100000, lines: { suite: 20000 } }, hist);
ok(back2.activity.placements.year === 20, 'permanent goal 80000 / 4000 = 20 placements');
ok(near(back2.byLine.reduce((a, l) => a + l.year, 0), 100000, 0.1), 'line goals add up to the goal');

// progress
const pr = goalProgress(input, { year: 2027, total: 100000 }, new Date('2027-07-02T00:00:00Z'));
ok(pr.started && pr.soldToDate === 22148 && pr.status === 'behind' && pr.gap < 0, 'behind: ' + JSON.stringify([pr.soldToDate, pr.expectedToDate, pr.status]));
ok(near(pr.needPerMonthFromNow, (100000 - 22148) / (12 - (183 / 365) * 12), 5), 'needed per month from now ' + pr.needPerMonthFromNow);
ok(goalProgress({ invoices: [inv('B1', '2027-06-01', 60000)], now }, { year: 2027, total: 100000 }, new Date('2027-07-02T00:00:00Z')).status === 'ahead', 'ahead');
ok(goalProgress(input, { year: 2027, total: 100000 }, new Date('2026-11-18T00:00:00Z')).started === false, 'goal year not started yet');
ok(goalProgress(input, { year: 0, total: 0 }, new Date()).set === false, 'no goal set');
ok(pr.lines.reduce((a, l) => a + l.sold, 0) === pr.soldToDate, 'progress lines add up');

// Ella: counts only, manual override wins and is flagged
const e1 = targetsForPerson(back, 1, null);
ok(e1.submissions.month === 10.4 && e1.submissions.manual === false, 'Ella target calculated');
const e2 = targetsForPerson(back, 1, { submissions: { month: 20 } });
ok(e2.submissions.month === 20 && e2.submissions.manual === true && e2.submissions.week === e1.submissions.week, 'manual override persists and is flagged');
const e3 = targetsForPerson(back, 0.5, null);
ok(e3.submissions.month === 5.2, 'share of the team target');
const noMoney = JSON.stringify({ e1, pp: personProgress({ activity: [], comms: [], interviews: [] }, 'ella', e1, new Date('2027-07-02T00:00:00Z')) });
ok(!/revenue|fee|£|amount|margin|cost|spend/i.test(noMoney), 'Ella data holds no money wording');
const pp = personProgress({ activity: [{ timestamp: '2027-07-01T09:00:00Z', user: 'Ella Pietrzak', action: 'submitted' }], comms: [{ timestamp: '2027-07-01T09:00:00Z', user: 'ella', channel: 'call' }], interviews: [{ date: '2027-07-01', created_by: 'Ella', status: 'completed' }] }, 'ella', e1, new Date('2027-07-02T00:00:00Z'));
ok(pp.rows.find(r => r.key === 'submissions').monthDone === 1 && pp.rows.find(r => r.key === 'calls').monthDone === 1 && pp.rows.find(r => r.key === 'interviews').monthDone === 1, 'progress counts under one person key');

// profitability
const prof = roleProfitability({
  now, invoices, settings: {}, fin: { manualAd: 100 },
  roles: [{ company: 'Acme', role: 'Engineer', status: 'filled', date_opened: '2027-01-01', date_closed: '2027-01-20' }, { company: 'Gamma', role: 'Welder', status: 'open', date_opened: '2027-05-01' }, { company: 'Delta', role: 'Clerk', status: 'open', date_opened: '2027-06-28' }],
  adSpend: [{ date: '2027-01-05', amount: 500, company: 'Acme', role: 'Engineer' }, { date: '2027-05-05', amount: 800, company: 'Gamma', role: 'Welder' }, { date: '2027-06-01', amount: 300, company: '', role: '' }],
  candidates: [{ company: 'Gamma', role: 'Welder', stage: 'applied' }],
}, new Date('2027-07-02T00:00:00Z'));
const acme = prof.roles.find(r => r.company === 'Acme'), gam = prof.roles.find(r => r.company === 'Gamma');
ok(acme.feeEarned === 15000 && acme.adSpend === 500 && acme.net === 14500 && acme.flags.length === 0, 'role that earned more than it cost is not flagged');
ok(gam.adSpend === 800 && gam.feeEarned === 0 && gam.flags.some(f => /Costs more/.test(f)) && gam.flags.some(f => /no candidate submitted/.test(f)), 'role that cost more than it returned is flagged: ' + JSON.stringify(gam.flags));
ok(prof.unallocatedAdSpend12m === 300, 'shared advertising is shown as unallocated, not guessed');
ok(prof.clients.find(c => c.company === 'Acme').worth === 'Earning' && prof.clients.find(c => c.company === 'Gamma').worth === 'No return yet', 'client verdicts');
ok(prof.roles[0].company === 'Gamma', 'flagged roles come first');

// one view
const all = computeTargets({ ...input, activity, comms: [], interviews: [], roles: [], candidates: [], adSpend: [], settings: {}, fin: {} }, { year: 2027, total: 100000 }, { ellaShare: 1 });
ok(all.thisYearTotal === 22148 && all.back.goal.total === 100000 && all.ella.placements.month > 0, 'computeTargets ties it together');

console.log(bad ? `${bad} of ${n} checks failed` : `targets: all ${n} checks passed`);
process.exit(bad ? 1 : 0);
