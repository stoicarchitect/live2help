// Build 70 page test: pension status and NI helpers, cost maths, team list line. node scripts/test-page-70.mjs [page]
import fs from 'fs'; import vm from 'vm'; import assert from 'assert';
const s = fs.readFileSync(process.argv[2] || new URL('../dashboard-next/index.html', import.meta.url).pathname, 'utf8');
const a = s.indexOf('/* ---------- Build 70: pension status'), b = s.indexOf('function calculateEmployeeYTDSalary(emp){');
assert.ok(a > 0 && b > a, 'build 70 helpers and empCost found');
const store = {};
const ctx = { console, Date, Math, parseFloat, round2: n => Math.round((n || 0) * 100) / 100, finGet: k => store[k] || '' };
vm.createContext(ctx); vm.runInContext(s.slice(a, b), ctx);
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; }; const eq = (x, y, m) => { assert.deepStrictEqual(x, y, m); n++; };
const ella = { name: 'Ella Pietrzak', salary: 25000, startDate: '2026-11-02', pensionPct: 3, pensionStatus: 'not_enrolled', niExempt: true };
eq(ctx.epAutoEnrolDue(ella), '2027-02-02', 'auto-enrolment is 3 months after 2 Nov 2026');
eq(ctx.epAddMonths('2026-11-30', 3), '2027-02-28', 'month end clamps');
eq(ctx.epPensionActive(ella, '2026-11-30'), false, 'not enrolled is never active');
eq(ctx.epPensionActive({ pensionPct: 3 }, '2026-11-30'), true, 'people added before build 70 stay enrolled');
eq(ctx.epPensionActive({ pensionStatus: 'enrolled', pensionStart: '2027-02-02' }, '2027-01-31'), false, 'enrolled from Feb is not active in January');
eq(ctx.epPensionActive({ pensionStatus: 'enrolled', pensionStart: '2027-02-02' }, '2027-02-28'), true, 'active in the month holding the enrolment date');
eq([ctx.epNiExempt({}), ctx.epNiExempt({ niExempt: true }), ctx.epNiExempt({ niExempt: false })], [true, true, false], 'NI exempt by default, off only when false');
ok(/not enrolled \(auto-enrolment due by 2027-02-02\)/.test(ctx.epPensionLine(ella)), 'team list line for Ella');
// cost maths in a year view: no pension while not enrolled, NI only when not exempt
const c = ctx.empCost(ella, 2026);
eq([c.pension, c.ni], [0, 0], 'not enrolled and exempt: salary only');
const c2 = ctx.empCost({ ...ella, niExempt: false }, 2026);
ok(c2.ni > 0 && c2.total === Math.round((c2.salary + c2.pension + c2.ni) * 100) / 100, 'NI counted in the total when not exempt');
const c3 = ctx.empCost({ ...ella, pensionStatus: 'enrolled', pensionStart: '' }, 2026);
ok(c3.pension > 0, 'enrolled from the start accrues pension');
store['l2h-ni-rate-pct'] = '20'; store['l2h-ni-threshold-year'] = '6000';
eq(JSON.stringify(ctx.epNiRates()), JSON.stringify({ ratePct: 20, thresholdYear: 6000 }), 'rates come from settings');
// no em dashes in what the page writes into the payroll email
ok(!/—/.test(s.slice(a, b)), 'no em dash in build 70 page code');
console.log(`test-page-70: ${n} checks passed`);
