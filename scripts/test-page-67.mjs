// Build 67 page test: the Targets and profitability panel and Ella's own targets, run in a sandbox with stubbed calls.
//   node scripts/test-page-67.mjs [path to page]   (default: dashboard-next/index.html)
import fs from 'fs'; import vm from 'vm'; import assert from 'assert';
const s = fs.readFileSync(process.argv[2] || new URL('../dashboard-next/index.html', import.meta.url).pathname, 'utf8');
const a = s.indexOf('var P67 = {'); const b = s.indexOf('var P66 = {');
const code = s.slice(a, b);
const els = {}; const el = id => els[id] || (els[id] = { id, innerHTML: '', value: '' });
const toasts = []; const posted = [];
let api = {}, post = {}, owner = true;
const ctx = {
  document: { getElementById: el }, esc: x => String(x == null ? '' : x).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'),
  showToast: m => toasts.push(m), p64Owner: () => owner, k62Money: n => n == null ? '-' : '£' + Math.round(n).toLocaleString('en-GB'),
  b2Api: async u => { if (api[u] instanceof Error) throw api[u]; return api[u]; }, b2Post: async (u, body) => { posted.push([u, body]); if (post[u] instanceof Error) throw post[u]; return post[u]; },
  console, Date, Math, JSON, parseFloat, parseInt, isNaN,
};
vm.createContext(ctx); vm.runInContext(code, ctx);
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const act = v => ({ year: v * 12, month: v, week: v / 4 });
const data = {
  year: 2027, bankConnected: false, ellaShare: 1, ellaOverride: { submissions: { month: 20 } }, lines: [{ key: 'perm', label: 'Permanent placement' }, { key: 'partnership', label: 'Talent Partnership' }, { key: 'suite', label: 'Talent Suite' }, { key: 'youth', label: 'Funded Youth Hire' }],
  back: { goal: { year: 2027, total: 100000, lines: { perm: 85000, partnership: 0, suite: 10000, youth: 5000 } }, byLine: [{ key: 'perm', label: 'Permanent placement', year: 85000, month: 7083 }, { key: 'suite', label: 'Talent Suite', year: 10000, month: 833 }],
    activity: { placements: act(2), candidatesAdded: act(30), submissions: act(10), interviews: act(5), calls: act(100), emails: act(200) },
    assumptions: { avgFee: 4000, source: { avgFee: 'measured' }, candidatesPerPlacement: 15, submissionsPerPlacement: 5, interviewsPerPlacement: 2, callsPerPlacement: 50, emailsPerPlacement: 90, placementsLast12Months: 5, workingWeeksPerYear: 46, note: 'Ratios are measured from the last 12 months of placements.' } },
  progress: { set: true, started: false, startsOn: '2027-01-01', goal: 100000 }, thisYearTotal: 22148, thisYearByLine: [{ key: 'perm', label: 'Permanent placement', amount: 22000 }],
  invoices: [{ number: 'INV-1', date: '2027-01-10', company: 'Acme', role: 'Engineer', amount: 4000, line: 'perm' }, { number: 'INV-2', date: '2027-02-10', company: 'Beta', role: 'Fitter', amount: 2000, line: 'partnership' }],
  profitability: { roles: [{ company: 'Gamma', role: 'Welder', status: 'open', daysOpen: 62, feeEarned: 0, adSpend: 800, net: -800, candidates: 1, submitted: 0, flags: ['Costs more than it has returned'] }], clients: [{ company: 'Gamma', roles: 1, feeEarned: 0, adSpend: 800, net: -800, worth: 'No return yet' }], unallocatedAdSpend12m: 300, manualAdMonthly: 100, notes: ['Advertising is counted only where it was logged against a company and role.'] },
};
el('p67Targets'); api['/api/targets'] = data;
await ctx.p67Load(); let h = el('p67Targets').innerHTML;
ok(/Targets and profitability/.test(h) && /Annual revenue goal for 2027/.test(h), 'panel title and goal form');
ok(/Starling bank is not connected yet/.test(h), 'bank reminder shown while the bank is not connected');
ok(/goal starts on 2027-01-01/.test(h), 'goal year not started yet message');
ok(/Permanent placement \(the rest\)/.test(h) && /Talent Suite \(optional\)/.test(h), 'four service lines in the form');
ok(/Costs more than it has returned/.test(h) && /No return yet/.test(h) && /Advertising with no role/.test(h), 'profitability flags and clients');
ok(/Assumptions\./.test(h) && /measured/.test(h), 'assumptions shown openly');
ok(/Save Ella/.test(h) && /value="20"/.test(h), 'Ella override shown');
ok(/<option value="partnership" selected>/.test(h), 'invoice tagged with its line');
ok(!/[—–]/.test(h), 'no em or en dashes');
// started progress
api['/api/targets'] = { ...data, progress: { set: true, started: true, status: 'behind', soldToDate: 22148, expectedToDate: 50000, gap: -27852, goal: 100000, needPerMonthFromNow: 14000, lines: [{ key: 'perm', sold: 22148 }] } };
await ctx.p67Load(); h = el('p67Targets').innerHTML;
ok(/Behind/.test(h) && /gap of £27,852/.test(h) && /£14,000 a month/.test(h), 'behind message with the gap');
api['/api/targets?year=2027&fresh=1'] = data;
// saving the goal
post['/api/targets/goal'] = { ok: true }; el('p67Total').value = '100000'; el('p67L_suite').value = '10000'; el('p67L_partnership').value = ''; el('p67L_youth').value = '';
await ctx.p67SaveGoal();
ok(posted[0][0] === '/api/targets/goal' && posted[0][1].total === '100000' && posted[0][1].lines.suite === '10000' && !('partnership' in posted[0][1].lines), 'goal posts only the filled lines');
post['/api/targets/goal'] = new Error('Enter the annual revenue goal as a number, for example 100000');
await ctx.p67SaveGoal(); ok(/Enter the annual revenue goal/.test(el('p67Targets').innerHTML), 'a refused goal shows its reason in the panel');
// tagging
post['/api/targets/service-line'] = { ok: true }; post['/api/targets/goal'] = { ok: true };
await ctx.p67Tag('INV-1', 'youth'); ok(posted.some(p => p[0] === '/api/targets/service-line' && p[1].line === 'youth'), 'tag posts the line');
// override
post['/api/targets/override'] = { ok: true };
['placements','candidatesAdded','submissions','interviews','calls','emails'].forEach(k => { el('p67OM_' + k).value = ''; el('p67OW_' + k).value = ''; }); el('p67OM_submissions').value = '25'; el('p67Share').value = '100';
await ctx.p67SaveOverride(); const ovp = posted.filter(p => p[0] === '/api/targets/override')[0][1];
ok(ovp.override.submissions.month === '25' && !ovp.override.calls && ovp.person === 'ella', 'override posts only what was typed');
// not the owner: nothing rendered
owner = false; el('p67Targets').innerHTML = 'x'; await ctx.p67Load(); ok(el('p67Targets').innerHTML === '', 'a non owner sees nothing on the owner panel');
// Ella
el('p67Mine');
api['/api/targets/mine'] = { set: true, year: 2027, rows: [{ key: 'submissions', monthDone: 4, monthTarget: 10, weekDone: 1, weekTarget: 2.5, status: 'behind', gapMonth: 6, manual: true }, { key: 'calls', monthDone: 90, monthTarget: 100, weekDone: 20, weekTarget: 25, status: 'on_track', gapMonth: 10, manual: false }] };
await ctx.p67LoadMine(); h = el('p67Mine').innerHTML;
ok(/Your targets/.test(h) && /set by Daniel/.test(h) && /6 to go this month/.test(h) && /On track/.test(h), 'Ella sees her targets and progress');
ok(!/£|revenue|\bfee|margin|cost|spend/i.test(h.replace(/<[^>]*>/g, ' ')), 'Ella view holds no money wording');
api['/api/targets/mine'] = { owner: true }; await ctx.p67LoadMine(); ok(el('p67Mine').innerHTML === '', 'owner gets nothing on the personal card');
api['/api/targets/mine'] = { set: false }; await ctx.p67LoadMine(); ok(el('p67Mine').innerHTML === '', 'no goal means no card');
console.log(`page 67 panel: all ${n} checks passed`);
