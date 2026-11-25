// Build 73.4 tests: node scripts/test-sidebar-filled.mjs
// Filled roles stay in the sidebar for check-ins until the guarantee ends. The rule is read out of the page itself.
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const page = fs.readFileSync(process.argv[2] ? path.resolve(process.argv[2]) : path.join(root, 'dashboard', 'index.html'), 'utf8');
const m = page.match(/\/\*SB-FILLED-START\*\/([\s\S]*?)\/\*SB-FILLED-END\*\//);
assert.ok(m, 'the filled role rule is in the page');
const sbStillCheckingIn = new Function(m[1] + '; return sbStillCheckingIn;')();
let n = 0; const eq = (a, b, msg) => { assert.strictEqual(a, b, msg); n++; };
const today = '2026-12-01';

eq(sbStillCheckingIn({stage:'offer'}, null, 12, today), true, 'an offer not yet started keeps the filled role showing');
eq(sbStillCheckingIn({stage:'week1', startDate:'2026-11-23'}, null, 12, today), true, 'Week 1 inside the 12 weeks stays');
eq(sbStillCheckingIn({stage:'month1', startDate:'2026-11-23'}, null, 12, today), true, 'Month 1 inside the 12 weeks stays');
eq(sbStillCheckingIn({stage:'month1', startDate:'2026-08-24'}, null, 12, today), false, 'start 24 Aug: 12 weeks ended 16 Nov, so it drops off');
eq(sbStillCheckingIn({stage:'month1', startDate:'2026-09-08'}, null, 12, '2026-12-01'), true, 'start 8 Sep: 12 weeks end 1 Dec, still showing on the last day');
eq(sbStillCheckingIn({stage:'month1', startDate:'2026-09-08'}, null, 12, '2026-12-02'), false, 'the day after the guarantee ends it drops off');
eq(sbStillCheckingIn({stage:'day1', startDate:'2026-11-30'}, {guaranteeWeeks: 4, status:'active'}, 12, '2026-12-30'), false, 'a placement with a 4 week guarantee drops off after 4 weeks');
eq(sbStillCheckingIn({stage:'day1', startDate:'2026-11-30'}, {guaranteeEnd:'2027-03-01', status:'active'}, 12, today), true, 'the server guarantee end date wins');
eq(sbStillCheckingIn({stage:'week1', startDate:'2026-11-23'}, {status:'left'}, 12, today), false, 'someone who left in the guarantee drops off');
eq(sbStillCheckingIn({stage:'week1', startDate:'2026-11-23'}, {status:'completed'}, 12, today), false, 'a completed placement drops off');
eq(sbStillCheckingIn({stage:'week1', startDate:''}, null, 12, today), true, 'no start date yet: keep showing so it is not forgotten');
eq(sbStillCheckingIn({stage:'rejected'}, null, 12, today), false, 'rejected candidates do not keep a role showing');
eq(sbStillCheckingIn({stage:'interviewed'}, null, 12, today), false, 'candidates still in interviews do not keep a filled role showing');
console.log(`test-sidebar-filled: ${n} checks passed`);
