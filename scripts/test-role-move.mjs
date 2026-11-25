// Build 73.3 tests: node scripts/test-role-move.mjs
import assert from 'assert';
import { keyOf, planMove, belongsTo, retarget, rekey, invoiceFollows, summaryText } from '../role-move.js';

let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; }; const eq = (a, b, m) => { assert.deepStrictEqual(a, b, m); n++; };

const thomas = { name: 'Thomas B', company: 'MSF', role: 'Bench Joiner' };

// ---------- planning ----------
let p = planMove(thomas, { role: 'Polisher' });
ok(!p.error, 'a move to a new role on the same company is allowed');
eq([p.from, p.to, p.companyChanges], [{ company: 'MSF', role: 'Bench Joiner' }, { company: 'MSF', role: 'Polisher' }, false], 'company defaults to the current one');
eq([p.oldKey, p.newKey], ['msf-thomas-b-bench-joiner', 'msf-thomas-b-polisher'], 'old and new placement keys');
eq(p.oldKey, keyOf('MSF', 'Thomas B', 'Bench Joiner'), 'key matches the server key format');

p = planMove(thomas, { company: 'Other Co', role: 'Polisher' });
eq([p.to.company, p.companyChanges], ['Other Co', true], 'a different company is allowed and flagged');

ok(planMove(thomas, { role: 'bench joiner' }).error, 'same role in different case is refused');
ok(planMove(thomas, { role: '' }).error, 'a blank role is refused');
ok(planMove({ name: '', company: 'MSF', role: 'X' }, { role: 'Y' }).error, 'a candidate without a name is refused');
ok(planMove(thomas, { role: 'Polisher' }, [{ name: 'thomas b', role: 'Polisher', company: 'msf' }]).error, 'refused when they are already on the target role');
ok(!planMove(thomas, { role: 'Polisher' }, [{ name: 'Sam Jones', role: 'Polisher', company: 'MSF' }]).error, 'another person on the target role is fine');

// ---------- records that carry role and company as fields ----------
p = planMove(thomas, { role: 'Polisher' });
const interview = { id: 'i1', candidate_name: 'Thomas B', role: 'Bench Joiner', company: 'MSF', date: '2026-11-10' };
ok(belongsTo(interview, p), 'an interview for the old role belongs to the move');
ok(!belongsTo({ ...interview, role: 'Welder' }, p), 'an interview for another role is left alone');
ok(!belongsTo({ ...interview, candidate_name: 'Sam Jones' }, p), 'another candidate is left alone');
eq(retarget(interview, p), { id: 'i1', candidate_name: 'Thomas B', role: 'Polisher', company: 'MSF', date: '2026-11-10' }, 'only role and company change');

// ---------- records keyed by the placement key ----------
const offer = { id: p.oldKey, candidate_name: 'Thomas B', role: 'Bench Joiner', company: 'MSF', details_json: '{"offer_sent_at":"x"}' };
eq(rekey(offer, p), { id: 'msf-thomas-b-polisher', candidate_name: 'Thomas B', role: 'Polisher', company: 'MSF', details_json: '{"offer_sent_at":"x"}' }, 'offer record moves to the new key with its content kept');
eq(rekey({ id: p.oldKey, guarantee_weeks: '12', status: 'active' }, p), { id: 'msf-thomas-b-polisher', guarantee_weeks: '12', status: 'active' }, 'a placement has no role field, so only the id changes');

// ---------- invoices ----------
const inv = { number: 'L2H-2026-004', candidateName: 'Thomas B', company: 'MSF', role: 'Bench Joiner', status: 'pending' };
ok(invoiceFollows(inv, p), 'an unpaid invoice follows the candidate');
ok(invoiceFollows({ ...inv, status: 'sent' }, p), 'a sent invoice follows the candidate');
ok(!invoiceFollows({ ...inv, status: 'paid' }, p), 'a paid invoice is never changed');
ok(!invoiceFollows({ ...inv, status: 'refunded' }, p), 'a refunded invoice is never changed');
ok(!invoiceFollows({ ...inv, role: 'Welder' }, p), 'an invoice for another role is left alone');

// ---------- wording ----------
eq(summaryText(p, { interviews: 2, 'offer records': 1, invoices: 0 }), 'Moved from Bench Joiner (MSF) to Polisher (MSF). Updated: 2 interviews, 1 offer records.', 'summary lists only what changed');

console.log(`test-role-move: ${n} checks passed`);
