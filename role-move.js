/* Live 2 Help - build 73.3: move a candidate to another role, keeping their stage and every record.

   Pure functions only (no database, no network). The server applies the plan these build.
   A candidate belongs to a company and a role, and several records are keyed by company + name + role (the "placement key").
   Moving a candidate means: change company and role on the candidate, re-key those records, and update the role and company
   text on the records that only carry them as fields. The stage is never touched.
   Tests: node scripts/test-role-move.mjs */

const lc = v => String(v == null ? '' : v).trim().toLowerCase();

// The same key the server uses for Placements, Offer Details, Compliance and the offer portal
export function keyOf(company, name, role) {
  return `${company}|${name}|${role}`.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

// Checks a requested move and returns what it will change, or an error message in plain words.
// from: the candidate as it is now { company, role, name }. to: { company, role }. existing: other candidates already on the target role.
export function planMove(from, to, existing = []) {
  const name = String((from && from.name) || '').trim();
  const fromCompany = String((from && from.company) || '').trim();
  const fromRole = String((from && from.role) || '').trim();
  const toRole = String((to && to.role) || '').trim();
  const toCompany = String((to && to.company) || fromCompany).trim();
  if (!name || !fromRole) return { error: 'The candidate needs a name and a current role.' };
  if (!toRole) return { error: 'Choose the role to move them to.' };
  if (!toCompany) return { error: 'Choose the company for the new role.' };
  if (lc(toRole) === lc(fromRole) && lc(toCompany) === lc(fromCompany)) return { error: 'They are already on that role.' };
  const clash = (existing || []).find(c => lc(c.name) === lc(name) && lc(c.role) === lc(toRole) && lc(c.company) === lc(toCompany));
  if (clash) return { error: `${name} is already on ${toRole} at ${toCompany}. Merge or remove that card first.` };
  return {
    name, from: { company: fromCompany, role: fromRole }, to: { company: toCompany, role: toRole },
    oldKey: keyOf(fromCompany, name, fromRole), newKey: keyOf(toCompany, name, toRole),
    companyChanges: lc(toCompany) !== lc(fromCompany),
  };
}

// Does a record (a row with candidate_name, role and company fields) belong to this candidate on the old role?
export function belongsTo(row, plan, nameField = 'candidate_name') {
  return !!row && lc(row[nameField]) === lc(plan.name) && lc(row.role) === lc(plan.from.role) && lc(row.company) === lc(plan.from.company);
}

// The record with its role and company switched to the new ones. Everything else on the record is kept.
export function retarget(row, plan) {
  return { ...row, role: plan.to.role, company: plan.to.company };
}

// A record that is keyed by the placement key: the same record under the new id.
export function rekey(row, plan) {
  return { ...row, id: plan.newKey, ...(('role' in row) ? { role: plan.to.role } : {}), ...(('company' in row) ? { company: plan.to.company } : {}) };
}

// An invoice can follow the candidate only while it is unpaid
export function invoiceFollows(inv, plan) {
  const st = lc(inv && inv.status);
  return !!inv && st !== 'paid' && st !== 'refunded'
    && lc(inv.candidateName) === lc(plan.name) && lc(inv.company) === lc(plan.from.company) && lc(inv.role) === lc(plan.from.role);
}

export function summaryText(plan, counts) {
  const parts = Object.entries(counts || {}).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`);
  return `Moved from ${plan.from.role} (${plan.from.company}) to ${plan.to.role} (${plan.to.company})` + (parts.length ? `. Updated: ${parts.join(', ')}.` : '.');
}
