// Build 67.3 page test: Needs attention (contact-aware list, Complete/Dismiss/Snooze, Clear all). node scripts/test-page-673.mjs [page]
import fs from 'fs'; import vm from 'vm'; import assert from 'assert';
const s = fs.readFileSync(process.argv[2] || new URL('../dashboard-next/index.html', import.meta.url).pathname, 'utf8');
const grab = (from, to) => { const a = s.indexOf(from), b = s.indexOf(to, a); assert.ok(a > 0 && b > a, 'missing ' + from); return s.slice(a, b); };
const code = grab('function buildNotifications(){', 'function updateNotifBadge') + grab('/* ---------- build 67.3: Done, Snooze', 'function opsOpenCandidate') + grab('function renderNotifications(){', '/* ---------- Home');
const els = {}; const el = id => els[id] || (els[id] = { id, innerHTML: '', textContent: '' });
const toasts = [], posted = [];
const today = '2026-11-19';
const ctx = { console, Date, Math, JSON, esc: x => String(x == null ? '' : x).replace(/&/g, '&amp;').replace(/</g, '&lt;'),
  signedInUser: { admin: true }, opsToday: () => today, opsDateOnly: v => String(v || '').slice(0, 10), opsDaysBetween: (a, b) => Math.round((new Date(b + 'T00:00:00Z') - new Date(a + 'T00:00:00Z')) / 86400000),
  opsTrunc: x => x, opsFmt: x => x, opsMoney: x => '£' + x, daysSince: d => Math.round((new Date(today + 'T12:00:00Z') - new Date(d)) / 86400000), poolStageLabel: x => x,
  UNASSIGNED_LABEL: 'Unassigned', STALE_DAYS: { interview_requested: 3 }, mergedRoles: () => [], poolLoaded: false, POOL: [], poolNeedsCv: () => false,
  DATA: { Acme: { Fitter: [{ id: 'c1', name: 'Jo Smith', stage: 'submitted', date: '2026-11-16' }] } },
  updateNotifBadge: () => {}, renderHome: () => {}, renderRoles: () => {}, renderPlacements: () => {}, renderSidebar: () => {}, opsIsVisible: () => true, currentUserRole: 'dan',
  document: { getElementById: el }, showToast: m => toasts.push(m), confirm: () => true, fetch: async (u) => ({ ok: true }), API_BASE: '',
  b2Post: async (u, body) => { posted.push([u, body]); return { hidden: Object.fromEntries(body.items.map(i => [i.id, { sig: i.sig, until: body.days ? '2026-11-26' : '' }])) }; },
  OPS: { tasks: [{ id: 't1', title: 'Call Jo', status: 'Open', dueDate: '2026-11-17', context: '' }], invoices: [], placements: [], roles: [], notes: [], comms: [], hidden: {}, hiddenCount: 0 } };
vm.createContext(ctx); vm.runInContext(code + '\nthis.recomputeOps = function(){ OPS.notes = buildNotifications(); };', ctx);
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const titles = () => ctx.OPS.notes.map(x => x.title);
ctx.recomputeOps();
ok(titles().some(t => /Overdue task: Call Jo/.test(t)) && titles().some(t => /Chase client for feedback: Jo Smith/.test(t)), 'overdue task and chase show');
ok(ctx.OPS.notes.every(x => x.id && x.sig), 'every item has an id and a situation signature');
// contact since the submission day removes the chase
ctx.OPS.comms = [{ timestamp: '2026-11-16T09:00:00Z', company: 'Acme', entity_type: 'client', channel: 'email', direction: 'outbound' }];
ctx.recomputeOps(); ok(titles().some(t => /Chase client/.test(t)), 'the submission email on the same day does not clear the chase');
ctx.OPS.comms = [{ timestamp: '2026-11-18T09:00:00Z', company: 'Acme', entity_type: 'client', channel: 'email', direction: 'outbound' }];
ctx.recomputeOps(); ok(!titles().some(t => /Chase client/.test(t)), 'an email to the client on a later day clears the chase');
ctx.OPS.comms = [{ timestamp: '2026-11-18T09:00:00Z', company: 'Acme', entity_name: 'Jo Smith', entity_type: 'candidate', channel: 'email', direction: 'outbound' }];
ctx.recomputeOps(); ok(titles().some(t => /Chase client/.test(t)), 'contact with the candidate does not clear a client chase');
// snooze and dismiss
ctx.OPS.comms = [];
ctx.recomputeOps();
const i = ctx.OPS.notes.findIndex(x => x.id === 'chase:c1');
await ctx.opsSnooze(i, 3); await new Promise(r => setTimeout(r, 5));
ok(posted[0][0] === '/api/attention/hide' && posted[0][1].days === 3 && posted[0][1].items[0].id === 'chase:c1', 'snooze posts the id for 3 days');
ok(!titles().some(t => /Chase client/.test(t)) && ctx.OPS.hiddenCount === 1, 'snoozed item is hidden and counted');
ctx.OPS.hidden['chase:c1'].until = '2026-11-18'; ctx.recomputeOps(); ok(titles().some(t => /Chase client/.test(t)), 'an expired snooze brings it back');
ctx.OPS.hidden['chase:c1'] = { sig: 'med', until: '' }; ctx.recomputeOps(); ok(titles().some(t => /Chase client/.test(t)), 'a changed situation (med to high) brings a dismissed item back');
ctx.OPS.hidden['chase:c1'] = { sig: 'high', until: '' }; ctx.recomputeOps(); ok(!titles().some(t => /Chase client/.test(t)), 'a dismissed item stays hidden while unchanged');
// complete a task and clear a group
const ti = ctx.OPS.notes.findIndex(x => x.id === 'task:t1');
await ctx.opsDone(ti); ok(!ctx.OPS.tasks.length && toasts.includes('Task completed'), 'Complete finishes the task');
ctx.OPS.hidden = {}; ctx.OPS.tasks = [{ id: 't2', title: 'A', status: 'Open', dueDate: '2026-11-10' }, { id: 't3', title: 'B', status: 'Open', dueDate: '2026-11-11' }]; ctx.recomputeOps();
posted.length = 0; ctx.opsClearGroup('high'); await new Promise(r => setTimeout(r, 5));
ok(posted[0][1].items.length >= 3 && posted[0][1].days === 7, 'Clear all hides every urgent item for 7 days');
ok(!ctx.OPS.notes.some(x => x.sev === 'high') && ctx.OPS.tasks.length === 2, 'urgent items are hidden but the tasks are not completed');
ctx.renderNotifications(); ok(/Show them again/.test(els.notifBody.innerHTML), 'a way to show hidden items again');
ok(!/[—–]/.test(els.notifBody.innerHTML), 'no em or en dashes');
console.log(`page 67.3 needs attention: all ${n} checks passed`);
