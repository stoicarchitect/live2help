// Build 66.3 page test: the Mailbox sync panel and the suggested updates cards, run in a sandbox with stubbed calls.
//   node scripts/test-page-663.mjs [path to page]   (default: dashboard-next/index.html)
import fs from 'fs'; import vm from 'vm'; import assert from 'assert';
const s = fs.readFileSync(process.argv[2] || new URL('../dashboard-next/index.html', import.meta.url).pathname, 'utf8');
const a = s.indexOf('var P66 = {'); const b = s.indexOf("setInterval(function(){ if(document.visibilityState === 'visible' && typeof p66SugLoad");
const code = s.slice(a, b);
const els = {}; const el = id => els[id] || (els[id] = { id, innerHTML: '' });
const toasts = []; let posted = [];
const ctx = {
  document: { getElementById: el, visibilityState: 'visible' }, esc: x => String(x == null ? '' : x).replace(/&/g, '&amp;').replace(/</g, '&lt;'),
  showToast: m => toasts.push(m), confirm: () => true, p64Owner: () => true, loadComms: () => {}, console,
  b2Api: async u => api[u], b2Post: async (u, body) => { posted.push(u); if (post[u] instanceof Error) throw post[u]; return post[u]; },
  Date, Math, JSON,
};
let api = {}, post = {};
vm.createContext(ctx); vm.runInContext(code, ctx);
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const base = { stored: true, enabled: true, sinceDay: '2026-11-11', noReplyDays: 2, previewMonths: 12, loggedTotal: 267, loggedToday: 212, pending: 11, doNotLog: [], counts: {}, running: false };
// partial
el('p66Mail'); ctx.P66.st = { ...base, outcome: 'partial', last: '2026-11-18T10:50:00Z', error: 'dan.brown@x inbox: Microsoft 365 refused access (403)', needsPermission: true,
  mailboxes: [{ owner: 'dan', mailbox: 'd', logged: 55, lastOk: '2026-11-17T13:10:00Z', lastFail: '2026-11-18T10:50:00Z', ranOk: false }, { owner: 'ella', mailbox: 'e', logged: 212, lastOk: '2026-11-18T10:50:00Z', ranOk: true }] };
ctx.p66Render(); let h = el('p66Mail').innerHTML;
ok(/Partly working/.test(h) && /Daniel Brown is being refused/.test(h) && /Ella is being read/.test(h), 'partial banner names both');
ok(!/none yet/.test(h), 'no none yet text');
ok(/Daniel Brown: <span[^>]*>refused by Microsoft/.test(h) && /Ella: <span[^>]*>working/.test(h), 'status line for each mailbox');
ok(/What Microsoft said/.test(h), 'microsoft text kept in a details box');
ok(!/[—–]/.test(h), 'no em or en dashes');
// run result
post['/api/mailsync/run'] = { ok: true, outcome: 'partial', counts: { suggested: 2, logged: 49 }, boxes: [{ owner: 'dan', ok: false, logged: 0 }, { owner: 'ella', ok: true, logged: 49 }] };
api['/api/mailsync/status'] = ctx.P66.st; api['/api/mailsync/suggestions'] = { pending: [], recent: [] };
await ctx.p66Run(); await new Promise(r => setTimeout(r, 20));
ok(/Ella: 49 new emails logged/.test(ctx.P66.result.text) && /Daniel Brown: refused/.test(ctx.P66.result.text) && ctx.P66.result.cls === 'warn', 'run result message');
ok(/Finished, but one mailbox was refused/.test(el('p66Mail').innerHTML), 'run result is shown in the panel after reload');
// second press while a run is on
post['/api/mailsync/run'] = new Error('A sync is already running. Wait for it to finish, then press Run now again.');
await ctx.p66Run();
ok(/Did not run: A sync is already running/.test(ctx.P66.result.text) && ctx.P66.result.cls === 'bad', 'a refused second press is explained');
// health check + repair button
api['/api/mailsync/check'] = { mailboxLog: { rows: 267, duplicates: { ids: 3, extraRows: 3 } }, suggestions: { byStatus: { pending: 11, accepted: 2 }, duplicates: { extraRows: 2 }, withResultButPending: 0 }, perMailbox: { dan: { rows: 55, distinctIds: 55, byDirection: { in: 30, out: 25 } }, ella: { rows: 212, distinctIds: 209, byDirection: { in: 150, out: 62 } } } };
await ctx.p66Check(); h = el('p66Mail').innerHTML;
ok(/Remove 5 repeated rows/.test(h) && /Ella: 212 rows, 209 different/.test(h), 'health check shows duplicates and the repair button');
post['/api/mailsync/repair'] = { mailboxLog: { removed: 3 }, suggestions: { removed: 2 } };
await ctx.p66Repair(); ok(posted.includes('/api/mailsync/repair') && /Removed 3 repeated emails and 2 repeated suggestions/.test(toasts[toasts.length - 1]), 'repair runs');
// all ok
ctx.P66.st = { ...base, outcome: 'ok', last: 'x', mailboxes: [{ owner: 'dan', logged: 1, lastOk: 'x', ranOk: true }, { owner: 'ella', logged: 1, lastOk: 'x', ranOk: true }] }; ctx.P66.check = null; ctx.p66Render();
ok(/Working\./.test(el('p66Mail').innerHTML), 'working banner when all read');
// suggestion error stays on the card, preview note
el('p66Sug'); ctx.P66.sug = { preview: true, pending: [{ id: 'sg-1', label: 'Role filled', contact_name: 'Jane', company: 'Acme', role: 'Welder', subject: 's', created_at: '2026-11-18T09:00:00Z', evidence: 'we have filled the role' }] };
ctx.P66.err['sg-1'] = 'Acme has 2 open roles and the email does not say which.'; ctx.p66SugRender(); h = el('p66Sug').innerHTML;
ok(/Not applied: Acme has 2 open roles/.test(h) && /Preview: Accept and Dismiss/.test(h), 'failed accept is shown on the card, with the preview note');
post['/api/mailsync/suggestions/sg-1/accept'] = new Error('Acme has 2 open roles.'); api['/api/mailsync/suggestions'] = { pending: ctx.P66.sug.pending };
ctx.P66.err = {}; await ctx.p66Handle('sg-1', true); ok(/Acme has 2 open roles/.test(ctx.P66.err['sg-1']), 'error remembered after a failed accept');
console.log('page 66.3 panel: all ' + n + ' checks passed');
