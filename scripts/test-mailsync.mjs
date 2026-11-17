// Build 66 tests: mailbox sync logic and engine against a fake Microsoft Graph and in-memory tables.
//   node scripts/test-mailsync.mjs
// Nothing here touches a real mailbox, database or email service.
import assert from 'node:assert/strict';
import {
  normaliseMessage, skipReason, makeDirectory, matchMessage, detectSuggestions, workingDaysBetween, unansweredClientMail,
  createMailSync, previewOf, isWorkingDay,
} from '../mailsync.js';

let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const eq = (a, b, m) => { assert.deepEqual(a, b, m); n++; };

/* ---------- pure pieces ---------- */
ok(previewOf('a  b\n\n c '.repeat(100)).length <= 200, 'preview is cut to 200 characters');
eq(previewOf('  hello \n world '), 'hello world', 'preview collapses whitespace');

const g = (from, to, subject, preview, extra = {}) => ({
  id: 'AAA' + Math.random().toString(36).slice(2), internetMessageId: '<' + Math.random().toString(36).slice(2) + '@x>', conversationId: 'c1',
  subject, bodyPreview: preview, receivedDateTime: '2026-11-16T09:00:00Z', sentDateTime: '2026-11-16T09:00:00Z',
  from: { emailAddress: { address: from } }, toRecipients: (to || []).map(a => ({ emailAddress: { address: a } })), ccRecipients: [], isDraft: false, ...extra,
});
const DAN = 'dan.brown@live2helprecruitment.co.uk';
let nm = normaliseMessage(g('Jane@Acme.co.uk', [DAN], 'Hello', 'hi'), DAN, 'inbox');
eq([nm.direction, nm.counterparts], ['in', ['jane@acme.co.uk']], 'inbound message: counterpart is the sender, lower cased');
nm = normaliseMessage(g(DAN, ['jane@acme.co.uk', 'bob@acme.co.uk'], 'Re', 'x'), DAN, 'sentitems');
eq([nm.direction, nm.counterparts], ['out', ['jane@acme.co.uk', 'bob@acme.co.uk']], 'sent message: counterparts are the recipients');
ok(skipReason(normaliseMessage(g('x@y.com', [DAN], 'Hi', 'p', { isDraft: true }), DAN, 'inbox')) === 'draft', 'drafts skipped');
ok(skipReason(normaliseMessage(g('postmaster@acme.co.uk', [DAN], 'Undeliverable: Welder', 'p'), DAN, 'inbox')) === 'bounce', 'bounce notices are left to the cold outreach scan');
ok(skipReason(normaliseMessage(g('jane@acme.co.uk', [DAN], 'Automatic reply: Welder', 'I am out of the office'), DAN, 'inbox')) === 'automatic', 'out of office skipped');
ok(skipReason(normaliseMessage(g('no-reply@acme.co.uk', [DAN], 'Invoice', 'p'), DAN, 'inbox')) === 'automatic', 'no-reply senders skipped');
ok(skipReason(normaliseMessage(g('jane@acme.co.uk', [DAN], 'Welder', 'p'), DAN, 'inbox')) === null, 'a normal message is considered');

const dir = makeDirectory([
  { email: 'jane@acme.co.uk', name: 'Jane', company: 'Acme', type: 'prospect' },
  { email: 'Jane@acme.co.uk', name: 'Jane Smith', company: 'Acme', type: 'client' },
  { email: 'sam@cand.com', name: 'Sam', company: 'Acme', role: 'Welder', type: 'candidate' },
]);
eq(dir.get('jane@acme.co.uk').type, 'client', 'client record wins when an address is on two records');
const mc = { directory: dir, doNotLog: new Set(['sam@cand.com']), suppressed: new Set(), internalDomains: new Set(['live2helprecruitment.co.uk']) };
eq(matchMessage(normaliseMessage(g('jane@acme.co.uk', [DAN], 'a', 'b'), DAN, 'inbox'), mc).map(c => c.email), ['jane@acme.co.uk'], 'known address matches');
eq(matchMessage(normaliseMessage(g('stranger@random.com', [DAN], 'a', 'b'), DAN, 'inbox'), mc), [], 'unknown address does not match');
eq(matchMessage(normaliseMessage(g('sam@cand.com', [DAN], 'a', 'b'), DAN, 'inbox'), mc), [], 'do not log address does not match');
eq(matchMessage(normaliseMessage(g('ella@live2helprecruitment.co.uk', [DAN], 'a', 'b'), DAN, 'inbox'), mc), [], 'our own domain is never a contact');
eq(matchMessage(normaliseMessage(g('jane@acme.co.uk', [DAN], 'a', 'b'), DAN, 'inbox'), { ...mc, suppressed: new Set(['jane@acme.co.uk']) }), [], 'suppression list address does not match');

// suggestions
const cand = { type: 'candidate' }, cli = { type: 'client' };
const sug = (type, subject, preview) => detectSuggestions(normaliseMessage(g('a@b.com', [DAN], subject, preview), DAN, 'inbox'), { type }).map(s => s.kind);
eq(sug('candidate', 'Offer', 'I am delighted to accept the offer and look forward to starting.'), ['offer_accepted'], 'offer accepted');
eq(sug('candidate', 'Role', 'Sorry but I have accepted another offer so I am withdrawing.'), ['candidate_withdrawn'], 'candidate withdrawn (not misread as offer accepted)');
ok(sug('candidate', 'Interview', 'Happy to confirm the interview on Thursday at 2pm').includes('interview_confirmed'), 'interview confirmed by a candidate');
ok(sug('client', 'Re: Interview', 'Tuesday at 10am is confirmed for the interview').includes('interview_confirmed'), 'interview confirmed by a client');
eq(sug('client', 'Fitter', 'We have filled the position, thank you for your help.'), ['role_filled'], 'role filled');
eq(sug('client', 'Fitter', 'We are putting the role on hold until January.'), ['role_on_hold'], 'role on hold');
eq(sug('client', 'Candidate', 'Thanks for sending Sam. Feedback: not quite the right fit for us.'), ['client_feedback'], 'client feedback');
eq(sug('client', 'Hello', 'Can you call me tomorrow about pricing?'), [], 'nothing suggested for ordinary mail');
eq(sug('candidate', 'Hello', 'We have filled the position'), [], 'client only rules ignore candidate mail');
eq(detectSuggestions(normaliseMessage(g(DAN, ['a@b.com'], 'Offer', 'I accept the offer'), DAN, 'sentitems'), cand), [], 'our own sent mail never creates a suggestion');

// working days (Tue 17 Nov 2026 is a working day; Sat 21 and Sun 22 are not)
ok(isWorkingDay('2026-11-19') && !isWorkingDay('2026-11-21'), 'weekend is not a working day');
eq(workingDaysBetween('2026-11-16', '2026-11-19', new Set()), 3, 'Mon to Thu is 3 working days');
eq(workingDaysBetween('2026-11-20', '2026-11-23', new Set()), 1, 'Fri to Mon is 1 working day');
eq(workingDaysBetween('2026-11-16', '2026-11-19', new Set(['2026-11-17'])), 2, 'a bank holiday is skipped');

/* ---------- the engine against a fake Graph ---------- */
const mem = () => {
  const rows = [];
  return {
    rows,
    list: async () => rows.map(r => ({ ...r })),
    append: async r => { rows.push({ ...r }); },
    upsert: async r => { const i = rows.findIndex(x => x.id === r.id); if (i >= 0) rows[i] = { ...r }; else rows.push({ ...r }); },
    remove: async id => { const i = rows.findIndex(x => x.id === id); if (i >= 0) rows.splice(i, 1); },
    updateWhere: async (p, f) => { let c = 0; rows.forEach((r, i) => { if (p(r)) { rows[i] = f({ ...r }); c++; } }); return c; },
  };
};
const ELLA = 'ella@live2helprecruitment.co.uk';
function world(opts = {}) {
  const t = { mailLog: mem(), suggestions: mem(), doNotLog: mem(), comms: mem() };
  const settings = new Map(Object.entries({ mail_sync_enabled: 'yes', mail_sync_since: '2026-11-10', ...(opts.settings || {}) }));
  const tasks = [], alerts = [], calls = [];
  // folders: per mailbox and folder, queued batches. A batch is the answer to one delta call.
  const folders = {}; // key mailbox|folder -> { queue: [[messages...] or Error] }
  const q = (mb, f) => (folders[mb + '|' + f] = folders[mb + '|' + f] || { queue: [], n: 0 });
  const graph = async (method, url) => {
    calls.push(url);
    const m = /\/users\/([^/]+)\/mailFolders\/([^/]+)\/messages\/delta/.exec(decodeURIComponent(url)) || /\/delta\/([^/]+)\/([^/]+)\//.exec(url);
    const f = q(decodeURIComponent(m[1]), m[2]);
    const next = f.queue.shift();
    if (next instanceof Error) throw next;
    f.n++;
    const batch = next || [];
    if (batch.nextPage) return { value: batch, '@odata.nextLink': `https://g/delta/${m[1]}/${m[2]}/page${f.n}` };
    return { value: batch, '@odata.deltaLink': `https://g/delta/${m[1]}/${m[2]}/tok${f.n}` };
  };
  const eng = createMailSync({
    graph, ...t,
    settingsGet: async k => settings.get(k), settingsSet: async (k, v) => { settings.set(k, v); },
    loadDirectory: async () => opts.directory || [
      { email: 'jane@acme.co.uk', name: 'Jane Smith', company: 'Acme Engineering', type: 'client' },
      { email: 'sam@cand.com', name: 'Sam Jones', company: 'Acme Engineering', role: 'Welder', type: 'candidate' },
      { email: 'lee@lead.com', name: 'Lee', company: 'Lead Ltd', type: 'lead' },
    ],
    loadSuppressed: async () => new Set(opts.suppressed || []),
    internalDomains: () => new Set(['live2helprecruitment.co.uk']),
    mailboxes: () => [{ owner: 'dan', mailbox: DAN }, { owner: 'ella', mailbox: ELLA }],
    holidays: async () => new Set(opts.holidays || []),
    today: () => opts.today || '2026-11-19', now: () => '2026-11-19T10:00:00Z',
    addTasks: async list => { list.forEach(x => { if (!tasks.some(y => y.key === x.key)) tasks.push(x); }); return list.length; },
    alert: async (k, s, tx) => { alerts.push({ k, s, tx }); },
    ready: () => opts.ready !== false,
  });
  return { ...t, eng, settings, tasks, alerts, calls, q };
}
const strip = x => JSON.stringify(x);

// 1. a known client's email appears once, however many times we sync
{
  const w = world();
  const inbound = g('jane@acme.co.uk', [DAN], 'Welder vacancy', 'Hi Dan, can you send me two more CVs this week please? Thanks, Jane');
  w.q(DAN, 'inbox').queue.push([inbound]);
  const r1 = await w.eng.run();
  eq([r1.counts.logged, w.mailLog.rows.length, w.comms.rows.length], [1, 1, 1], 'known client email logged once, on the log and on the timeline');
  const row = w.mailLog.rows[0];
  eq(Object.keys(row).sort(), ['at', 'company', 'contact_email', 'contact_name', 'contact_type', 'conversation_id', 'direction', 'id', 'logged_at', 'mailbox', 'owner', 'preview', 'role', 'subject'].sort(), 'only the agreed fields are stored (no body, no attachments)');
  eq([row.direction, row.contact_email, row.owner], ['in', 'jane@acme.co.uk', 'dan'], 'log row is for the right contact and mailbox');
  eq([w.comms.rows[0].entity_type, w.comms.rows[0].company, w.comms.rows[0].direction, w.comms.rows[0].channel], ['client', 'Acme Engineering', 'inbound', 'email'], 'timeline entry is attached to the account');
  ok(!/two more CVs/.test(strip(w.comms.rows)), 'the preview text is not copied to the shared timeline, only the subject');
  // the same message again (a second run uses the stored delta link) adds nothing
  w.q(DAN, 'inbox').queue.push([inbound]);
  const r2 = await w.eng.run();
  eq([r2.counts.logged, r2.counts.duplicates, w.mailLog.rows.length], [0, 1, 1], 'the same email twice is still one row');
  ok(w.calls.some(u => /\/delta\/.*\/inbox\/tok1/.test(u)), 'the second run resumes from the delta link');
}

// 2. mail from an unknown address is not stored anywhere
{
  const w = world();
  w.q(DAN, 'inbox').queue.push([g('stranger@random.com', [DAN], 'Private holiday photos', 'secret preview text'), g('friend@gmail.com', [DAN], 'Pub on Friday', 'see you there')]);
  w.q(DAN, 'sentitems').queue.push([g(DAN, ['mum@family.org'], 'Sunday lunch', 'lunch at one')]);
  const r = await w.eng.run();
  eq([r.counts.logged, r.counts.ignored], [0, 3], 'unknown addresses are counted, not stored');
  ok(!/Private holiday|Pub on Friday|Sunday lunch|secret preview|mum@family|stranger@/.test(strip([w.mailLog.rows, w.comms.rows, w.suggestions.rows, [...w.settings.values()]])), 'nothing about unknown mail is kept anywhere');
}

// 3. a suggested update appears and nothing changes until a click (the engine only ever writes the suggestion)
{
  const w = world();
  w.q(ELLA, 'inbox').queue.push([g('sam@cand.com', [ELLA], 'Re: Welder offer', 'Hi Ella, I am delighted to accept the offer. When do I start?')]);
  const r = await w.eng.run();
  eq(r.counts.suggested, 1, 'a suggestion is created');
  const s = w.suggestions.rows[0];
  eq([s.kind, s.status, s.contact_name, s.owner, s.role], ['offer_accepted', 'pending', 'Sam Jones', 'ella', 'Welder'], 'the suggestion waits as pending for the right person');
  eq(w.comms.rows.length, 1, 'only the timeline line was written, no record was changed');
  const again = world(); again.q(ELLA, 'inbox').queue.push([g('sam@cand.com', [ELLA], 'x', 'accepted the offer')]);
  await again.eng.run();
  eq(again.suggestions.rows.length, 1, 'one suggestion per message');
}

// 4. no reply task after 2 working days
{
  // Thu 19 Nov: a client mail from Mon 16 Nov is 3 working days old
  const w = world();
  w.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Welder vacancy', 'Can you send CVs please', { receivedDateTime: '2026-11-16T09:00:00Z' })]);
  const r = await w.eng.run();
  eq([r.counts.tasks, w.tasks.length], [1, 1], 'a task appears for client mail with no reply after 2 working days');
  eq([w.tasks[0].user, w.tasks[0].dueDate], ['dan', '2026-11-19'], 'task is for the mailbox owner and due today');
  w.q(DAN, 'inbox').queue.push([]);
  await w.eng.run();
  eq(w.tasks.length, 1, 'running again does not duplicate the task');

  // answered: a sent reply after the client mail means no task
  const w2 = world();
  w2.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Welder vacancy', 'Can you send CVs please', { receivedDateTime: '2026-11-16T09:00:00Z' })]);
  w2.q(DAN, 'sentitems').queue.push([g(DAN, ['jane@acme.co.uk'], 'Re: Welder vacancy', 'Sent', { sentDateTime: '2026-11-17T08:00:00Z', receivedDateTime: '2026-11-17T08:00:00Z' })]);
  const r2 = await w2.eng.run();
  eq([r2.counts.logged, r2.counts.tasks], [2, 0], 'a reply from us cancels the follow up');

  // too recent: Wed 18 Nov is 1 working day
  const w3 = world();
  w3.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Welder vacancy', 'Can you send CVs please', { receivedDateTime: '2026-11-18T09:00:00Z' })]);
  eq((await w3.eng.run()).counts.tasks, 0, 'no task before 2 working days');

  // a thank you needs no answer, and candidates never get this task
  const w4 = world();
  w4.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Re: CVs', 'Thanks!', { receivedDateTime: '2026-11-16T09:00:00Z' }), g('sam@cand.com', [DAN], 'Hello', 'Are you there?', { receivedDateTime: '2026-11-16T09:00:00Z' })]);
  eq((await w4.eng.run()).counts.tasks, 0, 'thank you mail and candidate mail do not create follow up tasks');

  // the setting
  const w5 = world({ settings: { mail_noreply_days: '4' } });
  w5.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Welder vacancy', 'Can you send CVs please', { receivedDateTime: '2026-11-16T09:00:00Z' })]);
  eq((await w5.eng.run()).counts.tasks, 0, 'the number of days is a setting');
}

// 5. removing a contact stops logging (do not log) and clears what was stored
{
  const w = world();
  w.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Welder vacancy', 'hello'), g('sam@cand.com', [DAN], 'Hello', 'accepted another offer')]);
  await w.eng.run();
  eq([w.mailLog.rows.length, w.comms.rows.length, w.suggestions.rows.length], [2, 2, 1], 'two contacts logged');
  const out = await w.eng.addDoNotLog('Sam@Cand.com', 'dan');
  eq([out.removed, w.mailLog.rows.length, w.comms.rows.length], [1, 1, 1], 'do not log clears the stored mail and timeline line');
  eq(w.suggestions.rows[0].status, 'dismissed', 'pending suggestions for that address are dismissed');
  w.q(DAN, 'inbox').queue.push([g('sam@cand.com', [DAN], 'Another', 'later email')]);
  await w.eng.run();
  eq(w.mailLog.rows.length, 1, 'later mail from that address is not logged');
  await w.eng.removeDoNotLog('sam@cand.com');
  w.q(DAN, 'inbox').queue.push([g('sam@cand.com', [DAN], 'Back again', 'hello')]);
  await w.eng.run();
  eq(w.mailLog.rows.length, 2, 'logging resumes when the address is taken off the list');
}

// 6. the rules around the edges
{
  // off by default, and manual runs honour the switch unless forced
  const off = world({ settings: { mail_sync_enabled: 'no' } });
  off.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Hi', 'x')]);
  eq((await off.eng.run()).skipped, 'off', 'nothing is read while the switch is off');
  eq(off.mailLog.rows.length, 0, 'nothing logged while off');
  eq((world({ ready: false }).eng.run()) instanceof Promise, true, 'run is async');
  eq((await world({ ready: false }).eng.run()).skipped, 'no database', 'no database means no sync (previews never go to Google Sheets)');

  // contacts could not be read: nothing is read, so no message is skipped for good
  const nodir = world({ directory: [] });
  nodir.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Hi', 'x')]);
  const rn = await nodir.eng.run();
  ok(/No client, lead, prospect or candidate email addresses/.test(rn.errors[0]) && nodir.alerts.length === 1, 'an empty contact list stops the run and alerts Daniel Brown');
  eq(nodir.calls.length, 0, 'and Graph is not called, so the delta position does not move');

  // a record source that cannot be read stops the run the same way
  const w9 = world(); const throwing = createMailSync({ ...{ graph: async () => { throw new Error('should not be called'); } }, mailLog: mem(), suggestions: mem(), doNotLog: mem(), comms: mem(),
    settingsGet: async k => (k === 'mail_sync_enabled' ? 'yes' : ''), settingsSet: async () => {}, loadDirectory: async () => { throw new Error('Google Sheets is down'); }, loadSuppressed: async () => new Set(),
    internalDomains: () => new Set(), mailboxes: () => [{ owner: 'dan', mailbox: DAN }], holidays: async () => new Set(), today: () => '2026-11-19', now: () => 'x', addTasks: async () => 0, alert: async (k, s, tx) => { w9.alerts.push({ k, s, tx }); }, ready: () => true });
  const rt = await throwing.run();
  ok(/Google Sheets is down/.test(rt.errors[0]) && w9.alerts.length === 1, 'a failing record source stops the run with a clear message and an alert');

  // suppressed, internal and automatic mail
  const w = world({ suppressed: ['lee@lead.com'] });
  w.q(DAN, 'inbox').queue.push([g('lee@lead.com', [DAN], 'Hi', 'x'), g(ELLA, [DAN], 'Internal', 'x'), g('jane@acme.co.uk', [DAN], 'Automatic reply: Hi', 'I am out of the office'), g('postmaster@acme.co.uk', [DAN], 'Undeliverable: Hi', 'x')]);
  eq((await w.eng.run()).counts.logged, 0, 'suppressed, internal, automatic and bounce mail is never logged');

  // the same email sent to two of our mailboxes is one line per mailbox
  const two = world();
  const mail = g('jane@acme.co.uk', [DAN, ELLA], 'Hello both', 'hi');
  two.q(DAN, 'inbox').queue.push([mail]); two.q(ELLA, 'inbox').queue.push([mail]);
  eq((await two.eng.run()).counts.logged, 2, 'each mailbox keeps its own line');

  // cc'd contacts on a sent email
  const cc = world();
  cc.q(DAN, 'sentitems').queue.push([g(DAN, ['jane@acme.co.uk', 'stranger@x.com', 'sam@cand.com'], 'CVs attached', 'p')]);
  eq((await cc.eng.run()).counts.logged, 2, 'a sent email logs one line for each known contact and ignores the rest');

  // a first big catch up carries on in the next run
  const big = world();
  for (let i = 0; i < 12; i++) { const b = [g('jane@acme.co.uk', [DAN], 'Msg ' + i, 'p')]; b.nextPage = true; big.q(DAN, 'inbox').queue.push(b); }
  big.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Last one', 'p')]);
  const rb = await big.eng.run();
  eq(rb.counts.more, true, 'a long catch up is flagged and resumes next run');
  const rb2 = await big.eng.run();
  ok(big.mailLog.rows.some(r => r.subject === 'Last one') && rb2.counts.more === false, 'the next run finishes the catch up from where it stopped');

  // Microsoft refuses access (permission or access policy)
  const deny = world();
  const e403 = Object.assign(new Error('Access is denied'), { status: 403, code: 'ErrorAccessDenied' });
  deny.q(DAN, 'inbox').queue.push(e403); deny.q(DAN, 'sentitems').queue.push(e403);
  const rd = await deny.eng.run();
  ok(rd.needsPermission && /refused access/.test(rd.errors[0]), 'a 403 is reported clearly');
  eq(deny.alerts.length, 1, 'Daniel Brown is alerted by email');
  ok(!/—|–/.test(strip(rd.errors) + strip(deny.alerts)), 'no em or en dashes in our own messages');

  // an expired delta token starts again
  const exp = world();
  exp.settings.set(`mail_delta:${DAN}:inbox`, 'https://g/delta/' + DAN + '/inbox/old');
  exp.q(DAN, 'inbox').queue.push(Object.assign(new Error('gone'), { status: 410, code: 'syncStateNotFound' }));
  const re = await exp.eng.run();
  eq([re.counts.resets, exp.settings.get(`mail_delta:${DAN}:inbox`) || ''], [1, ''], 'an expired delta token is cleared and restarts next run');

  // one mailbox failing does not stop the other
  const part = world();
  part.q(DAN, 'inbox').queue.push(new Error('boom'));
  part.q(ELLA, 'inbox').queue.push([g('jane@acme.co.uk', [ELLA], 'Hello Ella', 'x')]);
  const rp = await part.eng.run();
  eq([part.mailLog.rows.length, rp.errors.length], [1, 1], 'a failing mailbox does not stop the other');

  // previews expire, the line stays
  const old = world();
  old.q(DAN, 'inbox').queue.push([g('jane@acme.co.uk', [DAN], 'Old news', 'some preview', { receivedDateTime: '2025-01-05T09:00:00Z' })]);
  await old.eng.run({ sinceDay: '2025-01-01' });
  eq(await old.eng.purgeOldPreviews(), 1, 'old previews are cleared');
  eq([old.mailLog.rows[0].preview, old.mailLog.rows[0].subject], ['', 'Old news'], 'the subject line stays when the preview goes');
}

console.log(`mailsync: all ${n} checks passed`);
