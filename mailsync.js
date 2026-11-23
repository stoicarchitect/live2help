/* Build 66: mailbox sync. Reads the work mailboxes of Daniel Brown and Ella through Microsoft Graph and keeps the
   workspace up to date from email to or from people who are already on a client, lead, prospect or candidate record.

   Rules that never bend:
   - Only mail to or from an address already on a record is stored. Everything else is counted and thrown away, never stored.
   - Never stores a message body or an attachment. Only: subject, direction, time, and a short preview of the first 200 characters.
   - An address on the Do not log list or the Suppression List is never logged.
   - Our own domain (staff, shared inboxes) is never a contact.
   - Suggested record changes are only ever suggestions. Nothing changes until a person presses Accept.
   - Detection is plain rules. No AI is used, so there is no AI spend.

   This file holds the pure logic and the sync engine. The engine takes everything it touches (Graph, tables, settings, tasks,
   alerts) as dependencies, so it runs the same against the real server and against the fakes in scripts/test-mailsync.mjs. */
import crypto from 'crypto';
import { looksLikeNdr, isAutoReply } from './cold-bounce.js';

export const lc = s => String(s == null ? '' : s).trim().toLowerCase();
export const isEmail = s => /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(String(s || ''));
export const hashId = (prefix, key) => prefix + crypto.createHash('sha1').update(String(key)).digest('hex').slice(0, 16);
export const MAIL_FOLDERS = ['inbox', 'sentitems'];
export const DELTA_SELECT = 'id,internetMessageId,conversationId,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,bodyPreview,isDraft';
export const MAX_PAGES_PER_RUN = 12; // 50 messages a page, so a first big catch up carries on in the next run
export const PREVIEW_CHARS = 200;
const CLIENT_TYPES = new Set(['client', 'lead', 'prospect']);
export const isClientType = t => CLIENT_TYPES.has(t);

/* ---------- messages ---------- */
export function previewOf(text, max = PREVIEW_CHARS) {
  return String(text || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

// One Graph message in a mailbox folder, reduced to what the sync needs. direction 'out' for anything we sent.
export function normaliseMessage(m, mailbox, folder) {
  const addr = r => lc(r && r.emailAddress && r.emailAddress.address);
  const mb = lc(mailbox);
  const from = addr(m.from);
  const to = (m.toRecipients || []).map(addr).filter(isEmail);
  const cc = (m.ccRecipients || []).map(addr).filter(isEmail);
  const outgoing = folder === 'sentitems' || from === mb;
  const counterparts = [...new Set((outgoing ? [...to, ...cc] : [from]).filter(e => isEmail(e) && e !== mb))];
  return {
    mailbox: mb,
    key: String(m.internetMessageId || m.id || ''),
    graphId: String(m.id || ''),
    conversationId: String(m.conversationId || ''),
    direction: outgoing ? 'out' : 'in',
    from,
    counterparts,
    at: String((outgoing ? (m.sentDateTime || m.receivedDateTime) : (m.receivedDateTime || m.sentDateTime)) || ''),
    subject: String(m.subject || '').replace(/\s+/g, ' ').trim().slice(0, 200),
    preview: previewOf(m.bodyPreview),
    isDraft: !!m.isDraft,
  };
}

// Why a message is not logged at all (null means it can be considered)
export function skipReason(n) {
  if (n.isDraft) return 'draft';
  if (!n.key || !n.at) return 'incomplete';
  if (n.direction === 'in' && looksLikeNdr(n.from, n.subject)) return 'bounce'; // the cold outreach scan handles these
  if (n.direction === 'in' && /(^|[^a-z])(no-?reply|do-?not-?reply|donotreply|mailer-daemon|postmaster|bounce)[^a-z]/i.test(' ' + n.from.split('@')[0] + ' ')) return 'automatic';
  if (isAutoReply(n.subject, n.preview)) return 'automatic';
  if (!n.counterparts.length) return 'nobody';
  return null;
}

/* ---------- who counts as a contact ---------- */
const TYPE_PRIORITY = { client: 0, candidate: 1, lead: 2, prospect: 3 };
// entries: [{ email, name, company, role, type }]. If an address is on more than one record the client record wins.
export function makeDirectory(entries) {
  const dir = new Map();
  for (const e of entries || []) {
    const email = lc(e.email);
    if (!isEmail(email)) continue;
    const cur = dir.get(email);
    if (!cur || (TYPE_PRIORITY[e.type] ?? 9) < (TYPE_PRIORITY[cur.type] ?? 9)) {
      dir.set(email, { email, name: e.name || '', company: e.company || '', role: e.role || '', type: e.type || 'prospect' });
    }
  }
  return dir;
}
export const domainOf = e => lc(e).split('@')[1] || '';

// Contacts a message belongs to. Nothing else about the message survives this step.
export function matchMessage(n, { directory, doNotLog, suppressed, internalDomains }) {
  const out = [];
  for (const e of n.counterparts) {
    if (internalDomains && internalDomains.has(domainOf(e))) continue;
    if ((doNotLog && doNotLog.has(e)) || (suppressed && suppressed.has(e))) continue;
    const c = directory.get(e);
    if (c) out.push(c);
  }
  return out;
}

/* ---------- suggested record changes (rules only, never applied without a click) ---------- */
export const SUGGESTION_KINDS = {
  interview_confirmed: 'Interview confirmed',
  offer_accepted: 'Offer accepted',
  candidate_withdrawn: 'Candidate withdrawn',
  client_feedback: 'Client feedback',
  role_on_hold: 'Role on hold',
  role_filled: 'Role filled',
};
const RULES = [
  { kind: 'offer_accepted', who: 'candidate', re: /\b(i|we)\b[^.!?]{0,40}\baccept(ed|ing)?\s+(the|your|this)\s+(\w+\s+)?offer\b|\baccept(ed|ing)? (the|your|this) (\w+ )?offer\b|\bformally accept/i },
  { kind: 'candidate_withdrawn', who: 'candidate', re: /\bwithdraw(ing|n|al)?\b|no longer (interested|available|looking)|\b(accepted|taken|received|got) (another|a different|an alternative|a) (offer|job|role|position)\b|\bpull(ing)? out\b|\bdecided not to (proceed|continue|go ahead)\b/i },
  { kind: 'interview_confirmed', who: 'any', re: /\b(confirm(ed|ing)?|can confirm|happy to confirm)\b[^.!?]{0,60}\binterview\b|\binterview\b[^.!?]{0,60}\b(confirmed|works for me|is fine|suits me|suits us|is good for me)\b|\bsee you (on|at)\b[^.!?]{0,40}(interview|\d{1,2}(:\d{2})?\s?(am|pm))/i },
  { kind: 'role_filled', who: 'client', re: /\b(position|role|vacancy)\b[^.!?]{0,50}\b(has been|is now|now) (filled|closed)\b|\b(we('| ha)ve|have) (filled|appointed|recruited|hired)\b|\bfilled (the|this) (position|role|vacancy)\b|\bno longer (recruiting|hiring)\b/i },
  { kind: 'role_on_hold', who: 'client', re: /\b(put|placed|placing|putting|on)\b[^.!?]{0,30}\bhold\b|\b(pause|pausing|paused)\b[^.!?]{0,30}\b(recruitment|hiring|the (role|vacancy|search))\b|\bhiring freeze\b|\bheadcount (freeze|has been frozen)\b/i },
  { kind: 'client_feedback', who: 'client', re: /\bfeedback\b|\b(would|wish|like) to (progress|proceed|move forward)\b|\bnot (going to )?(progress|proceed|move forward)\b|\b(unfortunately|regret)\b[^.!?]{0,60}\b(candidate|applicant|interview)\b|\bnot (quite )?(the right|a good) (fit|match)\b/i },
];
export function detectSuggestions(n, contact) {
  if (n.direction !== 'in' || !contact) return [];
  const text = `${n.subject}\n${n.preview}`;
  const isCand = contact.type === 'candidate';
  const out = [];
  for (const r of RULES) {
    if (r.who === 'candidate' && !isCand) continue;
    if (r.who === 'client' && !isClientType(contact.type)) continue;
    if (r.re.test(text)) out.push({ kind: r.kind, evidence: previewOf(n.preview || n.subject, 160) });
    if (out.length >= 2) break;
  }
  return out;
}

/* ---------- working days ---------- */
const isoOf = d => d.toISOString().slice(0, 10);
const dayDate = iso => new Date(String(iso).slice(0, 10) + 'T00:00:00Z');
export function isWorkingDay(iso, holidays) {
  const d = dayDate(iso).getUTCDay();
  return d !== 0 && d !== 6 && !(holidays && holidays.has(String(iso).slice(0, 10)));
}
// Working days after fromISO, up to and including toISO
export function workingDaysBetween(fromISO, toISO, holidays) {
  let n = 0;
  const d = dayDate(fromISO), end = dayDate(toISO);
  while (d < end) { d.setUTCDate(d.getUTCDate() + 1); if (isWorkingDay(isoOf(d), holidays)) n++; }
  return n;
}

// Client mail with no reply from us for `days` working days. rows are Mailbox Log rows.
const THANKS = /^(thanks|thank you|many thanks|cheers|ok|okay|great|noted|perfect|brilliant|lovely|will do|sounds good|got it)\b[\s\S]{0,40}$/i;
export function unansweredClientMail(rows, { today, days = 2, holidays, lookbackDays = 21 }) {
  const cutoff = isoOf(new Date(dayDate(today).getTime() - lookbackDays * 86400000));
  const latestOut = new Map(); // mailbox|contact -> latest outbound time
  const latestIn = new Map();  // mailbox|contact -> latest inbound row
  for (const r of rows) {
    const k = lc(r.mailbox) + '|' + lc(r.contact_email);
    if (r.direction === 'out') { if (!latestOut.has(k) || r.at > latestOut.get(k)) latestOut.set(k, r.at); }
    else if (isClientType(r.contact_type) && String(r.at).slice(0, 10) >= cutoff) {
      if (!latestIn.has(k) || r.at > latestIn.get(k).at) latestIn.set(k, r);
    }
  }
  const out = [];
  for (const [k, r] of latestIn) {
    if ((latestOut.get(k) || '') > r.at) continue; // we have replied since
    if (THANKS.test(String(r.preview || r.subject || '').trim())) continue; // a thank you needs no answer
    if (workingDaysBetween(String(r.at).slice(0, 10), today, holidays) < days) continue;
    out.push(r);
  }
  return out;
}

/* ---------- the engine ---------- */
export function createMailSync(deps) {
  const {
    graph,              // (method, pathOrUrl) => json; throws errors with .status and .code
    mailLog, suggestions, doNotLog, comms,   // tables: list, append, upsert, updateWhere, remove
    settingsGet, settingsSet,
    loadDirectory,      // () => [{ email, name, company, role, type }]
    loadSuppressed,     // () => Set of lowercased addresses
    internalDomains,    // () => Set of our own domains
    mailboxes,          // () => [{ owner, mailbox }]
    holidays,           // () => Set of ISO days
    today, now,         // () => 'YYYY-MM-DD', () => ISO time
    addTasks, alert,    // addTasks([{ key, user, title, priority, dueDate, context }]), alert(kind, subject, text)
    ready,              // () => true when the database is connected
    log = () => {},
  } = deps;

  const state = { running: false, last: null, lastOk: null, error: '', needsPermission: false, counts: {}, boxes: [] };
  const enc = encodeURIComponent;
  // Build 66.3: insert a row only if its id is not already there (tables without the helper fall back to a plain append)
  const addNew = async (table, row) => (table.appendIfAbsent ? table.appendIfAbsent(row) : table.append(row).then(() => true));
  const LEASE_KEY = 'mail_sync_lease', LEASE_MINUTES = 10;

  async function settings() {
    const g = async (k, d) => { const v = await settingsGet(k); return v === undefined || v === null || v === '' ? d : v; };
    return {
      enabled: lc(await g('mail_sync_enabled', 'no')) === 'yes',
      sinceDay: String(await g('mail_sync_since', '')).slice(0, 10),
      noReplyDays: Math.max(1, Math.min(10, parseInt(await g('mail_noreply_days', '2'), 10) || 2)),
      previewMonths: Math.max(1, Math.min(60, parseInt(await g('mail_preview_months', '12'), 10) || 12)),
    };
  }

  function commsRow(rowId, n, c) {
    const label = n.direction === 'in' ? 'Email received' : 'Email sent';
    return {
      id: 'cm-' + rowId, timestamp: n.at, user: n.owner, entity_type: c.type === 'candidate' ? 'candidate' : 'client', entity_name: c.name || c.email,
      company: c.company || '', role: c.role || '', channel: 'email', direction: n.direction === 'in' ? 'inbound' : 'outbound',
      summary: `${label}: ${n.subject || '(no subject)'}`.slice(0, 300), follow_up_date: '', follow_up_done: '',
    };
  }

  async function handle(n, ctx, counts) {
    const why = skipReason(n);
    if (why) { counts.skipped++; return; }
    const matches = matchMessage(n, ctx);
    if (!matches.length) { counts.ignored++; return; } // not stored, not kept anywhere
    for (const c of matches) {
      const rowId = hashId('ml-', `${n.mailbox}|${n.key}|${c.email}`);
      if (ctx.keys.has(rowId)) { counts.duplicates++; continue; }
      ctx.keys.add(rowId);
      const added = await addNew(mailLog, {
        id: rowId, mailbox: n.mailbox, owner: n.owner, direction: n.direction, contact_email: c.email, contact_name: c.name, contact_type: c.type,
        company: c.company, role: c.role, subject: n.subject, preview: n.preview, at: n.at, conversation_id: n.conversationId, logged_at: now(),
      });
      if (!added) { counts.duplicates++; continue; } // another run wrote it first
      await addNew(comms, commsRow(rowId, n, c)).catch(e => log('comms append failed: ' + e.message));
      counts.logged++;
      for (const s of detectSuggestions(n, c)) {
        const sid = hashId('sg-', rowId + '|' + s.kind);
        if (ctx.sugKeys.has(sid)) continue;
        ctx.sugKeys.add(sid);
        const made = await addNew(suggestions, {
          id: sid, kind: s.kind, contact_email: c.email, contact_name: c.name, contact_type: c.type, company: c.company, role: c.role,
          mailbox: n.mailbox, owner: n.owner, mail_id: rowId, subject: n.subject, evidence: s.evidence, status: 'pending', created_at: now(),
          handled_by: '', handled_at: '', result: '',
        });
        if (made) counts.suggested++;
      }
    }
  }

  async function syncFolder(box, folder, ctx, counts, sinceISO) {
    const key = `mail_delta:${box.mailbox}:${folder}`;
    let url = await settingsGet(key);
    if (!url) url = `/users/${enc(box.mailbox)}/mailFolders/${folder}/messages/delta?$select=${DELTA_SELECT}&$filter=${enc('receivedDateTime ge ' + sinceISO)}`;
    for (let page = 0; page < MAX_PAGES_PER_RUN; page++) {
      let res;
      try { res = await graph('GET', url); }
      catch (e) {
        if (e.status === 410 || /syncStateNotFound|resyncRequired|invalidDeltaToken/i.test(`${e.code || ''} ${e.message || ''}`)) { await settingsSet(key, ''); counts.resets++; return; }
        throw e;
      }
      for (const m of res.value || []) {
        if (m['@removed']) continue;
        const n = normaliseMessage(m, box.mailbox, folder); n.owner = box.owner;
        counts.scanned++;
        await handle(n, ctx, counts);
      }
      if (res['@odata.nextLink']) { url = res['@odata.nextLink']; await settingsSet(key, url); continue; }
      if (res['@odata.deltaLink']) { await settingsSet(key, res['@odata.deltaLink']); return; }
      return;
    }
    counts.more = true; // a big first catch up: carries on in the next run
  }

  // Follow up tasks for client mail nobody has answered
  async function followUps(ctx, st) {
    const hol = await holidays().catch(() => new Set());
    const rows = await mailLog.list();
    const due = unansweredClientMail(rows, { today: today(), days: st.noReplyDays, holidays: hol });
    const tasks = due.map(r => ({
      key: 'mail-noreply-' + r.id, user: lc(r.owner) || 'dan',
      title: `Reply to ${r.contact_name || r.contact_email}${r.company ? ' at ' + r.company : ''}: no reply for ${st.noReplyDays} working days`,
      priority: 'Medium', dueDate: today(),
      context: `Their email "${r.subject || '(no subject)'}" arrived on ${String(r.at).slice(0, 10)} and nothing has gone back from ${r.mailbox} since. Reply, or mark this task done if it needs no answer.`,
    }));
    if (tasks.length) await addTasks(tasks);
    return tasks.length;
  }

  const parseBox = async mailbox => { try { return JSON.parse((await settingsGet('mail_box:' + mailbox)) || '{}'); } catch (e) { return {}; } };

  // Build 66.3: one run at a time. The in-process flag is set before anything is awaited, so two presses of Run now (or a
  // press during a scheduled run) can never both start. A short lease kept in settings also stops an old and a new server
  // instance running together during a deploy. A lease older than LEASE_MINUTES is treated as left behind by a crash.
  async function takeLease() {
    const cur = String((await settingsGet(LEASE_KEY)) || '');
    const at = Date.parse(cur.split('|')[0]);
    if (cur && !isNaN(at) && Date.parse(now()) - at < LEASE_MINUTES * 60000) return { ok: false, since: cur.split('|')[0] };
    await settingsSet(LEASE_KEY, now() + '|' + Math.random().toString(36).slice(2, 8));
    return { ok: true };
  }
  const releaseLease = () => settingsSet(LEASE_KEY, '').catch(() => {});

  async function run({ force = false, sinceDay = '' } = {}) {
    if (!ready()) return { skipped: 'no database' };
    if (state.running) return { skipped: 'A sync is already running. Wait for it to finish, then press Run now again.' };
    state.running = true; // set at once, before any await
    const memT0 = Date.now(), memAt = process.memoryUsage();
    let leased = false;
    const counts = { scanned: 0, logged: 0, ignored: 0, skipped: 0, duplicates: 0, suggested: 0, resets: 0, tasks: 0, more: false };
    const errors = [];
    const boxes = [];
    const finish = async (ok, msg) => {
      state.error = msg; state.last = now(); state.counts = counts; state.boxes = boxes;
      if (ok) state.lastOk = state.last;
      await settingsSet('mail_sync_status', JSON.stringify({ at: state.last, ok, error: msg, counts, boxes }).slice(0, 4000)).catch(() => {});
    };
    const stop = async msg => {
      await finish(false, msg);
      await alert('mailsync', 'Live 2 Help: mailbox sync could not start', msg).catch(() => {});
      return { counts, errors: [msg], boxes, outcome: 'failed', needsPermission: false };
    };
    try {
      const st = await settings();
      if (!st.enabled && !force) return { skipped: 'off' };
      const lease = await takeLease();
      if (!lease.ok) return { skipped: `A sync that started at ${lease.since} is still running or was interrupted. Try again in a few minutes.` };
      leased = true;
      state.needsPermission = false; state.error = '';
      let loaded;
      try { loaded = await Promise.all([loadDirectory(), doNotLog.list(), loadSuppressed(), mailLog.list(), suggestions.list()]); }
      catch (e) { return await stop(`Could not read the client, candidate and log records (${e.message}). No mail was read, so nothing is missed: the next run starts from the same place.`); }
      const [dirEntries, dnlRows, suppressed] = loaded;
      // Nov 2026 memory fix: only the ids of the mail log and suggestions are needed, so the full rows are let go at once
      const logKeys = new Set(loaded[3].map(r => r.id)), sugKeys = new Set(loaded[4].map(r => r.id));
      loaded.length = 0;
      // No contacts at all means the record sources could not be read. Stop here: reading mail now would move the
      // place we are up to without being able to tell who is a contact, and those messages would be missed for good.
      if (!dirEntries || !dirEntries.length) return await stop('No client, lead, prospect or candidate email addresses were found, so no mail was read. Nothing is missed: the next run starts from the same place.');
      const ctx = {
        directory: makeDirectory(dirEntries), doNotLog: new Set(dnlRows.map(r => lc(r.email))), suppressed, internalDomains: internalDomains(),
        keys: logKeys, sugKeys,
      };
      const since = (sinceDay || st.sinceDay || isoOfDaysAgo(today(), 7)) + 'T00:00:00Z';
      for (const box of mailboxes()) {
        if (!box.mailbox) continue;
        const b = { owner: box.owner, mailbox: box.mailbox, ok: true, error: '', scanned: 0, logged: 0 };
        const before = { scanned: counts.scanned, logged: counts.logged };
        for (const folder of MAIL_FOLDERS) {
          try { await syncFolder(box, folder, ctx, counts, since); }
          catch (e) {
            b.ok = false;
            if (e.status === 403 || /Authorization_RequestDenied|ErrorAccessDenied|AccessDenied/i.test(e.code || '')) {
              state.needsPermission = true;
              const m = `${box.mailbox} ${folder}: Microsoft 365 refused access (${e.status || e.code}). Microsoft said: ${String(e.message || '').replace(/^Microsoft Graph [A-Z]+ failed /, '').slice(0, 220)}. Check the Mail.ReadWrite permission and the application access policy.`;
              errors.push(m); b.error = b.error || m;
            } else { const m = `${box.mailbox} ${folder}: ${e.message}`; errors.push(m); b.error = b.error || m; }
          }
        }
        b.scanned = counts.scanned - before.scanned; b.logged = counts.logged - before.logged;
        b.at = now();
        if (b.ok) await settingsSet('mail_box:' + box.mailbox, JSON.stringify({ lastOk: b.at })).catch(() => {});
        else { const prev = await parseBox(box.mailbox); await settingsSet('mail_box:' + box.mailbox, JSON.stringify({ lastOk: prev.lastOk || '', lastFail: b.at, error: b.error.slice(0, 300) })).catch(() => {}); }
        boxes.push(b);
      }
      try { counts.tasks = await followUps(ctx, st); } catch (e) { errors.push('Follow up check: ' + e.message); }
      const okCount = boxes.filter(b => b.ok).length;
      const outcome = !errors.length ? 'ok' : (okCount > 0 ? 'partial' : 'failed');
      await finish(outcome === 'ok', errors.join(' | '));
      if (outcome === 'partial') state.lastPartial = state.last;
      if (errors.length) await alert('mailsync', 'Live 2 Help: mailbox sync problem', errors.join('\n') + '\n\nNothing was lost. The sync tries again at the next run (every 15 minutes in working hours).').catch(() => {});
      return { counts, errors, boxes, outcome, needsPermission: state.needsPermission };
    } finally {
      if (leased) await releaseLease();
      state.running = false;
      { const m = process.memoryUsage(); console.log(`[mem] mailsync ${Math.round((Date.now() - memT0) / 1000)}s heap ${Math.round(memAt.heapUsed / 1048576)}->${Math.round(m.heapUsed / 1048576)}MB rss ${Math.round(memAt.rss / 1048576)}->${Math.round(m.rss / 1048576)}MB`); }
    }
  }

  // Build 66.3: owner only health check. Counts only, no names, subjects or text.
  async function check() {
    const [logRows, sugRows, boxState] = await Promise.all([mailLog.list(), suggestions.list(), Promise.all(mailboxes().map(async b => [b.mailbox, await parseBox(b.mailbox)]))]);
    const dupIds = rows => { const seen = new Map(); rows.forEach(r => seen.set(r.id, (seen.get(r.id) || 0) + 1)); let ids = 0, extra = 0; for (const n of seen.values()) if (n > 1) { ids++; extra += n - 1; } return { ids, extraRows: extra }; };
    const by = (rows, f) => { const o = {}; rows.forEach(r => { const k = f(r); o[k] = (o[k] || 0) + 1; }); return o; };
    const perMailbox = {};
    for (const b of mailboxes()) {
      const rows = logRows.filter(r => lc(r.mailbox) === b.mailbox);
      perMailbox[b.owner] = {
        rows: rows.length, distinctIds: new Set(rows.map(r => r.id)).size, distinctMessages: new Set(rows.map(r => r.conversation_id + '|' + r.at + '|' + r.contact_email)).size,
        byDirection: by(rows, r => r.direction), byContactType: by(rows, r => r.contact_type), byLoggedDay: by(rows, r => String(r.logged_at || '').slice(0, 10)), byMailDay: by(rows, r => String(r.at || '').slice(0, 10)),
        lastOk: (boxState.find(x => x[0] === b.mailbox) || [0, {}])[1].lastOk || '', lastFail: (boxState.find(x => x[0] === b.mailbox) || [0, {}])[1].lastFail || '',
      };
    }
    const pend = sugRows.filter(s => s.status === 'pending');
    return {
      mailboxLog: { rows: logRows.length, duplicates: dupIds(logRows) },
      suggestions: { rows: sugRows.length, byStatus: by(sugRows, s => s.status || '(blank)'), duplicates: dupIds(sugRows), pendingDuplicates: dupIds(pend), pendingByKind: by(pend, s => s.kind), withResultButPending: pend.filter(s => s.result).length },
      perMailbox,
    };
  }

  // Build 66.3: remove repeated rows left by overlapping runs. Keeps one row per id. For suggestions the row that was handled wins.
  async function repair(commsDedupe) {
    const handledFirst = list => { const i = list.findIndex(o => o.status && o.status !== 'pending'); return i >= 0 ? i : 0; };
    const out = { mailboxLog: await mailLog.dedupeById(null, null), suggestions: await suggestions.dedupeById(null, handledFirst) };
    if (commsDedupe) out.comms = await commsDedupe();
    return out;
  }

  // Do not log: stop logging an address and remove what was already stored for it
  async function addDoNotLog(email, by) {
    email = lc(email);
    if (!isEmail(email)) throw new Error('That is not an email address');
    await doNotLog.upsert({ id: hashId('dn-', email), email, added_by: by || '', added_at: now() });
    const rows = (await mailLog.list()).filter(r => lc(r.contact_email) === email);
    for (const r of rows) { await mailLog.remove(r.id); await comms.remove('cm-' + r.id).catch(() => {}); }
    await suggestions.updateWhere(s => lc(s.contact_email) === email && s.status === 'pending', s => ({ ...s, status: 'dismissed', handled_by: by || '', handled_at: now(), result: 'Do not log' }));
    return { removed: rows.length };
  }
  async function removeDoNotLog(email) { await doNotLog.remove(hashId('dn-', lc(email))); }

  // Previews are kept for a limited time; the line itself (who, when, subject) stays on the timeline
  async function purgeOldPreviews() {
    const st = await settings();
    const cut = new Date(Date.now() - st.previewMonths * 30.5 * 86400000).toISOString();
    return mailLog.updateWhere(r => r.preview && String(r.at) < cut, r => ({ ...r, preview: '' }));
  }

  return { run, state, settings, addDoNotLog, removeDoNotLog, purgeOldPreviews, followUps, check, repair, boxStates: async () => Object.fromEntries(await Promise.all(mailboxes().map(async b => [b.mailbox, await parseBox(b.mailbox)]))) };
}

function isoOfDaysAgo(todayISO, n) { return isoOf(new Date(dayDate(todayISO).getTime() - n * 86400000)); }
