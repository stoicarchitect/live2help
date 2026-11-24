/* Candidate offer portal (build 72)
   The offer stage, done online like client onboarding. One secure link per candidate offer, kept for the whole journey:
     1. the offer letter, accepted (signed) or declined on screen
     2. the information request as an online form (details, right to work, references)
     3. the pre-start details, confirmed with one tap
   There is also a one tap "received" link for the client on the handover pack email.
   Everything that touches the rest of the workspace (moving the card, tasks, email, Drive, the offer details record) is passed in
   as hooks by server.js, so this file only holds the page logic, the database and the routes. */
import crypto from 'crypto';

export const OFFER_CONSENT = 'I have read this offer letter and I accept the offer of employment set out in it. I understand that this is my electronic signature and has the same effect as a handwritten one.';
export const OFFER_LINK_DAYS = 30;
const sha = t => crypto.createHash('sha256').update(String(t)).digest('hex');
const clean = (v, n = 200) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, n);
const lc = s => String(s || '').trim().toLowerCase();
const nameKey = s => String(s || '').toLowerCase().replace(/[^a-z]+/g, ' ').trim();
const ipOf = req => String((req && req.ip) || '').replace(/^::ffff:/, '').slice(0, 64);
const cell = s => String(s == null ? '' : s).replace(/\|/g, '/').replace(/\n+/g, ' ').trim();
const isHourly = s => /per hour|hourly|an hour/i.test(String(s || ''));

/* ---------- the offer letter, as the same markdown the client documents use ---------- */
export function offerLetterSource(v) {
  const rows = [];
  const add = (k, val) => { if (String(val || '').trim()) rows.push(`| ${k} | ${cell(val)} |`); };
  add('Position', v.job_title);
  add('Company', v.company);
  add('Location', v.work_location);
  add('Salary', v.salary ? (isHourly(v.salary) ? v.salary : v.salary + ' per annum') : 'To be confirmed');
  add('Start Date', v.start_date_long || 'To be confirmed');
  add('Reporting To', v.reporting_to); // left out when not known yet, it is confirmed when they start
  add('Employment Type', v.employment_type);
  const by = v.offer_reply_by ? ` by ${v.offer_reply_by}` : '';
  return [
    '---',
    'title: Offer of Employment',
    `subtitle: ${cell(v.job_title)} at ${cell(v.company)}`,
    `version: ${cell(v.today)}`,
    'signing: offer',
    '---',
    '',
    `Dear ${cell(v.candidate_first || v.candidate_name)},`,
    '',
    `We are delighted to confirm that following a successful interview process, ${cell(v.company)} would like to extend an offer of employment to you for the position outlined below.`,
    '',
    `This offer has been made on the basis of the information you provided during the recruitment process and is subject to the terms detailed in this letter. A full contract of employment will be issued directly by ${cell(v.company)} prior to your start date.`,
    '',
    '## Offer Details',
    '',
    '| | |',
    '|---|---|',
    ...rows,
    '',
    '## Next Steps',
    '',
    `To accept this offer, please sign at the end of this letter${by}. It takes less than a minute and there is nothing to print. If you do not wish to accept, you can decline on the same page.`,
    '',
    `By accepting you confirm that you agree to the offer above${v.start_date_long ? ', including the start date,' : ''} and that you have no questions outstanding about it. If you do have any questions, please speak to us before you sign.`,
    '',
    'Once your acceptance is received, Ella from our team will be in touch with further information to prepare you for your start, including a short online information form and details on what to expect before day one.',
    '',
    '## Important Note',
    '',
    `This offer letter is issued by Live 2 Help Recruitment on behalf of ${cell(v.company)} as part of the recruitment process we have managed. The formal employment relationship will be between you and ${cell(v.company)} directly. Please ensure you resign from your current position only once you have received written confirmation of this offer and are satisfied with the terms.`,
    '',
    'We are really pleased to have placed you in this role and look forward to supporting your transition. If you have any questions at all, please do not hesitate to get in touch.',
    '',
    'Warm regards,',
    '',
    `${cell(v.sender_name || 'Ella Pietrzak')}, ${cell(v.sender_title || 'Live 2 Help Recruitment')}`,
    '',
  ].join('\n');
}

/* ---------- the information request form (stage 2) ---------- */
export const RTW_OPTIONS = [
  'UK or Irish passport',
  'Other passport with a visa or biometric residence permit (share code)',
  'EU Settlement Scheme status (share code)',
  'UK birth certificate and National Insurance number',
  'Something else, I will explain below',
];
export const INFO_FORM = [
  { key: 'a', title: 'Your details', intro: 'We need these for your employment record. Please give your name as it appears on your passport or driving licence.', fields: [
    { k: 'legal_name', label: 'Full legal name', req: true, wide: true },
    { k: 'address1', label: 'Home address, line 1', req: true, wide: true },
    { k: 'address2', label: 'Home address, line 2' },
    { k: 'town', label: 'Town or city', req: true },
    { k: 'postcode', label: 'Postcode', req: true },
    { k: 'email', label: 'Personal email address', type: 'email', req: true },
    { k: 'mobile', label: 'Personal mobile number', type: 'tel', req: true },
    { k: 'dob', label: 'Date of birth', type: 'date', req: true },
    { k: 'ni_number', label: 'National Insurance number', help: 'Needed for payroll. Leave blank if you do not have it to hand and we will ask again later.' },
    { k: 'em_name', label: 'Emergency contact name', req: true },
    { k: 'em_relationship', label: 'Their relationship to you', req: true },
    { k: 'em_phone', label: 'Their phone number', type: 'tel', req: true },
  ] },
  { key: 'b', title: 'Right to work', intro: 'We must confirm your right to work in the UK before you start. Tell us what you will use and, if you like, add a clear photo or scan now.', fields: [
    { k: 'rtw_type', label: 'Which document will you use?', type: 'select', options: RTW_OPTIONS, req: true, wide: true },
    { k: 'rtw_share_code', label: 'Share code (only if you chose a share code option)', help: 'Get one at gov.uk/prove-right-to-work. It starts with W.' },
    { k: 'rtw_note', label: 'Anything to add about your right to work', type: 'textarea', wide: true },
    { k: 'rtw_files', label: 'Photo or scan of your document (optional)', type: 'files', wide: true, help: 'A clear photo from your phone is fine. Photo page for a passport. JPG, PNG or PDF, up to 5 MB each.' },
  ] },
  { key: 'c', title: 'References', intro: 'Two professional references, ideally line managers or supervisors from your two most recent employers.', fields: [
    { k: 'ref1_name', label: 'Referee 1: full name', req: true }, { k: 'ref1_title', label: 'Job title' },
    { k: 'ref1_company', label: 'Company', req: true }, { k: 'ref1_relationship', label: 'Their relationship to you' },
    { k: 'ref1_email', label: 'Email address', type: 'email', req: true }, { k: 'ref1_phone', label: 'Phone number', type: 'tel' },
    { k: 'ref2_name', label: 'Referee 2: full name', req: true }, { k: 'ref2_title', label: 'Job title' },
    { k: 'ref2_company', label: 'Company', req: true }, { k: 'ref2_relationship', label: 'Their relationship to you' },
    { k: 'ref2_email', label: 'Email address', type: 'email', req: true }, { k: 'ref2_phone', label: 'Phone number', type: 'tel' },
  ] },
  { key: 'd', title: 'Anything else?', intro: 'Any reasonable adjustments, requirements for your first day, or anything that may affect your start date.', fields: [
    { k: 'special', label: 'Anything we should know', type: 'textarea', wide: true },
    { k: 'start_ok', label: 'Is your start date confirmed as agreed?', type: 'select', options: ['Yes, the start date works for me', 'No, I need to talk to you about it'], req: true, wide: true },
  ] },
];
const FIELD_LIST = INFO_FORM.flatMap(s => s.fields);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function cleanInfo(input, submit) {
  const a = {}, problems = [];
  for (const f of FIELD_LIST) {
    if (f.type === 'files') continue;
    let v = clean((input || {})[f.k], f.type === 'textarea' ? 1200 : 200);
    if (f.type === 'date' && v && !/^\d{4}-\d{2}-\d{2}$/.test(v)) v = '';
    if (f.type === 'select' && v && !f.options.includes(v)) v = '';
    a[f.k] = v;
    if (submit && f.req && !v) problems.push({ k: f.k, msg: `Please fill in: ${f.label}` });
    if (v && f.type === 'email' && !EMAIL_RE.test(v)) problems.push({ k: f.k, msg: `That email address does not look right: ${f.label}` });
  }
  if (a.dob) {
    const t = Date.parse(a.dob), age = (Date.now() - t) / (365.25 * 86400000);
    if (!(t > 0) || age < 16 || age > 90) problems.push({ k: 'dob', msg: 'Please check your date of birth' });
  }
  return { answers: a, problems };
}

/* ---------- the pre-start page (stage 3): what the candidate reads and confirms ---------- */
export const DAY_ONE_CHECKLIST = [
  ['Valid passport or Right to Work document', 'Original required on day 1'],
  ['National Insurance number', 'Have this to hand for payroll'],
  ['Bank account details', 'For payroll setup'],
  ['Emergency contact details', 'For HR records'],
  ['Relevant qualifications or certificates', 'If applicable to your role'],
];
export const FIRST_WEEK = [
  'You will likely be introduced to the team and shown around the site or office on your first day.',
  'HR or your line manager will walk you through your contract, policies and any paperwork that needs signing.',
  'You may complete some mandatory training or inductions during the first few days. This is completely normal.',
  'Do not put pressure on yourself to know everything immediately. The first week is for listening, observing and asking questions.',
  'If anything feels unclear, speak to your line manager early. It is always better to ask.',
];

/* ---------- schema ---------- */
const schemaReady = new WeakMap();
export function ensureSchema(pool) {
  if (!schemaReady.has(pool)) {
    const p = pool.query(`
      create table if not exists offer_portal (
        id text primary key,
        candidate_name text not null,
        candidate_email text not null default '',
        company text not null default '',
        role text not null default '',
        created_by text not null default '',
        token_hash text not null,
        token_enc text not null default '',
        expires_at timestamptz,
        preview boolean not null default false,
        client_token_hash text not null default '',
        client_token_enc text not null default '',
        vals jsonb not null default '{}'::jsonb,
        status text not null default 'sent',
        manual boolean not null default false,
        doc_source text not null default '',
        doc_hash text not null default '',
        sent_at timestamptz,
        viewed_at timestamptz,
        signed_at timestamptz,
        signer_name text not null default '',
        method text not null default '',
        signature_image text not null default '',
        ip text not null default '',
        user_agent text not null default '',
        record jsonb not null default '{}'::jsonb,
        pdf bytea,
        pdf_drive_id text not null default '',
        declined_at timestamptz,
        decline_reason text not null default '',
        info_status text not null default 'none',
        info_requested_at timestamptz,
        info jsonb not null default '{}'::jsonb,
        info_submitted_at timestamptz,
        prestart_status text not null default 'none',
        prestart_sent_at timestamptz,
        prestart_confirmed_at timestamptz,
        client_sent_at timestamptz,
        client_confirmed_at timestamptz,
        events jsonb not null default '[]'::jsonb,
        reminders jsonb not null default '{}'::jsonb,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      );
      create index if not exists offer_portal_token on offer_portal (token_hash);
      create index if not exists offer_portal_ctoken on offer_portal (client_token_hash);
      create table if not exists offer_portal_files (
        id serial primary key,
        offer_id text not null,
        filename text not null,
        mime text not null,
        data bytea not null,
        created_at timestamptz not null default now()
      );
      create index if not exists offer_portal_files_offer on offer_portal_files (offer_id);
    `).catch(e => { schemaReady.delete(pool); throw e; });
    schemaReady.set(pool, p);
  }
  return schemaReady.get(pool);
}

async function addEvent(pool, id, what, req) {
  const e = { at: new Date().toISOString(), what, ip: ipOf(req) };
  await pool.query(
    `update offer_portal set events = (select coalesce(jsonb_agg(x order by i), '[]'::jsonb) from
       (select x, i from jsonb_array_elements(coalesce(events, '[]'::jsonb) || $2::jsonb) with ordinality t(x, i) order by i desc limit 200) s),
       updated_at = now() where id = $1`, [id, JSON.stringify([e])]);
}

/* ---------- issuing and finding links (used by server.js when an email is built) ---------- */
// kind: 'offer' | 'info_request' | 'prestart' | 'placement'
// The same link is kept for the whole journey, so older emails keep working. Its life is extended each time.
export async function issue(d, pool, { id, candidate, values, kind, by, preview }) {
  await ensureSchema(pool);
  const cur = (await pool.query('select * from offer_portal where id = $1', [id])).rows[0];
  const days = OFFER_LINK_DAYS;
  let token = cur && cur.token_enc ? d.decrypt(cur.token_enc) : null;
  if (token && sha(token) !== cur.token_hash) token = null;
  const expires = new Date(Date.now() + days * 86400000);
  const snapshot = JSON.stringify(values || {});
  if (!cur) {
    token = crypto.randomBytes(24).toString('base64url');
    const manual = kind !== 'offer';
    const src = kind === 'offer' ? offerLetterSource(values) : '';
    await pool.query(
      `insert into offer_portal (id, candidate_name, candidate_email, company, role, created_by, token_hash, token_enc, expires_at, preview, vals, status, manual, doc_source, doc_hash)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15)`,
      [id, candidate.name, lc(candidate.email), candidate.company || '', candidate.role || '', by || '', sha(token), d.encrypt(token), expires, !!preview, snapshot,
        manual ? 'accepted' : 'sent', manual, src, src ? d.docHash(src) : '']);
    if (manual) await addEvent(pool, id, 'Link made after the offer was accepted by another route', null);
  } else {
    if (!token) token = crypto.randomBytes(24).toString('base64url');
    const sets = ['token_hash = $2', 'token_enc = $3', 'expires_at = $4', 'vals = $5::jsonb', 'candidate_email = $6', 'updated_at = now()'];
    const args = [id, sha(token), d.encrypt(token), expires, snapshot, lc(candidate.email) || cur.candidate_email];
    // the letter can still be reworded until the candidate has acted on it
    if (kind === 'offer' && ['sent', 'viewed', 'declined'].includes(cur.status)) {
      const src = offerLetterSource(values);
      args.push(src, d.docHash(src)); sets.push(`doc_source = $${args.length - 1}`, `doc_hash = $${args.length}`, "status = 'sent'");
      if (cur.status === 'declined') sets.push('declined_at = null', "decline_reason = ''");
    }
    await pool.query(`update offer_portal set ${sets.join(', ')} where id = $1`, args);
  }
  const row = (await pool.query('select * from offer_portal where id = $1', [id])).rows[0];
  const out = { url: d.urlFor(token, row.preview), row };
  if (kind === 'placement') {
    let ct = row.client_token_enc ? d.decrypt(row.client_token_enc) : null;
    if (!ct || sha(ct) !== row.client_token_hash) {
      ct = crypto.randomBytes(24).toString('base64url');
      await pool.query('update offer_portal set client_token_hash = $2, client_token_enc = $3 where id = $1', [id, sha(ct), d.encrypt(ct)]);
    }
    out.clientUrl = d.clientUrlFor(ct, row.preview);
  }
  return out;
}

// Called once the email has really gone out
export async function markSent(pool, id, kind) {
  await ensureSchema(pool);
  if (kind === 'offer') await pool.query("update offer_portal set sent_at = now(), updated_at = now() where id = $1 and sent_at is null", [id]);
  if (kind === 'info_request') await pool.query("update offer_portal set info_requested_at = now(), info_status = case when info_status in ('none') then 'requested' else info_status end, updated_at = now() where id = $1", [id]);
  if (kind === 'prestart') await pool.query("update offer_portal set prestart_sent_at = now(), prestart_status = case when prestart_status = 'none' then 'sent' else prestart_status end, updated_at = now() where id = $1", [id]);
  if (kind === 'placement') await pool.query("update offer_portal set client_sent_at = now(), updated_at = now() where id = $1", [id]);
  await addEvent(pool, id, `Email sent: ${kind.replace(/_/g, ' ')}`, null);
}

export async function statusFor(pool, id) {
  await ensureSchema(pool);
  const r = (await pool.query('select * from offer_portal where id = $1', [id])).rows[0];
  if (!r) return { exists: false };
  const files = (await pool.query('select id, filename, mime, length(data) as size from offer_portal_files where offer_id = $1 order by id', [id])).rows;
  return {
    exists: true, status: r.status, manual: r.manual, sent_at: r.sent_at, viewed_at: r.viewed_at, signed_at: r.signed_at, signer_name: r.signer_name, method: r.method,
    declined_at: r.declined_at, decline_reason: r.decline_reason, has_pdf: !!r.pdf,
    info_status: r.info_status, info_requested_at: r.info_requested_at, info_submitted_at: r.info_submitted_at,
    prestart_status: r.prestart_status, prestart_sent_at: r.prestart_sent_at, prestart_confirmed_at: r.prestart_confirmed_at,
    client_sent_at: r.client_sent_at, client_confirmed_at: r.client_confirmed_at, expires_at: r.expires_at,
    files: files.map(f => ({ n: f.id, name: f.filename, mime: f.mime, size: Number(f.size) })),
    events: (r.events || []).slice(-12).reverse(),
  };
}

/* ---------- routes ---------- */
export function mountOfferPortal(app, d) {
  const bad = new Map();
  const miss = req => { const ip = ipOf(req), now = Date.now(), r = bad.get(ip); if (!r || r.reset < now) bad.set(ip, { n: 1, reset: now + 15 * 60 * 1000 }); else r.n++; if (bad.size > 5000) for (const [k, v] of bad) if (v.reset < now) bad.delete(k); };
  const locked = req => { const r = bad.get(ipOf(req)); return r && r.reset > Date.now() && r.n >= 30; };
  const fail = (res, where, e) => { console.error(`${where} error:`, e.message); res.status(/database is not connected|test database/i.test(e.message) ? 503 : 500).json({ error: /database is not connected|test database/i.test(e.message) ? e.message : 'Something went wrong. Please try again in a minute.' }); };

  async function byToken(req, res, col = 'token_hash') {
    if (locked(req)) { res.status(429).json({ error: 'Too many attempts. Please try again later.' }); return null; }
    const tok = String(req.params.token || '');
    const nope = () => { miss(req); res.status(404).json({ error: 'This link is not valid. Please use the most recent link we emailed you.', code: 'BAD_LINK' }); return null; };
    if (!/^[A-Za-z0-9_-]{30,80}$/.test(tok)) return nope();
    const pool = d.pool(); await ensureSchema(pool);
    const row = (await pool.query(`select * from offer_portal where ${col} = $1`, [sha(tok)])).rows[0];
    if (!row) return nope();
    if (row.expires_at && Date.parse(row.expires_at) < Date.now()) { res.status(410).json({ error: 'This link has expired. Please reply to our email or call 01902 945444 and we will send you a new one.', code: 'EXPIRED' }); return null; }
    return { pool, row };
  }
  const firstOf = n => String(n || '').trim().split(/\s+/)[0] || '';

  app.use('/api/cportal', (req, res, next) => { res.set('Cache-Control', 'no-store'); res.set('Referrer-Policy', 'no-referrer'); res.set('X-Robots-Tag', 'noindex'); next(); });

  // everything the page needs
  app.get('/api/cportal/:token', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      const v = row.vals || {};
      if (!row.viewed_at && row.status === 'sent') await pool.query("update offer_portal set viewed_at = now(), status = 'viewed' where id = $1", [row.id]);
      if (!(row.events || []).some(e => e.what === 'Portal opened' && Date.now() - Date.parse(e.at) < 3600 * 1000)) await addEvent(pool, row.id, 'Portal opened', req);
      const files = (await pool.query('select id, filename, mime, length(data) as size from offer_portal_files where offer_id = $1 order by id', [row.id])).rows;
      const accepted = row.status === 'accepted';
      res.json({
        first: firstOf(row.candidate_name), name: row.candidate_name, company: row.company, role: v.job_title || row.role,
        status: row.status, manual: row.manual, expires_at: row.expires_at,
        offer: { signed_at: row.signed_at, declined_at: row.declined_at, has_letter: !!row.doc_source, reply_by: v.offer_reply_by || '', consent: OFFER_CONSENT },
        info: { status: row.info_status, locked: !accepted, answers: row.info && Object.keys(row.info).length ? row.info : {
          legal_name: row.candidate_name, email: row.candidate_email, mobile: v.candidate_phone || '' }, schema: INFO_FORM, submitted_at: row.info_submitted_at,
          files: files.map(f => ({ n: f.id, name: f.filename, size: Number(f.size) })) },
        prestart: row.prestart_status === 'none' ? null : {
          status: row.prestart_status, confirmed_at: row.prestart_confirmed_at,
          details: [['Start date', v.start_date_long], ['Start time', v.start_time], ['Location', v.work_location], ['Who to ask for', v.reporting_to],
            ['Parking', v.parking], ['What to wear', v.dress_code]].filter(x => x[1] && x[1] !== 'N/A' && x[1] !== 'To be confirmed'),
          company_item: v.company_item && v.company_item !== 'Anything specific to the site' ? [v.company_item, v.company_item_note] : null,
          checklist: DAY_ONE_CHECKLIST, first_week: FIRST_WEEK },
        contact: { name: v.sender_name || 'Ella Pietrzak', title: v.sender_title || 'Recruitment Coordinator', email: v.sender_email || 'ella.pietrzak@live2helprecruitment.co.uk', phone: v.sender_phone || '07434 351996' },
      });
    } catch (e) { fail(res, 'GET cportal', e); }
  });

  app.get('/api/cportal/:token/doc', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { row } = got;
      if (!row.doc_source) return res.status(404).json({ error: 'There is no offer letter on this link' });
      const parsed = d.parseDoc(row.doc_source);
      res.json({ name: 'Offer letter', meta: parsed.meta, html: d.docToHtml(parsed.blocks), hash: row.doc_hash, signed: row.signed_at ? { signed_at: row.signed_at, signer_name: row.signer_name } : null });
    } catch (e) { fail(res, 'GET cportal doc', e); }
  });

  app.get('/api/cportal/:token/pdf', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { row } = got;
      if (!row.doc_source) return res.status(404).json({ error: 'There is no offer letter on this link' });
      let buf = row.pdf, label = 'Signed';
      if (!buf) { const p = d.parseDoc(row.doc_source); buf = await d.buildPdf({ meta: p.meta, blocks: p.blocks, sign: null }); label = 'Draft'; }
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${`Offer letter ${row.company} ${label}.pdf`.replace(/[\\/:*?"<>|]/g, '')}"`);
      res.send(buf);
    } catch (e) { fail(res, 'GET cportal pdf', e); }
  });

  app.post('/api/cportal/:token/sign', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      if (row.status === 'accepted') return res.status(409).json({ error: 'This offer has already been accepted', code: 'ALREADY_SIGNED' });
      if (row.status === 'declined') return res.status(409).json({ error: 'This offer was declined. Please contact us if you have changed your mind.' });
      if (!row.doc_source) return res.status(409).json({ error: 'There is no offer letter to sign on this link' });
      const b = req.body || {};
      if (b.agree !== true) return res.status(400).json({ error: 'Please tick the box to confirm you accept the offer' });
      const method = b.method === 'drawn' ? 'drawn' : 'typed';
      let png = null;
      if (method === 'drawn') { png = d.pngFromDataUrl(b.signature); if (!png) return res.status(400).json({ error: 'Please draw your signature in the box' }); }
      else if (nameKey(b.typed) !== nameKey(row.candidate_name)) return res.status(400).json({ error: `Please type your full name exactly as shown: ${row.candidate_name}` });
      if (String(b.hash || '') !== row.doc_hash) return res.status(409).json({ error: 'This letter was updated while you had it open. Please read it again before accepting.', code: 'CHANGED' });
      const now = new Date().toISOString(), ip = ipOf(req), ua = clean(req.get('user-agent'), 300);
      const parsed = d.parseDoc(row.doc_source);
      const events = (row.events || []).filter(e => e.what === 'Portal opened').slice(-5).concat([{ at: now, what: `Accepted by ${row.candidate_name} (${method === 'drawn' ? 'drawn signature' : 'typed name'})`, ip }]);
      const record = { docHash: row.doc_hash, reference: `OFFER-${row.id}`.toUpperCase().slice(0, 80), company: row.company, signerEmail: row.candidate_email,
        method, consentText: OFFER_CONSENT, ip, userAgent: ua, events };
      const pdf = await d.buildPdf({ meta: parsed.meta, blocks: parsed.blocks, sign: { client: { name: row.candidate_name, title: '', png, at: now }, agency: null, record,
        labels: { client: 'Candidate acceptance', party: 'Candidate', noAgency: true, intro: 'Accepted electronically through the Live 2 Help candidate portal. By signing, the candidate confirms they have read the offer letter and accept the offer set out in it.', via: 'Accepted through the candidate portal after reading the offer letter' } } });
      const upd = await pool.query(
        `update offer_portal set status = 'accepted', signed_at = $2, signer_name = $3, method = $4, signature_image = $5, ip = $6, user_agent = $7, record = $8::jsonb, pdf = $9,
           info_status = case when info_status = 'none' then 'open' else info_status end, updated_at = now()
         where id = $1 and status in ('sent','viewed') returning *`,
        [row.id, now, row.candidate_name, method, png ? png.toString('base64') : '', ip, ua, JSON.stringify(record), pdf]);
      if (!upd.rows[0]) return res.status(409).json({ error: 'This offer has already been accepted', code: 'ALREADY_SIGNED' });
      await addEvent(pool, row.id, `Offer accepted by ${row.candidate_name}`, req);
      let moved = '';
      try { moved = (await d.onAccepted(upd.rows[0], pdf)) || ''; } catch (e) { console.error('offer accepted hook failed:', e.message); }
      res.json({ ok: true, signed_at: now, moved });
    } catch (e) { fail(res, 'POST cportal sign', e); }
  });

  app.post('/api/cportal/:token/decline', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      if (!['sent', 'viewed'].includes(row.status)) return res.status(409).json({ error: row.status === 'accepted' ? 'This offer has already been accepted. Please call us if you need to change anything.' : 'This offer has already been declined.' });
      const reason = clean((req.body || {}).reason, 600);
      const upd = await pool.query("update offer_portal set status = 'declined', declined_at = now(), decline_reason = $2, updated_at = now() where id = $1 and status in ('sent','viewed') returning *", [row.id, reason]);
      if (!upd.rows[0]) return res.status(409).json({ error: 'This offer has already been dealt with' });
      await addEvent(pool, row.id, 'Offer declined', req);
      try { await d.onDeclined(upd.rows[0]); } catch (e) { console.error('offer declined hook failed:', e.message); }
      res.json({ ok: true });
    } catch (e) { fail(res, 'POST cportal decline', e); }
  });

  // information form: save as they go, or submit
  app.post('/api/cportal/:token/info', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      if (row.status !== 'accepted') return res.status(409).json({ error: 'This form opens once the offer has been accepted.' });
      const submit = (req.body || {}).submit === true;
      const { answers, problems } = cleanInfo((req.body || {}).answers, submit);
      if (submit) {
        const n = Number((await pool.query('select count(*)::int as n from offer_portal_files where offer_id = $1', [row.id])).rows[0].n);
        if (!n && !answers.rtw_type) problems.push({ k: 'rtw_type', msg: 'Please tell us which right to work document you will use' });
        if (problems.length) return res.status(400).json({ error: problems[0].msg, problems });
      } else if (problems.length) return res.status(400).json({ error: problems[0].msg, problems });
      const status = submit ? 'submitted' : (row.info_status === 'submitted' ? 'submitted' : 'started');
      const upd = await pool.query(
        `update offer_portal set info = $2::jsonb, info_status = $3, info_submitted_at = case when $4 then now() else info_submitted_at end, updated_at = now() where id = $1 returning *`,
        [row.id, JSON.stringify(answers), status, submit]);
      if (submit) {
        await addEvent(pool, row.id, 'Information form submitted', req);
        try { await d.onInfo(upd.rows[0], answers); } catch (e) { console.error('info hook failed:', e.message); }
      }
      res.json({ ok: true, status });
    } catch (e) { fail(res, 'POST cportal info', e); }
  });

  // right to work photos
  app.post('/api/cportal/:token/upload', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      if (row.status !== 'accepted') return res.status(409).json({ error: 'Uploads open once the offer has been accepted.' });
      const b = req.body || {};
      const mime = String(b.mime || '').toLowerCase();
      if (!/^(image\/(jpeg|png|heic|heif|webp)|application\/pdf)$/.test(mime)) return res.status(400).json({ error: 'Please use a JPG, PNG or PDF file' });
      const data = Buffer.from(String(b.data || ''), 'base64');
      if (data.length < 200) return res.status(400).json({ error: 'That file looks empty' });
      if (data.length > 5 * 1024 * 1024) return res.status(400).json({ error: 'That file is over 5 MB. Please choose a smaller photo or scan.' });
      const n = Number((await pool.query('select count(*)::int as n from offer_portal_files where offer_id = $1', [row.id])).rows[0].n);
      if (n >= 4) return res.status(400).json({ error: 'You can add up to 4 files' });
      const name = clean(b.name, 120).replace(/[\\/:*?"<>|]/g, '') || 'document';
      const ins = await pool.query('insert into offer_portal_files (offer_id, filename, mime, data) values ($1,$2,$3,$4) returning id', [row.id, name, mime, data]);
      await addEvent(pool, row.id, `Right to work file added: ${name}`, req);
      res.json({ ok: true, n: ins.rows[0].id, name, size: data.length });
    } catch (e) { fail(res, 'POST cportal upload', e); }
  });
  app.post('/api/cportal/:token/upload/:n/delete', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      if (row.info_status === 'submitted') return res.status(409).json({ error: 'Your details have been submitted. Please call us if you need to change a file.' });
      await pool.query('delete from offer_portal_files where id = $1 and offer_id = $2', [parseInt(req.params.n, 10) || 0, row.id]);
      res.json({ ok: true });
    } catch (e) { fail(res, 'POST cportal upload delete', e); }
  });

  app.post('/api/cportal/:token/prestart', async (req, res) => {
    try {
      const got = await byToken(req, res); if (!got) return;
      const { pool, row } = got;
      if (row.prestart_status === 'none') return res.status(409).json({ error: 'Your start details have not been sent yet.' });
      if ((req.body || {}).agree !== true) return res.status(400).json({ error: 'Please tick the box to confirm' });
      if (row.prestart_status === 'confirmed') return res.json({ ok: true, already: true });
      const upd = await pool.query("update offer_portal set prestart_status = 'confirmed', prestart_confirmed_at = now(), updated_at = now() where id = $1 returning *", [row.id]);
      await addEvent(pool, row.id, 'Start details confirmed', req);
      try { await d.onPrestart(upd.rows[0]); } catch (e) { console.error('prestart hook failed:', e.message); }
      res.json({ ok: true });
    } catch (e) { fail(res, 'POST cportal prestart', e); }
  });

  // the client's one tap "received" on the handover pack email
  app.get('/api/cportal/c/:token', async (req, res) => {
    try {
      const got = await byToken(req, res, 'client_token_hash'); if (!got) return;
      const { row } = got;
      res.json({ company: row.company, candidate: row.candidate_name, role: (row.vals || {}).job_title || row.role, start: (row.vals || {}).start_date_long || '', confirmed_at: row.client_confirmed_at });
    } catch (e) { fail(res, 'GET cportal client', e); }
  });
  app.post('/api/cportal/c/:token/confirm', async (req, res) => {
    try {
      const got = await byToken(req, res, 'client_token_hash'); if (!got) return;
      const { pool, row } = got;
      if (row.client_confirmed_at) return res.json({ ok: true, already: true });
      const upd = await pool.query('update offer_portal set client_confirmed_at = now(), updated_at = now() where id = $1 returning *', [row.id]);
      await addEvent(pool, row.id, 'Client confirmed the handover pack was received', req);
      try { await d.onClientConfirmed(upd.rows[0]); } catch (e) { console.error('client confirm hook failed:', e.message); }
      res.json({ ok: true });
    } catch (e) { fail(res, 'POST cportal client confirm', e); }
  });

  /* ----- staff side (signed in) ----- */
  app.get('/api/offer-portal/status', async (req, res) => {
    try {
      const key = String(req.query.key || '');
      if (!key) return res.status(400).json({ error: 'key is required' });
      res.json(await statusFor(d.pool(), key));
    } catch (e) { fail(res, 'GET offer-portal status', e); }
  });
  app.get('/api/offer-portal/pdf', async (req, res) => {
    try {
      const pool = d.pool(); await ensureSchema(pool);
      const r = (await pool.query('select company, candidate_name, pdf from offer_portal where id = $1', [String(req.query.key || '')])).rows[0];
      if (!r || !r.pdf) return res.status(404).json({ error: 'There is no signed offer letter yet' });
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${`Offer letter ${r.candidate_name} signed.pdf`.replace(/[\\/:*?"<>|]/g, '')}"`);
      res.send(r.pdf);
    } catch (e) { fail(res, 'GET offer-portal pdf', e); }
  });
  app.get('/api/offer-portal/file/:n', async (req, res) => {
    try {
      const pool = d.pool(); await ensureSchema(pool);
      const f = (await pool.query('select * from offer_portal_files where id = $1', [parseInt(req.params.n, 10) || 0])).rows[0];
      if (!f) return res.status(404).json({ error: 'File not found' });
      res.setHeader('Content-Type', f.mime);
      res.setHeader('Content-Disposition', `attachment; filename="${f.filename.replace(/"/g, '')}"`);
      res.send(f.data);
    } catch (e) { fail(res, 'GET offer-portal file', e); }
  });
}

/* ---------- reminders (the daily job) ---------- */
export async function runReminders(d, pool) {
  await ensureSchema(pool);
  const done = { offer: 0, info: 0, prestart: 0 };
  const rows = (await pool.query(
    `select * from offer_portal where preview = false and (
       (status in ('sent','viewed') and sent_at is not null) or
       (status = 'accepted' and info_status = 'requested' and info_requested_at is not null) or
       (status = 'accepted' and prestart_status = 'sent' and prestart_sent_at is not null))`)).rows;
  for (const r of rows) {
    const rem = r.reminders || {};
    const days = t => (Date.now() - Date.parse(t)) / 86400000;
    const set = async (k) => { rem[k] = new Date().toISOString(); await pool.query('update offer_portal set reminders = $2::jsonb where id = $1', [r.id, JSON.stringify(rem)]); };
    try {
      if (['sent', 'viewed'].includes(r.status) && r.sent_at) {
        const a = days(r.sent_at);
        if (a >= 2 && !rem.offer1) { await d.remind(r, 'offer1'); await set('offer1'); done.offer++; }
        else if (a >= 5 && !rem.offer2) { await d.remind(r, 'offer2'); await set('offer2'); done.offer++; }
      } else if (r.status === 'accepted' && r.info_status === 'requested' && r.info_requested_at) {
        const a = days(r.info_requested_at);
        if (a >= 2 && !rem.info1) { await d.remind(r, 'info1'); await set('info1'); done.info++; }
        else if (a >= 5 && !rem.info2) { await d.remind(r, 'info2'); await set('info2'); done.info++; }
      } else if (r.status === 'accepted' && r.prestart_status === 'sent' && r.prestart_sent_at) {
        const a = days(r.prestart_sent_at);
        if (a >= 3 && !rem.pre1) { await d.remind(r, 'pre1'); await set('pre1'); done.prestart++; }
      }
    } catch (e) { console.error(`offer reminder failed for ${r.id}:`, e.message); }
  }
  return done;
}
