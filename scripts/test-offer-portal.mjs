// Build 72 tests: the candidate offer portal (offer-portal.js) against a local Postgres.
//   TEST_DATABASE_URL=postgres://localhost:55432/postgres node scripts/test-offer-portal.mjs
import assert from 'node:assert/strict';
import express from 'express';
import crypto from 'crypto';
import pg from 'pg';
import PDFDocument from 'pdfkit';
import * as onbDocs from '../onboarding-docs.js';
import * as op from '../offer-portal.js';

const url = process.env.TEST_DATABASE_URL;
if (!url) { console.log('offer portal tests skipped: set TEST_DATABASE_URL'); process.exit(0); }
const pool = new pg.Pool({ connectionString: url });
await pool.query('drop table if exists offer_portal, offer_portal_files');
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };

const calls = [];
const key = crypto.randomBytes(32);
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); const e = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), e].map(b => b.toString('base64url')).join('.'); };
const dec = s => { try { const [iv, tag, e] = s.split('.').map(x => Buffer.from(x, 'base64url')); const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag); return Buffer.concat([d.update(e), d.final()]).toString('utf8'); } catch (e) { return null; } };
const deps = {
  pool: () => pool, encrypt: enc, decrypt: dec,
  urlFor: (t) => `https://x/offer/#t=${t}`, clientUrlFor: (t) => `https://x/offer/#c=${t}`,
  parseDoc: onbDocs.parseDoc, docToHtml: onbDocs.docToHtml, docHash: onbDocs.docHash,
  buildPdf: ({ meta, blocks, sign }) => onbDocs.buildDocPdf({ PDFDocument, logo: null, meta, blocks, sign }),
  pngFromDataUrl: v => { const m = String(v || '').match(/^data:image\/png;base64,([A-Za-z0-9+/=]+)$/); return m ? Buffer.from(m[1], 'base64') : null; },
  onAccepted: async (rec, pdf) => { calls.push(['accepted', rec.candidate_name, pdf.length]); return 'Moved to Start Date'; },
  onDeclined: async rec => { calls.push(['declined', rec.candidate_name, rec.decline_reason]); },
  onInfo: async (rec, a) => { calls.push(['info', a.legal_name]); },
  onPrestart: async rec => { calls.push(['prestart', rec.candidate_name]); },
  onReview: async rec => { calls.push(['review', rec.review_rating]); },
  onClientConfirmed: async rec => { calls.push(['client', rec.company]); },
  remind: async (rec, kind) => { calls.push(['remind', kind]); },
};
const app = express(); app.use(express.json({ limit: '15mb' })); op.mountOfferPortal(app, deps);
const srv = app.listen(0); const base = `http://127.0.0.1:${srv.address().port}`;
const call = async (path, body) => { const r = await fetch(base + path, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { s: r.status, j: await r.json().catch(() => ({})), r }; };
const tokOf = u => u.split('#t=')[1];

const vals = { candidate_name: 'Thomas Brown', candidate_first: 'Thomas', company: 'Acme Ltd', job_title: 'Warehouse Operative', salary: '£13.24 per hour (£25,818 a year)', start_date_long: '', reporting_to: '', work_location: 'Telford', employment_type: 'Full time', today: '24 November 2026', offer_reply_by: '25 November 2026', sender_name: 'Ella Pietrzak', sender_title: 'Recruitment Coordinator' };

// letter text
const src = op.offerLetterSource(vals);
ok(/Start Date \| To be confirmed/.test(src), 'start date to be confirmed');
ok(!/Reporting To/.test(src), 'no Reporting To when unknown');
ok(!/per annum/.test(src), 'no per annum for hourly');
ok(/£13\.24 per hour/.test(src), 'hourly rate shown');
ok(op.offerLetterSource({ ...vals, salary: '£30,000', reporting_to: 'Sam Lee, Manager', start_date_long: '1 December 2026' }).match(/£30,000 per annum[\s\S]*Reporting To \| Sam Lee/), 'annual and reporting shown');

// issue + read
const a = await op.issue(deps, pool, { id: 'acme|thomas|wo', candidate: { name: 'Thomas Brown', email: 'Tom@Example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: vals, kind: 'offer', by: 'ella' });
ok(a.url.includes('#t='), 'link made');
const T = tokOf(a.url);
let r = await call('/api/cportal/' + T);
ok(r.s === 200 && r.j.first === 'Thomas' && r.j.status === 'viewed' || r.j.status === 'sent', 'state read');
ok(r.j.info.locked === true, 'info locked before acceptance');
r = await call('/api/cportal/' + 'x'.repeat(40)); ok(r.s === 404, 'bad token 404');
r = await call('/api/cportal/' + T + '/doc'); ok(r.s === 200 && /Offer Details/i.test(r.j.html) && r.j.hash, 'letter html');
const hash = r.j.hash;
r = await fetch(base + '/api/cportal/' + T + '/pdf'); ok(r.status === 200 && (await r.arrayBuffer()).byteLength > 1500, 'draft pdf');
// info locked, upload locked
r = await call('/api/cportal/' + T + '/info', { answers: {}, submit: false }); ok(r.s === 409, 'info refused before acceptance');
// sign failures
r = await call('/api/cportal/' + T + '/sign', { method: 'typed', typed: 'Thomas Brown', hash }); ok(r.s === 400, 'must tick agree');
r = await call('/api/cportal/' + T + '/sign', { method: 'typed', typed: 'Someone Else', agree: true, hash }); ok(r.s === 400, 'name must match');
r = await call('/api/cportal/' + T + '/sign', { method: 'typed', typed: 'Thomas Brown', agree: true, hash: 'bad' }); ok(r.s === 409 && r.j.code === 'CHANGED', 'hash mismatch');
r = await call('/api/cportal/' + T + '/sign', { method: 'typed', typed: 'thomas  brown', agree: true, hash }); ok(r.s === 200 && r.j.ok, 'signed');
ok(calls.some(c => c[0] === 'accepted' && c[2] > 1500), 'accept hook with pdf');
r = await call('/api/cportal/' + T + '/sign', { method: 'typed', typed: 'Thomas Brown', agree: true, hash }); ok(r.s === 409 && r.j.code === 'ALREADY_SIGNED', 'no double sign');
r = await call('/api/cportal/' + T + '/decline', { reason: 'x' }); ok(r.s === 409, 'cannot decline after accepting');
r = await fetch(base + '/api/cportal/' + T + '/pdf'); const pdfBuf = Buffer.from(await r.arrayBuffer()); ok(pdfBuf.subarray(0, 4).toString() === '%PDF', 'signed pdf');
let st = await op.statusFor(pool, 'acme|thomas|wo'); ok(st.status === 'accepted' && st.signed_at && st.has_pdf, 'staff status accepted');

// info form
r = await call('/api/cportal/' + T + '/info', { answers: { legal_name: 'Thomas Brown', email: 'bad' }, submit: false }); ok(r.s === 400, 'bad email rejected');
r = await call('/api/cportal/' + T + '/info', { answers: { legal_name: 'Thomas Brown' }, submit: true }); ok(r.s === 400 && /Please fill in/.test(r.j.error), 'required fields on submit');
r = await call('/api/cportal/' + T + '/info', { answers: { legal_name: 'Thomas Brown', address1: '1 High St' }, submit: false }); ok(r.s === 200 && r.j.status === 'started', 'draft saved');
r = await call('/api/cportal/' + T); ok(r.j.info.answers.address1 === '1 High St', 'draft comes back');
r = await call('/api/cportal/' + T + '/upload', { name: 'passport.jpg', mime: 'image/jpeg', data: Buffer.alloc(3000, 1).toString('base64') }); ok(r.s === 200 && r.j.n, 'file uploaded');
const fileN = r.j.n;
r = await call('/api/cportal/' + T + '/upload', { name: 'x.exe', mime: 'application/x-msdownload', data: Buffer.alloc(3000, 1).toString('base64') }); ok(r.s === 400, 'bad file type refused');
r = await call('/api/cportal/' + T + '/upload', { name: 'big.pdf', mime: 'application/pdf', data: Buffer.alloc(6 * 1024 * 1024, 1).toString('base64') }); ok(r.s === 400, 'big file refused');
const full = { legal_name: 'Thomas Brown', address1: '1 High St', town: 'Telford', postcode: 'TF1 1AA', email: 'tom@example.com', mobile: '07700900000', dob: '1990-05-04', em_name: 'Ann Brown', em_relationship: 'Mother', em_phone: '07700900001',
  rtw_type: op.RTW_OPTIONS[0], ref1_name: 'A One', ref1_company: 'Co', ref1_email: 'a@co.com', ref2_name: 'B Two', ref2_company: 'Co2', ref2_email: 'b@co.com', start_ok: 'Yes, the start date works for me' };
r = await call('/api/cportal/' + T + '/info', { answers: { ...full, dob: '2015-01-01' }, submit: true }); ok(r.s === 400, 'dob sanity');
r = await call('/api/cportal/' + T + '/info', { answers: full, submit: true }); ok(r.s === 200 && r.j.status === 'submitted', 'info submitted');
ok(calls.some(c => c[0] === 'info' && c[1] === 'Thomas Brown'), 'info hook');
st = await op.statusFor(pool, 'acme|thomas|wo'); ok(st.info_status === 'submitted' && st.files.length === 1, 'staff sees info and file');

// pre-start
r = await call('/api/cportal/' + T + '/prestart', { agree: true }); ok(r.s === 409, 'prestart not sent yet');
const p = await op.issue(deps, pool, { id: 'acme|thomas|wo', candidate: { name: 'Thomas Brown', email: 'tom@example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: { ...vals, start_date_long: '1 December 2026', start_time: '8:00am', parking: 'On site' }, kind: 'prestart', by: 'ella' });
ok(tokOf(p.url) === T, 'same link kept for the whole journey');
await op.markSent(pool, 'acme|thomas|wo', 'prestart');
r = await call('/api/cportal/' + T); ok(r.j.prestart && r.j.prestart.details.some(d => d[0] === 'Start date' && d[1] === '1 December 2026'), 'prestart details shown');
r = await call('/api/cportal/' + T + '/prestart', { agree: false }); ok(r.s === 400, 'must tick');
r = await call('/api/cportal/' + T + '/prestart', { agree: true }); ok(r.s === 200, 'prestart confirmed');
ok(calls.some(c => c[0] === 'prestart'), 'prestart hook');

// client confirm
const pl = await op.issue(deps, pool, { id: 'acme|thomas|wo', candidate: { name: 'Thomas Brown', email: 'tom@example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: vals, kind: 'placement', by: 'ella' });
ok(pl.clientUrl && pl.clientUrl.includes('#c='), 'client link');
const C = pl.clientUrl.split('#c=')[1];
r = await call('/api/cportal/c/' + C); ok(r.s === 200 && r.j.candidate === 'Thomas Brown', 'client page data');
r = await call('/api/cportal/c/' + C + '/confirm', {}); ok(r.s === 200, 'client confirmed');
ok(calls.some(c => c[0] === 'client'), 'client hook');
r = await call('/api/cportal/c/' + T); ok(r.s === 404, 'candidate link does not open the client page');

// decline path
const b = await op.issue(deps, pool, { id: 'acme|jo|wo', candidate: { name: 'Jo Green', email: 'jo@example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: { ...vals, candidate_name: 'Jo Green', candidate_first: 'Jo' }, kind: 'offer', by: 'ella' });
const T2 = tokOf(b.url);
r = await call('/api/cportal/' + T2 + '/decline', { reason: 'Took another job' }); ok(r.s === 200, 'declined');
ok(calls.some(c => c[0] === 'declined' && c[2] === 'Took another job'), 'decline hook with reason');
r = await call('/api/cportal/' + T2 + '/doc'); const h2 = r.j.hash;
r = await call('/api/cportal/' + T2 + '/sign', { method: 'typed', typed: 'Jo Green', agree: true, hash: h2 }); ok(r.s === 409, 'cannot accept after declining');
// a new offer built after a decline reopens it
await op.issue(deps, pool, { id: 'acme|jo|wo', candidate: { name: 'Jo Green', email: 'jo@example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: { ...vals, candidate_name: 'Jo Green', candidate_first: 'Jo' }, kind: 'offer', by: 'ella' });
st = await op.statusFor(pool, 'acme|jo|wo'); ok(st.status === 'sent', 'offer rebuilt after a decline reopens');

// a candidate accepted by another route gets the form via a manual record
const m = await op.issue(deps, pool, { id: 'acme|old|wo', candidate: { name: 'Old Case', email: 'old@example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: vals, kind: 'info_request', by: 'ella' });
r = await call('/api/cportal/' + tokOf(m.url)); ok(r.s === 200 && r.j.status === 'accepted' && r.j.manual && !r.j.info.locked, 'manual record opens the form');

// client testimonials
const tm = await op.issue(deps, pool, { id: 'acme|thomas|wo', candidate: { name: 'Thomas Brown', email: 'tom@example.com', company: 'Acme Ltd', role: 'Warehouse Operative' }, values: { ...vals, client_contact: 'Sam Lee' }, kind: 'testimonial', by: 'ella' });
ok(tm.clientUrl && tm.clientUrl.includes('#c='), 'testimonial uses the client link');
const TC = tm.clientUrl.split('#c=')[1];
await op.markSent(pool, 'acme|thomas|wo', 'testimonial');
r = await call('/api/cportal/c/' + TC); ok(r.j.review.status === 'requested', 'testimonial requested');
r = await call('/api/cportal/c/' + TC + '/review', { rating: 0 }); ok(r.s === 400, 'rating required');
r = await call('/api/cportal/' + T + '/review', { rating: 5 }); ok(r.s === 404 || r.s === 405 || r.s === 400, 'candidates have no review route here');
r = await call('/api/cportal/c/' + TC + '/review', { rating: 5, text: 'Ella made hiring easy.', name: 'Sam Lee, Operations Manager', publish_ok: true }); ok(r.s === 200, 'testimonial saved');
ok(calls.some(c => c[0] === 'review'), 'review hook');
r = await call('/api/testimonials'); ok(r.s === 200 && r.j.testimonials.length === 0, 'not public until approved');
st = await op.statusFor(pool, 'acme|thomas|wo'); ok(st.review_status === 'submitted' && st.review_rating === 5 && st.review_consent, 'staff sees it');
await pool.query('update offer_portal set preview = false');
r = await call('/api/offer-portal/review/approve', { key: 'acme|thomas|wo' }); ok(r.s === 200, 'approved');
r = await call('/api/testimonials'); ok(r.j.testimonials.length === 1 && r.j.testimonials[0].name === 'Sam Lee, Operations Manager' && r.j.testimonials[0].company === 'Acme Ltd' && !JSON.stringify(r.j).includes('example.com') && !JSON.stringify(r.j).includes('Thomas'), 'public feed shows name and company only');
r = await call('/api/offer-portal/review/approve', { key: 'acme|thomas|wo', approve: false }); r = await call('/api/testimonials'); ok(r.j.testimonials.length === 0, 'taken off the website');
r = await call('/api/offer-portal/review/approve', { key: 'acme|jo|wo' }); ok(r.s === 404, 'nothing to approve');

// reminders
await pool.query("update offer_portal set sent_at = now() - interval '3 days' where id = 'acme|jo|wo'");
await pool.query("update offer_portal set preview = false");
const rem = await op.runReminders(deps, pool); ok(rem.offer >= 1 && calls.some(c => c[0] === 'remind' && c[1] === 'offer1'), 'day 2 reminder');
const rem2 = await op.runReminders(deps, pool); ok(rem2.offer === 0, 'reminder not repeated');

// expiry
await pool.query("update offer_portal set expires_at = now() - interval '1 day' where id = 'acme|jo|wo'");
r = await call('/api/cportal/' + T2); ok(r.s === 410, 'expired link');

srv.close(); await pool.end();
console.log(`offer portal: all ${n} checks passed`);
