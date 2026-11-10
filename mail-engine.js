/* ======================================================================
   Build 57.0: the new email engine

   Runs ALONGSIDE Brevo. Nothing that already sends through Brevo uses this file.
   New features (Gap Briefs, hiring signal alerts, the Hiring Pulse) send through here,
   and existing sends move across one at a time only once these routes have proven themselves.

   Two routes:
   - m365: one-to-one emails from the person's own Microsoft 365 mailbox, through Microsoft Graph
     (normal HTTPS, so Render's blocked mail ports do not matter). Lands in their Sent Items.
     Render settings: MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET (app "Live 2 Help Workspace Mail",
     Mail.Send application permission, admin consent granted). MS_SECRET_EXPIRES (YYYY-MM-DD) optional.
   - ses: bulk emails (Gap Briefs, Hiring Pulse) through Amazon SES on news.live2helprecruitment.co.uk,
     SMTP port 2587 (allowed on Render). Render settings: SES_SMTP_USER, SES_SMTP_PASS,
     SES_REGION (default eu-west-2), BULK_FROM (default news@news.live2helprecruitment.co.uk),
     SES_DAILY_QUOTA (default 200, the sandbox limit; raise after production access).

   Limits (separate from the Brevo 300 a day, which still applies to Brevo sends only):
   - m365: 2,000 external recipients per mailbox per day, 30 per minute (Microsoft's own limits)
   - ses: SES_DAILY_QUOTA recipients per day
   Every send checks the shared suppression list first, so anyone who opted out through Brevo
   is still respected. Preview requests (/dashboard-next) never send.
   ====================================================================== */
import nodemailer from 'nodemailer';

export const MS_SECRET_EXPIRES_DEFAULT = '2028-11-08';
const MS_DAILY = 2000;
const MS_PER_MINUTE = 30;
const MS_MAX_BYTES = 3 * 1024 * 1024; // Graph sendMail takes up to about 3MB of attachments in one request

export const ENGINE_LOG_HEADER = ['id', 'at', 'day', 'route', 'user', 'from', 'to', 'cc', 'subject', 'kind', 'recipients', 'message_id', 'status', 'error', 'ref'];

const isEmail = x => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(x || '').trim());
const addrs = v => String(Array.isArray(v) ? v.join(',') : (v || '')).split(/[,;\s]+/).map(x => x.trim()).filter(isEmail);
const clean = (s, n) => String(s || '').replace(/[\r\n]+/g, ' ').trim().slice(0, n);
const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function msSecretExpires() {
  const v = String(process.env.MS_SECRET_EXPIRES || MS_SECRET_EXPIRES_DEFAULT).trim();
  return /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : MS_SECRET_EXPIRES_DEFAULT;
}
export function msSecretDaysLeft(now = new Date()) {
  return Math.floor((new Date(msSecretExpires() + 'T00:00:00Z') - now) / 86400000);
}

export function createMailEngine({ fetch, isPreview, logTable, isSuppressed, today, unsubUrl }) {
  const unsubMailto = () => String(process.env.UNSUB_MAILTO || 'info@live2helprecruitment.co.uk').trim();
  /* ---------- Microsoft 365 (Graph) ---------- */
  const msConfigured = () => !!(process.env.MS_TENANT_ID && process.env.MS_CLIENT_ID && process.env.MS_CLIENT_SECRET);
  let msTok = { value: '', exp: 0 };

  async function msToken() {
    if (msTok.value && Date.now() < msTok.exp - 60000) return msTok.value;
    const body = new URLSearchParams({
      client_id: process.env.MS_CLIENT_ID,
      client_secret: process.env.MS_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    });
    const r = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(process.env.MS_TENANT_ID)}/oauth2/v2.0/token`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) {
      const code = String(j.error_codes && j.error_codes[0] || j.error || r.status);
      const hint = /7000215|invalid_client/.test(code + ' ' + (j.error_description || '')) ? ' The client secret looks wrong or expired: check MS_CLIENT_SECRET on Render is the secret VALUE, not the Secret ID.'
        : /90002|700016|AADSTS90002|AADSTS700016/.test(code + ' ' + (j.error_description || '')) ? ' The tenant or client ID looks wrong: check MS_TENANT_ID and MS_CLIENT_ID on Render.'
        : '';
      throw new Error(`Microsoft sign-in failed (${code}).${hint}`);
    }
    msTok = { value: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
    return msTok.value;
  }

  async function msSend(m) {
    const token = await msToken();
    const rcp = list => list.map(a => ({ emailAddress: { address: a } }));
    const message = {
      subject: m.subject,
      body: { contentType: m.html ? 'HTML' : 'Text', content: m.html || m.text || '' },
      toRecipients: rcp(m.to),
    };
    if (m.cc.length) message.ccRecipients = rcp(m.cc);
    if (m.bcc.length) message.bccRecipients = rcp(m.bcc);
    if (m.replyTo) message.replyTo = rcp([m.replyTo]);
    const hdrs = Object.entries(m.headers || {}).filter(([k]) => /^x-/i.test(k)).map(([name, value]) => ({ name, value: String(value).slice(0, 900) }));
    if (hdrs.length) message.internetMessageHeaders = hdrs;
    if (m.attachments.length) {
      message.attachments = m.attachments.map(a => ({
        '@odata.type': '#microsoft.graph.fileAttachment',
        name: a.filename, contentType: a.contentType || 'application/octet-stream', contentBytes: a.content,
        ...(a.cid ? { isInline: true, contentId: a.cid } : {}),
      }));
    }
    const r = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(m.from)}/sendMail`, {
      method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, saveToSentItems: true }),
    });
    if (r.status === 202 || r.ok) return { messageId: '' };
    const j = await r.json().catch(() => ({}));
    const code = (j.error && j.error.code) || String(r.status);
    const msg = (j.error && j.error.message) || '';
    let hint = '';
    if (r.status === 403 || /AccessDenied|Authorization_RequestDenied/i.test(code)) hint = ' Microsoft refused permission: check Mail.Send (Application) shows "Granted" in Entra, API permissions.';
    else if (r.status === 404 || /ResourceNotFound|MailboxNotEnabled|ErrorInvalidUser/i.test(code)) hint = ` ${m.from} was not found as a mailbox in the Live 2 Help Microsoft 365 account.`;
    else if (r.status === 429) hint = ' Microsoft is rate limiting this mailbox. Wait a minute and try again.';
    throw new Error(`Microsoft 365 did not send it (${code}${msg ? ': ' + msg.slice(0, 200) : ''}).${hint}`);
  }

  /* ---------- Amazon SES (SMTP on 2587) ---------- */
  const sesRegion = () => String(process.env.SES_REGION || 'eu-west-2').trim();
  const bulkFrom = () => String(process.env.BULK_FROM || 'news@news.live2helprecruitment.co.uk').trim();
  const sesQuota = () => Math.max(1, parseInt(process.env.SES_DAILY_QUOTA || '200', 10) || 200);
  const sesConfigured = () => !!(process.env.SES_SMTP_USER && process.env.SES_SMTP_PASS);
  let sesT = null, sesKey = '';

  function sesTransport() {
    const key = [sesRegion(), process.env.SES_SMTP_USER].join('|');
    if (!sesT || sesKey !== key) {
      sesT = nodemailer.createTransport({
        host: `email-smtp.${sesRegion()}.amazonaws.com`, port: 2587, secure: false, requireTLS: true,
        connectionTimeout: 20000, greetingTimeout: 15000,
        auth: { user: process.env.SES_SMTP_USER, pass: process.env.SES_SMTP_PASS },
      });
      sesKey = key;
    }
    return sesT;
  }

  async function sesSend(m) {
    const info = await sesTransport().sendMail({
      from: `"${String(m.fromName || 'Live 2 Help Recruitment').replace(/["<>]/g, '')}" <${m.from}>`,
      replyTo: m.replyTo || undefined,
      to: m.to, cc: m.cc.length ? m.cc : undefined, bcc: m.bcc.length ? m.bcc : undefined,
      subject: m.subject, html: m.html || undefined, text: m.text || undefined,
      attachments: m.attachments.map(a => ({ filename: a.filename, content: a.content, encoding: 'base64', contentType: a.contentType, cid: a.cid })),
      headers: m.headers || {},
    });
    // SES puts its own message ID in the SMTP reply ("250 Ok <id>"); that is what its events report later
    const sesId = (String(info && info.response || '').match(/Ok\s+(\S+)/i) || [])[1] || '';
    return { messageId: sesId || String(info && info.messageId || '').replace(/[<>]/g, '') };
  }

  /* ---------- Limits ---------- */
  async function sentRows() {
    const day = today();
    return (await logTable.list().catch(() => [])).filter(o => o.day === day && o.status === 'sent');
  }
  async function usage(route, from) {
    const rows = (await sentRows()).filter(o => o.route === route && (!from || String(o.from).toLowerCase() === String(from).toLowerCase()));
    const n = rows.reduce((s, o) => s + (Number(o.recipients) || 1), 0);
    const since = Date.now() - 60000;
    const minute = rows.filter(o => Date.parse(o.at) >= since).reduce((s, o) => s + (Number(o.recipients) || 1), 0);
    return { today: n, minute };
  }

  /* ---------- Send ---------- */
  async function send(o) {
    const route = o.route === 'ses' ? 'ses' : 'm365';
    const m = {
      from: String(o.from || (route === 'ses' ? bulkFrom() : '')).trim().toLowerCase(),
      fromName: clean(o.fromName, 120),
      to: addrs(o.to), cc: addrs(o.cc), bcc: addrs(o.bcc),
      replyTo: isEmail(o.replyTo) ? String(o.replyTo).trim() : '',
      subject: clean(o.subject, 250),
      html: String(o.html || ''), text: String(o.text || ''),
      headers: { 'X-L2H-Kind': clean(o.kind || 'email', 40), 'X-L2H-Engine': '57', ...(o.headers || {}) },
      attachments: (Array.isArray(o.attachments) ? o.attachments : []).filter(a => a && a.content).map(a => ({
        filename: String(a.filename || 'attachment').replace(/[\r\n"]/g, ''), content: a.content, contentType: a.contentType || 'application/octet-stream', cid: a.cid || '',
      })),
    };
    if (!isEmail(m.from)) throw new Error('No valid sender address');
    if (!m.to.length) throw new Error('Add a valid email address to send to');
    if (!m.subject) throw new Error('Add a subject');
    if (!m.html && !m.text) throw new Error('The email is empty');
    if (!m.html) m.html = '<html><body>' + m.text.split(/\n{2,}/).map(p => `<p style="margin:0 0 12px 0;font-family:Calibri,'Segoe UI',Arial,sans-serif;font-size:11pt;color:#222;">${esc(p).replace(/\n/g, '<br>')}</p>`).join('') + '</body></html>';
    const recipients = m.to.length + m.cc.length + m.bcc.length;
    const bytes = m.attachments.reduce((s, a) => s + String(a.content).length * 0.75, 0);

    // Build 57.1 (commitment to AWS): every bulk email carries a personal one-click unsubscribe.
    // That means one email per recipient, with List-Unsubscribe and List-Unsubscribe-Post on it.
    if (route === 'ses') {
      if (recipients !== 1) throw new Error('Bulk emails through Amazon SES go out one per recipient, so each has its own unsubscribe link.');
      const url = o.unsubscribeUrl || (unsubUrl ? unsubUrl(m.to[0]) : '');
      if (!/^https:\/\//i.test(url)) throw new Error('This bulk email has no unsubscribe link, so it was not sent.');
      m.headers['List-Unsubscribe'] = `<${url}>, <mailto:${unsubMailto()}?subject=Unsubscribe>`;
      m.headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
    }

    if (isPreview()) return { ok: true, preview: true, route, messageId: 'preview-not-sent' };

    if (route === 'm365' && !msConfigured()) throw new Error('Microsoft 365 is not set up on the server yet (MS_TENANT_ID, MS_CLIENT_ID and MS_CLIENT_SECRET on Render).');
    if (route === 'ses' && !sesConfigured()) throw new Error('Amazon SES is not set up on the server yet (SES_SMTP_USER and SES_SMTP_PASS on Render).');
    if (route === 'm365' && bytes > MS_MAX_BYTES) throw new Error('Attachments are too large for this route (3MB at most for now).');

    if (!o.skipSuppression) {
      const sup = await isSuppressed([...m.to, ...m.cc], o.meta && o.meta.company);
      if (sup) throw Object.assign(new Error(`${sup} has opted out of emails from us, so this cannot be sent.`), { status: 409 });
    }

    const u = await usage(route, route === 'm365' ? m.from : '');
    if (route === 'm365') {
      if (u.today + recipients > MS_DAILY) throw Object.assign(new Error(`${m.from} has reached Microsoft's limit of ${MS_DAILY} recipients today. It resets at midnight.`), { status: 429 });
      if (u.minute + recipients > MS_PER_MINUTE) throw Object.assign(new Error(`Microsoft allows ${MS_PER_MINUTE} recipients a minute per mailbox. Wait a minute and try again.`), { status: 429 });
    } else if (u.today + recipients > sesQuota()) {
      throw Object.assign(new Error(`Today's Amazon SES limit of ${sesQuota()} has been reached. It resets at midnight (raise SES_DAILY_QUOTA on Render after production access).`), { status: 429 });
    }

    const now = new Date().toISOString();
    const row = {
      id: 'en-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), at: now, day: today(), route,
      user: clean(o.user || 'system', 40), from: m.from, to: m.to.join(', '), cc: m.cc.join(', '), subject: m.subject,
      kind: clean(o.kind || 'email', 40), recipients: String(recipients), message_id: '', status: 'sent', error: '',
      ref: clean(o.meta && o.meta.ref, 120),
    };
    try {
      const r = route === 'ses' ? await sesSend(m) : await msSend(m);
      row.message_id = r.messageId || '';
    } catch (e) {
      row.status = 'failed'; row.error = clean(e.message, 400);
      await logTable.append(row).catch(() => {});
      throw e;
    }
    await logTable.append(row).catch(err => console.error('Engine log failed:', err.message));
    return { ok: true, route, id: row.id, messageId: row.message_id, recipients };
  }

  /* ---------- Status for the test panel ---------- */
  async function status() {
    const rows = await sentRows();
    const sum = f => rows.filter(f).reduce((s, o) => s + (Number(o.recipients) || 1), 0);
    return {
      m365: {
        configured: msConfigured(), secretExpires: msSecretExpires(), secretDaysLeft: msSecretDaysLeft(),
        dailyLimit: MS_DAILY, perMinute: MS_PER_MINUTE, today: sum(o => o.route === 'm365'),
      },
      ses: {
        configured: sesConfigured(), region: sesRegion(), from: bulkFrom(),
        dailyLimit: sesQuota(), today: sum(o => o.route === 'ses'),
      },
    };
  }

  return { send, status, msConfigured, sesConfigured, bulkFrom };
}
