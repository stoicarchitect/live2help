// Owner-only email rule (build 73.1).
// Any email whose recipients are only Daniel Brown (his own address or the reminder inbox) is always sent from Daniel's own mailbox.
// It then lands in Daniel's Sent Items and never in Ella's (or office@), so payroll, bank, report and alert mail stays private.
// Pure functions, no network, so the rule can be tested on its own.

export function addrOf(v) {
  const s = String(v || '').trim();
  const m = s.match(/<([^>]+)>\s*$/);
  return (m ? m[1] : s).trim().toLowerCase();
}

export function recipientsOf(o) {
  const out = [];
  for (const k of ['to', 'cc', 'bcc']) {
    const v = o && o[k];
    if (!v) continue;
    const arr = Array.isArray(v) ? v : String(v).split(',');
    for (const a of arr) {
      const e = addrOf(typeof a === 'string' ? a : (a && a.address) || '');
      if (e) out.push(e);
    }
  }
  return out;
}

// danEmail: Daniel's own mailbox. inboxEmail: where owner alerts are delivered (REMINDER_EMAIL_TO, may equal danEmail).
export function isOwnerOnly(o, danEmail, inboxEmail) {
  const owners = new Set([addrOf(danEmail), addrOf(inboxEmail)].filter(Boolean));
  const rcpts = recipientsOf(o);
  return rcpts.length > 0 && owners.size > 0 && rcpts.every(r => owners.has(r));
}

// Returns a copy of the mail options with From forced to Daniel's mailbox when the mail is owner only. Otherwise returns the options unchanged.
export function forceOwnerSender(o, { danEmail, danName, inboxEmail }) {
  if (!o || !danEmail || !isOwnerOnly(o, danEmail, inboxEmail)) return o;
  const name = String(danName || 'Live 2 Help Workspace').replace(/["<>]/g, '');
  return { ...o, from: `"${name}" <${danEmail}>` };
}
