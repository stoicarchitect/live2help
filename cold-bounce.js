/* Build 57.4: reading bounce notices and replies in a sender's inbox.
   Pure functions only (no network, no database) so they can be tested on their own. */

const NDR_FROM = /(postmaster|mailer-daemon|microsoftexchange[0-9a-f]*|mail delivery (sub)?system)/i;
const NDR_SUBJECT = /(undeliverable|delivery status notification|delivery has failed|mail delivery failed|returned mail|failure notice|delivery failure|message not delivered|could not be delivered|couldn'?t be delivered|not delivered)/i;
const AUTO_SUBJECT = /^\s*(automatic reply|auto[- ]?reply|autoreply|out of office|ooo\b|away from (the )?office|on annual leave)/i;
const AUTO_BODY = /(i am (currently )?(out of (the )?office|away from (my|the) (desk|office))|i('m| am) on (annual )?leave|this is an automated (reply|response)|automatic reply)/i;
const EMAIL_RE = /[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export const lc = s => String(s || '').trim().toLowerCase();

// Is this message a bounce notice (a non-delivery report) rather than a person's reply?
export function looksLikeNdr(from, subject) {
  return NDR_FROM.test(String(from || '')) || NDR_SUBJECT.test(String(subject || ''));
}
export function isAutoReply(subject, body) {
  return AUTO_SUBJECT.test(String(subject || '')) || AUTO_BODY.test(String(body || '').slice(0, 600));
}

// The address that failed: the first address in the notice that we actually sent a cold email to (never the sender's own mailbox)
export function failedRecipient(body, knownRecipients, ownMailbox) {
  const known = knownRecipients instanceof Set ? knownRecipients : new Set((knownRecipients || []).map(lc));
  const own = lc(ownMailbox);
  const text = String(body || '');
  // the structured line first: "Final-Recipient: rfc822; name@x.com" or "Original-Recipient"
  const fin = /(?:final|original)-recipient:\s*rfc822;\s*([^\s<>;]+@[^\s<>;]+)/i.exec(text);
  if (fin && known.has(lc(fin[1])) && lc(fin[1]) !== own) return lc(fin[1]);
  const found = (text.match(EMAIL_RE) || []).map(lc);
  return found.find(e => e !== own && known.has(e)) || '';
}

// kind: 'hard' (address is dead), 'soft' (temporary), 'policy' (their server refused us, address may be fine), 'unknown'
export function classifyBounce(subject, body) {
  const t = `${subject || ''}\n${body || ''}`;
  const codes = (t.match(/\b([45])\.(\d{1,3})\.(\d{1,3})\b/g) || []);
  const code = codes[0] || '';
  const has = re => re.test(t);
  // their server refused us on policy or reputation: do NOT treat the address as dead
  if (/\b5\.7\.\d{1,3}\b/.test(t) || has(/(blocked|blacklist|blocklist|spam|reputation|poor sender|sender (is )?not (allowed|authori[sz]ed)|not authori[sz]ed|policy (violation|reasons?)|relay(ing)? denied|dmarc|spf|content rejected|access denied|rejected by (the )?(recipient|policy))/i)
      && !/(does not exist|user unknown|no such user|not found)/i.test(t)) {
    return { kind: 'policy', code, reason: reasonFor(t, code, 'Rejected by their mail server (policy or spam filter)') };
  }
  if (has(/\b5\.1\.(0|1|2|3|6|10)\b/) || has(/\b5\.4\.(1|4)\b/) ||
      has(/(address (couldn'?t|could not|was not|wasn'?t|cannot|can'?t) be found|recipient (address )?(rejected|not found|unknown)|user unknown|unknown user|no such (user|recipient|mailbox)|does not exist|doesn'?t exist|mailbox (is )?(disabled|unavailable|not found|does not exist)|account (is )?(disabled|inactive|has been disabled)|invalid (recipient|address|mailbox)|recipientnotfound|domain (not found|does not exist|name not found)|host or domain name not found|no mx record|nxdomain)/i)) {
    return { kind: 'hard', code, reason: reasonFor(t, code, 'Address not found') };
  }
  if (has(/\b4\.\d{1,3}\.\d{1,3}\b/) || has(/\b5\.2\.[12]\b/) ||
      has(/(mailbox (is )?full|over (the )?quota|quota exceeded|temporar(y|ily)|try again later|greylist|too many (connections|messages)|server (is )?busy|deferred)/i)) {
    return { kind: 'soft', code, reason: reasonFor(t, code, 'Temporary delivery problem') };
  }
  return { kind: 'unknown', code, reason: reasonFor(t, code, 'Delivery failed (reason unclear)') };
}
function reasonFor(t, code, fallback) {
  const c = code ? ` (${code})` : '';
  if (/recipientnotfound|address (couldn'?t|could not|was not|wasn'?t) be found|no such (user|recipient|mailbox)|user unknown|unknown user|does not exist|doesn'?t exist/i.test(t)) return 'address not found' + c;
  if (/(disabled|inactive)/i.test(t) && /(mailbox|account)/i.test(t)) return 'mailbox disabled' + c;
  if (/(domain|host).{0,30}(not found|does not exist)|no mx record|nxdomain/i.test(t)) return 'domain not found' + c;
  if (/mailbox (is )?full|over (the )?quota|quota exceeded/i.test(t)) return 'mailbox full' + c;
  if (/(blocked|blacklist|blocklist|spam|reputation)/i.test(t)) return 'blocked as spam or by reputation' + c;
  return fallback + c;
}

// What a reply says: 'stop' (they want no more emails: honour it), 'reply' (a person answered), or 'auto' (out of office)
export function replyIntent(subject, body) {
  if (isAutoReply(subject, body)) return 'auto';
  // only what the person wrote, not the quoted email under it
  let top = String(body || '').split(/\r?\n\s*(?:from:|on .{5,80} wrote:|-----\s*original message|_{5,}|>)/i)[0] || '';
  top = top.replace(/\s+/g, ' ').trim().slice(0, 300);
  const first = top.split(/[.!?\n]/)[0].replace(/^(hi|hello|dear)\b[^,]*,\s*/i, '').trim();
  const STOP = /^(no|no thanks|no thank you|no thank-you|stop|please stop|unsubscribe|please unsubscribe|remove me|please remove me|remove|opt out|not interested|no,? not interested|no longer interested|please (do not|don'?t) (contact|email) (me|us)|do not (contact|email) (me|us)|don'?t (contact|email) (me|us))$/i;
  // a short reply that asks to be taken off the list ("Please remove me from your list") also counts; a long email that happens to contain these words does not
  const STOP_PHRASE = /\b(unsubscribe|remove me|take me off|stop (emailing|contacting|sending)|(do not|don'?t) (contact|email)|opt me out|opt out)\b/i;
  if (STOP.test(first) || STOP.test(top.replace(/[.!?]+$/, '')) || (top.length <= 200 && STOP_PHRASE.test(top))) return 'stop';
  return 'reply';
}
