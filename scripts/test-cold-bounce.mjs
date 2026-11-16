import assert from 'node:assert/strict';
import { looksLikeNdr, failedRecipient, classifyBounce, replyIntent, isAutoReply } from '../cold-bounce.js';

const known = new Set(['jane@acme-eng.co.uk', 'bob@widgets.com']);
const own = 'ella@live2helprecruitment.co.uk';

// Microsoft 365 "address not found"
const m365 = `Your message to jane@acme-eng.co.uk couldn't be delivered.\nThe address couldn't be found, or is unable to receive mail.\nRemote Server returned '550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup'\nOriginal sender: ${own}`;
assert.ok(looksLikeNdr('postmaster@live2helprecruitment.co.uk Microsoft Outlook', 'Undeliverable: Welder at Acme'));
assert.equal(failedRecipient(m365, known, own), 'jane@acme-eng.co.uk');
let c = classifyBounce('Undeliverable: Welder at Acme', m365);
assert.equal(c.kind, 'hard'); assert.match(c.reason, /address not found/);

// Gmail style, domain missing
const dom = `Delivery Status Notification (Failure)\nFinal-Recipient: rfc822; bob@widgets.com\nDNS Error: Domain name not found 5.4.4`;
assert.equal(failedRecipient(dom, known, own), 'bob@widgets.com');
assert.equal(classifyBounce('Delivery Status Notification (Failure)', dom).kind, 'hard');

// Mailbox full = soft
assert.equal(classifyBounce('Undeliverable', 'Your message to bob@widgets.com could not be delivered. 552 5.2.2 mailbox full, over quota').kind, 'soft');
// Temporary 4.x = soft
assert.equal(classifyBounce('Delivery delayed', '451 4.7.1 try again later greylisted').kind, 'soft');
// Policy block must NOT be hard
c = classifyBounce('Undeliverable', 'Remote server returned 550 5.7.1 Message rejected as spam by Content Filtering; sender blocked, poor reputation');
assert.equal(c.kind, 'policy');
c = classifyBounce('Undeliverable', '550 5.7.509 Access denied, sending domain does not pass DMARC verification');
assert.equal(c.kind, 'policy');
// Unclear = unknown (left for a human)
assert.equal(classifyBounce('Undeliverable', 'Something odd happened').kind, 'unknown');
// Never picks our own mailbox or an unknown address
assert.equal(failedRecipient(`From ${own} to stranger@other.com failed`, known, own), '');

// Replies
assert.equal(replyIntent('Re: Welder at Acme', 'No\n\nOn Mon, 16 Nov 2026 Ella wrote:\n> Hi Jane'), 'stop');
assert.equal(replyIntent('Re: x', 'No thanks.\n\nFrom: Ella'), 'stop');
assert.equal(replyIntent('Re: x', 'Please remove me from your list'), 'stop');
assert.equal(replyIntent('Re: x', 'Hi Ella, yes we are still looking for a welder. Can you call me on 07700 900123?'), 'reply');
assert.equal(replyIntent('Re: x', 'No idea what you mean but we do need a welder, call me'), 'reply');
assert.equal(replyIntent('Automatic reply: Welder at Acme', 'I am out of the office until Monday'), 'auto');
assert.equal(replyIntent('Re: x', 'I am currently out of the office with limited access to email.'), 'auto');
assert.equal(isAutoReply('Out of office', ''), true);
assert.equal(looksLikeNdr('jane@acme-eng.co.uk', 'Re: Welder at Acme'), false);
console.log('cold-bounce: all tests passed');
