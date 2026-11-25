// Build 73.1 tests: node scripts/test-owner-mail.mjs
import assert from 'assert';
import { addrOf, recipientsOf, isOwnerOnly, forceOwnerSender } from '../owner-mail.js';

let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; }; const eq = (a, b, m) => { assert.deepStrictEqual(a, b, m); n++; };
const DAN = 'dan.brown@live2helprecruitment.co.uk', ELLA = 'ella@live2helprecruitment.co.uk';
const ctx = { danEmail: DAN, danName: 'Daniel Brown', inboxEmail: DAN };

eq(addrOf('"Live 2 Help" <Dan.Brown@Live2HelpRecruitment.co.uk>'), DAN, 'address pulled from a display name form');
eq(recipientsOf({ to: `${DAN}, ${ELLA}`, cc: [ELLA] }), [DAN, ELLA, ELLA], 'to and cc both counted');

// payroll reminder passed Ella as the From: it must go out from Dan
let o = forceOwnerSender({ from: ELLA, to: DAN, subject: 'Payroll due' }, ctx);
eq(o.from, `"Daniel Brown" <${DAN}>`, 'payroll reminder sent from Ella is forced to Dan');
o = forceOwnerSender({ from: '"Live 2 Help Workspace" <office@live2helprecruitment.co.uk>', to: DAN }, ctx);
ok(o.from.includes(DAN), 'office@ as From is forced to Dan');
o = forceOwnerSender({ from: ELLA, to: DAN, bcc: DAN }, ctx);
ok(o.from.includes(DAN), 'a bcc to Dan only is still owner only');

// reminder inbox that is not Dan's own address still counts as owner only
o = forceOwnerSender({ from: ELLA, to: 'dan.private@example.com' }, { ...ctx, inboxEmail: 'dan.private@example.com' });
ok(o.from.includes(DAN), 'a separate reminder inbox is owner only');

// anything that reaches anyone else is left alone
const team = { from: ELLA, to: `${DAN}, ${ELLA}`, subject: 'details sent' };
eq(forceOwnerSender(team, ctx), team, 'team notice to Dan and Ella keeps its From');
const cand = { from: ELLA, to: 'candidate@example.com' };
eq(forceOwnerSender(cand, ctx), cand, 'candidate email from Ella keeps Ella as the From');
const none = { from: ELLA, to: '' };
eq(forceOwnerSender(none, ctx), none, 'no recipients, nothing changed');
eq(forceOwnerSender({ from: ELLA, to: DAN }, { danEmail: '', inboxEmail: '' }).from, ELLA, 'no Dan address configured, nothing changed');

// other fields survive
o = forceOwnerSender({ from: ELLA, to: DAN, replyTo: 'lead@example.com', attachments: [{ filename: 'a.pdf' }], subject: 'x' }, ctx);
eq([o.replyTo, o.attachments.length, o.subject], ['lead@example.com', 1, 'x'], 'reply-to, attachments and subject kept');

console.log(`test-owner-mail: ${n} checks passed`);
