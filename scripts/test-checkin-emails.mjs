import fs from 'fs';
const s = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8');
let n = 0; const ok = (c, m) => { if (!c) { console.error('FAIL', m); process.exit(1); } n++; };
const tpl = s.match(/OFFER_EMAILS\.day1_welcome = \{[\s\S]*?\n\};/);
ok(tpl, 'day1 template present');
const body = tpl[0];
['candidate_first', 'job_title', 'company', 'start_time', 'work_location', 'reporting_to', 'sig_coordinator'].forEach(k => ok(body.includes('{{' + k + '}}'), 'token ' + k));
ok(!/—/.test(body), 'no em dash');
ok(/CHECKIN_RULES = \[[\s\S]*?day1_welcome[\s\S]*?feedback_week1[\s\S]*?feedback_month1/.test(s), 'rules cover all three');
ok(s.includes("o.kind === 'checkin'") && s.includes("kind === 'checkin'") || (s.match(/o\.kind === 'checkin'/g) || []).length >= 2, 'render and send branches');
ok(s.includes("step('checkinQueue', checkinQueueStep)"), 'daily step wired');
// line dropping and window maths, same logic as the server
const drop = (text, vals) => text.split('\n').filter(l => { const m = l.match(/\{\{(\w+)\}\}/); return !(m && ['start_time', 'work_location', 'reporting_to'].includes(m[1]) && !String(vals[m[1]] || '').trim()); }).join('\n');
const out = drop('a\nReport time: {{start_time}}\nLocation: {{work_location}}\nb', { work_location: 'Stoke' });
ok(out === 'a\nLocation: {{work_location}}\nb', 'blank detail lines dropped');
const inWin = (d, r) => d >= r.from && d <= r.to;
ok(inWin(0, { from: 0, to: 3 }) && !inWin(4, { from: 0, to: 3 }) && inWin(7, { from: 7, to: 14 }) && !inWin(6, { from: 7, to: 14 }), 'windows');
console.log('test-checkin-emails: ' + n + ' checks passed');
