/* Build 67.3: closing chase and call tasks once the contact they ask for is logged. Pure, tested in scripts/test-attention.mjs.
   Client chases need an outbound email or call to the client's company, candidate calls need one to the candidate. The contact must
   be dated on or after the day the task falls due (chase3 from the day after it was created), so the submission email itself, sent
   when the task was created, never closes a chase. Rejection emails and cold call follow ups are handled elsewhere. */
export const CONTACT_TASKS = { chase1: ['client', 0], chase3: ['client', 2], fbchase: ['client', 0], 'iv-clientfb': ['client', 0], avail: ['candidate', 0], 'ivday-before': ['candidate', 0], 'iv-3h': ['candidate', 0], 'iv-after': ['candidate', 0] };

export function contactDoneReason(p, ev, t, comms, h) {
  const rule = CONTACT_TASKS[String(ev).replace(/-r\d+$/, '')];
  if (!rule) return null;
  const due = h.parseISODate(t.dueDate);
  if (!due) return null;
  const since = due.getTime() - rule[1] * 86400000;
  const hit = comms.find(c => ['email', 'call'].includes(h.lc(c.channel)) && !/^in/i.test(c.direction || '') && h.msOf(c.timestamp) >= since &&
    (rule[0] === 'client'
      ? (c.entity_type === 'client' || h.lc(c.entity_type) === 'company') && p.company && h.lc(c.company || c.entity_name) === h.lc(p.company)
      : c.entity_type !== 'client' && h.personNameMatches(c.entity_name, p.name) && (!c.role || h.lc(c.role) === h.lc(p.role))));
  if (!hit) return null;
  return `${h.lc(hit.channel) === 'call' ? 'a call' : 'an email'} to ${rule[0] === 'client' ? p.company : p.name} was logged on ${h.formatDateUK(String(hit.timestamp).slice(0, 10))}`;
}
