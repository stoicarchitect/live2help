/* Client onboarding documents (build 49.1)
   Reads the markdown sources in /onboarding-docs, fills in the {{placeholders}} and renders the
   same text two ways: HTML for the client portal and a branded PDF (with the signature page and
   signing record for the two agreements). One source, so the page the client reads and the PDF
   they keep can never differ. Pure functions, no network, no database. */
import crypto from 'crypto';

const NAVY = '#0B0B18', GOLD = '#C9A84C', GREY = '#444444', MUTED = '#6B6F80', LIGHT = '#F7F6F3', RULE = '#E3E1DA';

/* ---------- markdown subset: ## headings, paragraphs, - and 1. lists, | tables, **bold**, *italic*, [text](url) ---------- */
export function parseDoc(raw) {
  const m = String(raw).match(/^---\n([\s\S]*?)\n---\n/);
  const meta = {};
  if (m) m[1].split('\n').forEach(l => { const i = l.indexOf(': '); if (i > 0) meta[l.slice(0, i).trim()] = l.slice(i + 2).trim(); });
  const lines = String(raw).slice(m ? m[0].length : 0).split('\n');
  const blocks = [];
  let i = 0;
  const isTable = s => /^\s*\|/.test(s);
  const isList = s => /^\s*(?:-|\d+\.)\s+/.test(s);
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    const h = line.match(/^(#{2,3})\s+(.*)$/);
    if (h) { blocks.push({ type: 'h', level: h[1].length, inline: inline(h[2]) }); i++; continue; }
    if (isTable(line)) {
      const rows = [];
      while (i < lines.length && isTable(lines[i])) {
        const cells = lines[i].trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
        if (!cells.every(c => /^:?-{3,}:?$/.test(c))) rows.push(cells);
        i++;
      }
      const head = rows.shift() || [];
      blocks.push({ type: 'table', head: head.every(c => !c) ? null : head.map(inline), rows: rows.map(r => r.map(inline)) });
      continue;
    }
    if (isList(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items = [];
      while (i < lines.length && isList(lines[i])) { items.push(inline(lines[i].replace(/^\s*(?:-|\d+\.)\s+/, ''))); i++; }
      blocks.push({ type: 'list', ordered, items });
      continue;
    }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^#{2,3}\s/.test(lines[i]) && !isTable(lines[i]) && !isList(lines[i])) { para.push(lines[i].trim()); i++; }
    blocks.push({ type: 'p', inline: inline(para.join('\n')) });
  }
  return { meta, blocks };
}

// segments: { t: text, b: bold, i: italic, href }
function inline(s) {
  const out = [];
  const re = /\*\*(.+?)\*\*|\*(.+?)\*|\[([^\]]+)\]\(([^)\s]+)\)/g;
  let last = 0, m;
  const text = String(s);
  while ((m = re.exec(text))) {
    if (m.index > last) out.push({ t: text.slice(last, m.index) });
    if (m[1] != null) out.push({ t: m[1], b: true });
    else if (m[2] != null) out.push({ t: m[2], i: true });
    else out.push({ t: m[3], href: m[4] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ t: text.slice(last) });
  return out;
}

/* ---------- placeholders ---------- */
export function fillPlaceholders(raw, vars) {
  return String(raw).replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (all, k) => (vars && vars[k] != null && String(vars[k]) !== '' ? String(vars[k]) : '[' + k.replace(/_/g, ' ') + ' to be confirmed]'));
}
export function unfilledPlaceholders(raw, vars) {
  const out = new Set();
  String(raw).replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (all, k) => { if (!(vars && vars[k] != null && String(vars[k]) !== '')) out.add(k); return all; });
  return [...out];
}
// Fingerprint of exactly what the client was shown, kept in the signing record
export function docHash(filledText) { return crypto.createHash('sha256').update(String(filledText)).digest('hex'); }

/* ---------- HTML for the portal ---------- */
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const safeHref = u => (/^(https?:\/\/|mailto:)/i.test(u) ? u : '#');
function inlineHtml(segs) {
  return segs.map(s => {
    let t = esc(s.t).replace(/\n/g, '<br>');
    if (s.href) t = `<a href="${esc(safeHref(s.href))}" rel="noopener noreferrer">${t}</a>`;
    if (s.b) t = `<strong>${t}</strong>`;
    if (s.i) t = `<em>${t}</em>`;
    return t;
  }).join('');
}
export function docToHtml(blocks) {
  return blocks.map(b => {
    if (b.type === 'h') return `<h${b.level}>${inlineHtml(b.inline)}</h${b.level}>`;
    if (b.type === 'p') return `<p>${inlineHtml(b.inline)}</p>`;
    if (b.type === 'list') { const tag = b.ordered ? 'ol' : 'ul'; return `<${tag}>${b.items.map(it => `<li>${inlineHtml(it)}</li>`).join('')}</${tag}>`; }
    if (b.type === 'table') {
      const head = b.head ? `<thead><tr>${b.head.map(c => `<th>${inlineHtml(c)}</th>`).join('')}</tr></thead>` : '';
      return `<div class="tw"><table>${head}<tbody>${b.rows.map(r => `<tr>${r.map(c => `<td>${inlineHtml(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
    }
    return '';
  }).join('\n');
}
// Plain text of a document (used for the fingerprint and search)
export function docToText(blocks) {
  const t = segs => segs.map(s => s.t).join('');
  return blocks.map(b => b.type === 'table' ? [b.head, ...b.rows].filter(Boolean).map(r => r.map(t).join(' | ')).join('\n')
    : b.type === 'list' ? b.items.map(t).join('\n') : t(b.inline)).join('\n\n');
}

/* ---------- times ---------- */
export const ukTime = iso => new Date(iso).toLocaleString('en-GB', { timeZone: 'Europe/London', day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const ukDate = iso => new Date(iso).toLocaleDateString('en-GB', { timeZone: 'Europe/London', day: 'numeric', month: 'long', year: 'numeric' });

/* ---------- PDF ---------- */
const F = { reg: 'Helvetica', bold: 'Helvetica-Bold', ital: 'Helvetica-Oblique' };
const PAGE = { w: 595.28, h: 841.89, m: 50 };

function runInline(doc, segs, size, color, opts) {
  const parts = segs.filter(s => s.t !== '');
  if (!parts.length) { doc.font(F.reg).fontSize(size).fillColor(color).text(' ', opts); return; }
  parts.forEach((s, idx) => {
    doc.font(s.b ? F.bold : (s.i ? F.ital : F.reg)).fontSize(size).fillColor(s.href ? '#1A56A0' : color);
    doc.text(s.t, { ...opts, continued: idx < parts.length - 1, link: s.href && /^(https?:|mailto:)/i.test(s.href) ? s.href : undefined, underline: !!s.href });
  });
}
const plain = segs => segs.map(s => s.t).join('');

function cover(doc, logo, meta) {
  doc.rect(0, 0, PAGE.w, 118).fill(NAVY);
  doc.rect(0, 118, PAGE.w, 3).fill(GOLD);
  let titleY = 34;
  if (logo) { try { doc.image(logo, PAGE.m, 20, { height: 50 }); titleY = 80; } catch (e) { /* no logo */ } }
  if (titleY === 34) doc.font(F.bold).fontSize(12).fillColor(GOLD).text('LIVE 2 HELP RECRUITMENT', PAGE.m, 28);
  doc.font(F.bold).fontSize(titleY === 80 ? 17 : 22).fillColor('#FFFFFF').text(meta.title || '', PAGE.m, titleY, { width: PAGE.w - 2 * PAGE.m, lineBreak: false });
  doc.y = 138;
}
function ensure(doc, h) { if (doc.y + h > PAGE.h - 62) doc.addPage(); }

function drawTable(doc, b) {
  const W = PAGE.w - 2 * PAGE.m, cols = Math.max(b.head ? b.head.length : 0, ...b.rows.map(r => r.length), 1);
  const weights = Array.from({ length: cols }, (_, c) => {
    const lens = [...(b.head ? [b.head[c]] : []), ...b.rows.map(r => r[c])].filter(Boolean).map(x => plain(x).length);
    return Math.min(60, Math.max(8, ...lens, 1) ** 0.75);
  });
  const total = weights.reduce((a, x) => a + x, 0);
  const widths = weights.map(w => W * w / total);
  const pad = 5;
  const cellH = (segs, w, bold) => { doc.font(bold ? F.bold : F.reg).fontSize(8.6); return doc.heightOfString(plain(segs || [{ t: ' ' }]) || ' ', { width: w - 2 * pad }) + 2 * pad - 1; };
  const drawRow = (cells, header, shade) => {
    const h = Math.max(...Array.from({ length: cols }, (_, c) => cellH(cells[c], widths[c], header || (cells[c] || []).some(s => s.b))));
    ensure(doc, h);
    const y = doc.y;
    if (header) doc.rect(PAGE.m, y, W, h).fill(NAVY); else if (shade) doc.rect(PAGE.m, y, W, h).fill(LIGHT);
    let x = PAGE.m;
    for (let c = 0; c < cols; c++) {
      const segs = cells[c] || [];
      doc.save();
      doc.font(header ? F.bold : F.reg).fontSize(8.6).fillColor(header ? '#FFFFFF' : NAVY);
      const parts = segs.filter(s => s.t !== '');
      if (parts.length) parts.forEach((s, idx) => { doc.font(header || s.b ? F.bold : (s.i ? F.ital : F.reg)).fillColor(header ? '#FFFFFF' : (c === 0 ? NAVY : GREY)).text(s.t, idx === 0 ? x + pad : undefined, idx === 0 ? y + pad : undefined, { width: widths[c] - 2 * pad, continued: idx < parts.length - 1 }); });
      doc.restore();
      x += widths[c];
    }
    if (!header) doc.moveTo(PAGE.m, y + h).lineTo(PAGE.m + W, y + h).lineWidth(0.5).strokeColor(RULE).stroke();
    doc.y = y + h;
    doc.x = PAGE.m;
  };
  doc.moveDown(0.3);
  if (b.head) drawRow(b.head, true, false);
  b.rows.forEach((r, i) => drawRow(r, false, i % 2 === 1));
  doc.moveDown(0.7);
  doc.x = PAGE.m;
}

function drawBlocks(doc, blocks) {
  const W = PAGE.w - 2 * PAGE.m;
  for (const b of blocks) {
    doc.x = PAGE.m;
    if (b.type === 'h') {
      ensure(doc, 60);
      doc.moveDown(0.7);
      doc.font(F.bold).fontSize(b.level === 2 ? 12.5 : 10.5).fillColor(NAVY).text(plain(b.inline), PAGE.m, doc.y, { width: W });
      if (b.level === 2) { const y = doc.y + 2; doc.moveTo(PAGE.m, y).lineTo(PAGE.m + W, y).lineWidth(1.2).strokeColor(GOLD).stroke(); doc.y = y + 5; }
      doc.x = PAGE.m;
    } else if (b.type === 'p') {
      ensure(doc, 30);
      runInline(doc, b.inline, 9.4, GREY, { width: W, lineGap: 2.2 });
      doc.moveDown(0.45);
    } else if (b.type === 'list') {
      b.items.forEach((it, idx) => {
        ensure(doc, 24);
        const y = doc.y;
        doc.font(F.reg).fontSize(9.4).fillColor(GOLD).text(b.ordered ? `${idx + 1}.` : '•', PAGE.m + 4, y, { width: 16, lineBreak: false });
        doc.x = PAGE.m + 20; doc.y = y;
        runInline(doc, it, 9.4, GREY, { width: W - 20, lineGap: 2.2 });
        doc.moveDown(0.25);
      });
      doc.x = PAGE.m; doc.moveDown(0.3);
    } else if (b.type === 'table') drawTable(doc, b);
  }
}

function sigBlock(doc, title, s, who) {
  const W = PAGE.w - 2 * PAGE.m, H = 150;
  ensure(doc, H + 20);
  const y = doc.y;
  doc.rect(PAGE.m, y, W, H).fillAndStroke(LIGHT, RULE);
  doc.rect(PAGE.m, y, 3, H).fill(GOLD);
  doc.font(F.bold).fontSize(8.5).fillColor(GOLD).text(title.toUpperCase(), PAGE.m + 18, y + 14, { width: W - 36 });
  if (s) {
    if (s.png) { try { doc.image(s.png, PAGE.m + 18, y + 32, { fit: [230, 56] }); } catch (e) { doc.font('Times-Italic').fontSize(24).fillColor(NAVY).text(s.name, PAGE.m + 18, y + 42, { width: W - 36, lineBreak: false }); } }
    else doc.font('Times-Italic').fontSize(26).fillColor(NAVY).text(s.name, PAGE.m + 18, y + 40, { width: W - 36, lineBreak: false });
    doc.moveTo(PAGE.m + 18, y + 94).lineTo(PAGE.m + 270, y + 94).lineWidth(0.8).strokeColor(GREY).stroke();
    doc.font(F.bold).fontSize(10.5).fillColor(NAVY).text(s.name + (s.title ? ', ' + s.title : ''), PAGE.m + 18, y + 100, { width: W - 36, lineBreak: false });
    doc.font(F.reg).fontSize(8.5).fillColor(GREY).text('Signed ' + ukTime(s.at) + ' (UK time)', PAGE.m + 18, y + 117, { width: W - 36, lineBreak: false });
    doc.font(F.reg).fontSize(8).fillColor(MUTED).text(who, PAGE.m + 18, y + 131, { width: W - 36, lineBreak: false });
  } else {
    doc.font(F.ital).fontSize(12).fillColor(MUTED).text('Awaiting countersignature', PAGE.m + 18, y + 70, { width: W - 36, lineBreak: false });
  }
  doc.y = y + H + 16; doc.x = PAGE.m;
}

function kv(doc, rows) {
  const W = PAGE.w - 2 * PAGE.m, lw = 150;
  rows.filter(r => r[1] != null && r[1] !== '').forEach((r, i) => {
    doc.font(F.reg).fontSize(8.6);
    const h = Math.max(doc.heightOfString(String(r[1]), { width: W - lw - 12 }), 11) + 9;
    ensure(doc, h);
    const y = doc.y;
    if (i % 2 === 0) doc.rect(PAGE.m, y, W, h).fill(LIGHT);
    doc.font(F.bold).fontSize(8.6).fillColor(NAVY).text(r[0], PAGE.m + 8, y + 4.5, { width: lw - 8 });
    doc.font(F.reg).fontSize(8.6).fillColor(GREY).text(String(r[1]), PAGE.m + lw + 4, y + 4.5, { width: W - lw - 12 });
    doc.y = y + h; doc.x = PAGE.m;
  });
}

/* opts: { PDFDocument, logo (Buffer|null), meta, blocks, sign: null | { client, agency, record } }
   client / agency: { name, title, png (Buffer|null), at }   record: audit trail details */
export function buildDocPdf({ PDFDocument, logo, meta, blocks, sign }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 50, bottom: 62, left: PAGE.m, right: PAGE.m }, bufferPages: true,
      info: { Title: meta.title || 'Live 2 Help document', Author: 'Live 2 Help Recruitment Ltd', Subject: meta.subtitle || '' } });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    try {
      cover(doc, logo, meta);
      doc.font(F.bold).fontSize(11).fillColor(GOLD).text(meta.subtitle || '', PAGE.m, doc.y, { width: PAGE.w - 2 * PAGE.m });
      doc.font(F.reg).fontSize(8).fillColor(MUTED).text(meta.version || '', PAGE.m, doc.y + 3, { width: PAGE.w - 2 * PAGE.m });
      doc.moveDown(0.8);
      drawBlocks(doc, blocks);
      if (sign) {
        doc.addPage();
        doc.font(F.bold).fontSize(9).fillColor(GOLD).text('SIGNATURE PAGE', PAGE.m, 60);
        doc.font(F.bold).fontSize(20).fillColor(NAVY).text(meta.title || '', PAGE.m, doc.y + 4, { width: PAGE.w - 2 * PAGE.m });
        doc.font(F.ital).fontSize(9.5).fillColor(GREY).text('Signed electronically through the Live 2 Help client portal. By signing, each party confirms it has read, understood and agrees to be bound by this document.', PAGE.m, doc.y + 6, { width: PAGE.w - 2 * PAGE.m });
        doc.moveDown(1.2);
        sigBlock(doc, 'For the Client', sign.client, 'Signed through the client portal after reading the document and agreeing to its terms');
        sigBlock(doc, 'For and on behalf of Live 2 Help Recruitment Ltd', sign.agency, 'Countersigned in the Live 2 Help workspace');
        const r = sign.record || {};
        doc.addPage();
        doc.font(F.bold).fontSize(9).fillColor(GOLD).text('SIGNING RECORD', PAGE.m, 60);
        doc.font(F.bold).fontSize(18).fillColor(NAVY).text('Audit trail', PAGE.m, doc.y + 4);
        doc.font(F.reg).fontSize(9).fillColor(GREY).text('This page records how and when the document was signed. It forms part of the signed document.', PAGE.m, doc.y + 4, { width: PAGE.w - 2 * PAGE.m });
        doc.moveDown(0.8);
        kv(doc, [
          ['Document', `${meta.title || ''} (${meta.version || ''})`],
          ['Document fingerprint (SHA-256)', r.docHash],
          ['Reference', r.reference],
          ['Client company', r.company],
          ['Signatory', sign.client ? `${sign.client.name}${sign.client.title ? ', ' + sign.client.title : ''}` : 'Not yet signed'],
          ['Signatory email', r.signerEmail],
          ['Signature method', r.method === 'drawn' ? 'Drawn on screen' : (r.method ? 'Typed name' : '')],
          ['Consent given', r.consentText],
          ['Signed (UK time)', sign.client ? ukTime(sign.client.at) : ''],
          ['Signed (UTC)', sign.client ? new Date(sign.client.at).toISOString() : ''],
          ['IP address', r.ip],
          ['Browser', r.userAgent],
          ['Countersigned by', sign.agency ? `${sign.agency.name}${sign.agency.title ? ', ' + sign.agency.title : ''}` : ''],
          ['Countersigned (UK time)', sign.agency ? ukTime(sign.agency.at) : ''],
        ]);
        if (Array.isArray(r.events) && r.events.length) {
          doc.moveDown(0.8);
          doc.font(F.bold).fontSize(10).fillColor(NAVY).text('Events', PAGE.m, doc.y);
          doc.moveDown(0.3);
          kv(doc, r.events.map(e => [ukTime(e.at), e.what]));
        }
      }
      // footer and page numbers on every page
      const range = doc.bufferedPageRange();
      for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        doc.page.margins.bottom = 0;
        doc.font(F.ital).fontSize(7.5).fillColor(MUTED).text('Live 2 Help Recruitment Ltd · Company No. 11731080 · Anyone · Anywhere · Anytime', PAGE.m, PAGE.h - 40, { width: PAGE.w - 2 * PAGE.m - 60, lineBreak: false });
        doc.font(F.reg).fontSize(7.5).fillColor(MUTED).text(`${i + 1} / ${range.count}`, PAGE.w - PAGE.m - 50, PAGE.h - 40, { width: 50, align: 'right', lineBreak: false });
      }
      doc.end();
    } catch (e) { reject(e); }
  });
}
