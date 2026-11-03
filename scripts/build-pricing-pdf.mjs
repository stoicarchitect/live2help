// Builds docs/live2help-pricing-2026.pdf (the public pricing brochure linked from lead emails)
// from onboarding-docs/pricing.md, using the same layout as the onboarding PDFs.
// Run after any change to pricing.md:  node scripts/build-pricing-pdf.mjs
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import PDFDocument from 'pdfkit';
import * as onbDocs from '../onboarding-docs.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const m = src.match(/const EMBEDDED_LOGO_B64 = '([^']+)'/);
const logo = m ? Buffer.from(m[1], 'base64') : null;
const raw = fs.readFileSync(path.join(root, 'onboarding-docs', 'pricing.md'), 'utf8');
const left = onbDocs.unfilledPlaceholders(raw, {});
if (left.length) { console.error('pricing.md has placeholders that need client details:', left.join(', ')); process.exit(1); }
const { meta, blocks } = onbDocs.parseDoc(raw);
const pdf = await onbDocs.buildDocPdf({ PDFDocument, logo, meta, blocks, sign: null });
const out = path.join(root, 'docs', 'live2help-pricing-2026.pdf');
fs.writeFileSync(out, pdf);
console.log('Wrote', out, pdf.length, 'bytes');
