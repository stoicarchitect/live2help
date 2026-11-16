// Build 62: makes the page on /dashboard-next the live page (dashboard/index.html).
// Use it when a build was put on the preview first and Daniel Brown has approved it:
//   node scripts/promote-preview.mjs      then commit dashboard/index.html
// It removes the three things scripts/build-preview.mjs adds: the preview script, the PREVIEW title and the " preview" build label.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const next = fs.readFileSync(path.join(root, 'dashboard-next', 'index.html'), 'utf8');

const start = next.indexOf('\n<script>\n/* Preview workspace (made by scripts/build-preview.mjs');
if (start < 0) throw new Error('The preview script was not found in dashboard-next/index.html');
const end = next.indexOf('</script>', start);
if (end < 0) throw new Error('The end of the preview script was not found');
let out = next.slice(0, start) + next.slice(end + '</script>'.length);
if (!/<title>PREVIEW - /.test(out)) throw new Error('The PREVIEW title was not found');
out = out.replace(/<title>PREVIEW - ([^<]*)<\/title>/, '<title>$1</title>');
const m = out.match(/var PAGE_BUILD = '([^']*) preview';/);
if (!m) throw new Error('The preview build label was not found');
out = out.replace(m[0], `var PAGE_BUILD = '${m[1]}';`);
if (out.includes('x-l2h-preview')) throw new Error('Preview code is still in the page, nothing was written');

fs.writeFileSync(path.join(root, 'dashboard', 'index.html'), out);
console.log('dashboard/index.html is now ' + m[1]);
console.log('Next: node scripts/build-preview.mjs (so the preview matches), then commit both files.');
