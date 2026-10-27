// Build 48.0: makes dashboard-next/index.html (the preview workspace) from dashboard/index.html.
// Run after every change to the live page:  node scripts/build-preview.mjs
// The preview is the same page, plus:
// - every request to the server carries the x-l2h-preview header, so the server uses the test
//   database for groups in PG_PREVIEW_GROUPS and keeps everything else read only
// - a gold banner so nobody mistakes it for the live workspace
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = fs.readFileSync(path.join(root, 'dashboard', 'index.html'), 'utf8');

const inject = `
<script>
/* Preview workspace (made by scripts/build-preview.mjs - edit dashboard/index.html, not this file) */
(function(){
  var SERVER = 'https://l2h-api.onrender.com';
  var realFetch = window.fetch.bind(window);
  window.fetch = function(input, init){
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    if (url.indexOf(SERVER) === 0) {
      init = init || {};
      var h = new Headers(init.headers || (typeof input !== 'string' && input.headers) || {});
      h.set('x-l2h-preview', '1');
      init.headers = h;
    }
    return realFetch(input, init);
  };
  function banner(){
    if (document.getElementById('l2h-preview-banner')) return;
    var b = document.createElement('div');
    b.id = 'l2h-preview-banner';
    b.textContent = 'PREVIEW - test data only. Areas not yet moved are read only and no emails are sent. ';
    b.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;background:#C9A84C;color:#0B0B18;font:600 12px/1.4 sans-serif;text-align:center;padding:6px 12px;pointer-events:none;';
    var btn = document.createElement('button');
    btn.textContent = 'Reset test data';
    btn.style.cssText = 'pointer-events:auto;margin-left:10px;background:#0B0B18;color:#C9A84C;border:0;border-radius:4px;padding:3px 10px;font:600 12px sans-serif;cursor:pointer;';
    btn.onclick = function(){
      btn.disabled = true; btn.textContent = 'Adding...';
      window.fetch(SERVER + '/api/storage/preview-seed', { method: 'POST' }).then(function(r){ return r.json(); }).then(function(j){
        if (j && j.ok) location.reload(); else { btn.disabled = false; btn.textContent = (j && j.error) || 'Could not add test data'; }
      }).catch(function(){ btn.disabled = false; btn.textContent = 'Could not reach the server'; });
    };
    b.appendChild(btn);
    document.body.appendChild(b);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', banner); else banner();
})();
</script>`;

if (!src.includes('<head>')) throw new Error('dashboard/index.html has no <head> tag');
let out = src.replace('<head>', '<head>' + inject);
out = out.replace(/<title>([^<]*)<\/title>/, '<title>PREVIEW - $1</title>');
const m = out.match(/var PAGE_BUILD = '([^']*)';/);
if (!m) throw new Error('PAGE_BUILD not found in dashboard/index.html');
out = out.replace(m[0], `var PAGE_BUILD = '${m[1]} preview';`);

fs.writeFileSync(path.join(root, 'dashboard-next', 'index.html'), out);
console.log('dashboard-next/index.html made from ' + m[1]);
