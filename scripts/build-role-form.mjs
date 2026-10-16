// Builds a role-linked application form from a definition file.
//
//   node scripts/build-role-form.mjs forms/r007.json
//   node scripts/build-role-form.mjs --all
//
// Writes apply/<slug>/index.html, where the slug is just the role reference (r007), so the
// client's job title is never in the address. The page title follows the role's public title live. Every form posts to /api/applications/<slug>, and the
// server ties the application to the role by the reference ID at the end of the slug
// (r007 = role R007 on the Roles tab), so the server never needs changing for a new form.
// Salary: the form shows "Competitive salary" and then checks the Roles tab live, so once a
// salary band is saved on the role the form shows it automatically. A filled or lost role
// closes its own form.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_BASE = 'https://l2h-api.onrender.com';

const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function checkNoLongDashes(def, file) {
  const text = JSON.stringify(def);
  if (/[—–]/.test(text)) throw new Error(`${file} contains a long dash. Use a hyphen instead.`);
}

function questionHtml(q) {
  const req = q.required === false ? '' : '<span class="req">*</span>';
  const hint = q.hint ? `<span class="hint">${esc(q.hint)}</span>` : '';
  const err = {
    text: 'Please answer this question.', textarea: 'Please answer this question.',
    select: 'Please select an option.', radio: 'Please choose one option.',
    checkbox: 'Please tick at least one option.', scale: 'Please choose a number.',
  }[q.type] || 'Please answer this question.';
  const id = `q_${q.key}`;
  if (q.type === 'text') {
    return `<div class="field" data-f="${id}">
          <label class="q" for="${id}">${esc(q.label)}${req}${hint}</label>
          <input type="text" id="${id}" maxlength="${q.max || 300}">
          <div class="err">${err}</div>
        </div>`;
  }
  if (q.type === 'textarea') {
    return `<div class="field" data-f="${id}">
          <label class="q" for="${id}">${esc(q.label)}${req}${hint}</label>
          <textarea id="${id}" maxlength="${q.max || 1500}"></textarea>
          <div class="err">${err}</div>
        </div>`;
  }
  if (q.type === 'select') {
    return `<div class="field" data-f="${id}">
          <label class="q" for="${id}">${esc(q.label)}${req}${hint}</label>
          <select id="${id}">
            <option value="">Please select</option>
            ${q.options.map(o => `<option>${esc(o)}</option>`).join('\n            ')}
          </select>
          <div class="err">${err}</div>
        </div>`;
  }
  if (q.type === 'radio' || q.type === 'checkbox') {
    return `<div class="field" data-f="${id}">
          <span class="q-label">${esc(q.label)}${req}${hint}</span>
          <div class="opts">
            ${q.options.map(o => `<label class="opt"><input type="${q.type}" name="${id}" value="${esc(o)}"> ${esc(o)}</label>`).join('\n            ')}
          </div>
          <div class="err">${err}</div>
        </div>`;
  }
  if (q.type === 'scale') {
    const ends = q.ends || ['1', '10'];
    return `<div class="field" data-f="${id}">
          <span class="q-label">${esc(q.label)}${req}${hint}</span>
          <div class="scale" data-scale="${id}"></div>
          <div class="scale-ends"><span>${esc(ends[0])}</span><span>${esc(ends[1])}</span></div>
          <div class="err">${err}</div>
        </div>`;
  }
  throw new Error(`Unknown question type "${q.type}" for ${q.key}`);
}

function buildForm(def, logo) {
  const all = [...(def.about || []), ...def.sections.flatMap(s => s.questions)];
  const keys = new Set();
  all.forEach(q => {
    if (!q.key || !q.label || !q.type) throw new Error('Every question needs key, label and type');
    if (keys.has(q.key)) throw new Error(`Duplicate question key ${q.key}`);
    keys.add(q.key);
    if (['select', 'radio', 'checkbox'].includes(q.type) && !(q.options || []).length) throw new Error(`${q.key} needs options`);
  });
  if (!/^r\d{3,}$/.test(def.slug)) throw new Error('The slug must be the role reference only, e.g. r007, so the job title is never in the link');
  const qConfig = all.map(q => ({ id: `q_${q.key}`, label: q.sheet || q.label, type: q.type, required: q.required !== false }));

  return `<!DOCTYPE html>
<html lang="en-GB">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Apply - ${esc(def.title)}</title>
<meta name="robots" content="noindex">
<meta name="l2h-role-ref" content="${esc(def.ref)}">
<style>
  :root{
    --navy:#0B0B18;
    --navy-2:#14142A;
    --gold:#C9A84C;
    --gold-dark:#A8892F;
    --ink:#1A1A1A;
    --grey:#444444;
    --muted:#6B6B76;
    --lightbg:#F7F6F3;
    --border:#DDDDDD;
    --white:#FFFFFF;
    --danger:#B23A3A;
    --success:#3E7A4C;
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  html{scroll-padding-top:env(safe-area-inset-top,0px);}
  body{
    font-family:"Gill Sans MT","Gill Sans",Calibri,"Segoe UI",sans-serif;
    background:var(--lightbg);
    color:var(--grey);
    line-height:1.55;
    font-size:16px;
    padding-bottom:env(safe-area-inset-bottom,0px);
  }
  header{
    background:#000;
    padding:calc(22px + env(safe-area-inset-top,0px)) 20px 22px;
    text-align:center;
    border-bottom:3px solid var(--gold);
  }
  header img{width:150px;height:auto;display:block;margin:0 auto;}
  .wrap{max-width:720px;margin:0 auto;padding:28px 18px 60px;}
  .intro{background:var(--white);border:1px solid var(--border);border-top:4px solid var(--gold);padding:26px 24px;margin-bottom:22px;}
  .intro h1{font-size:28px;line-height:1.2;color:var(--navy);font-weight:600;margin-bottom:6px;}
  .intro .meta{color:var(--gold-dark);font-weight:600;letter-spacing:.04em;text-transform:uppercase;font-size:13px;margin-bottom:14px;}
  .intro p{margin-bottom:10px;}
  .intro ul{margin:8px 0 4px 20px;}
  .intro li{margin-bottom:4px;}
  .intro .also{margin-top:14px;padding:10px 14px;background:#FBF7EA;border-left:3px solid var(--gold);color:var(--ink);font-size:15px;}
  fieldset{background:var(--white);border:1px solid var(--border);padding:24px 24px 8px;margin-bottom:20px;}
  legend{
    font-size:13px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--navy);
    padding:0 10px;margin-left:-10px;border-bottom:2px solid var(--gold);
  }
  .field{margin:18px 0;}
  label.q, .q-label{display:block;font-weight:600;color:var(--ink);margin-bottom:6px;}
  .hint{display:block;font-weight:400;color:var(--muted);font-size:14px;margin-top:2px;}
  .req{color:var(--danger);margin-left:3px;}
  input[type=text],input[type=email],input[type=tel],select,textarea{
    width:100%;padding:12px 13px;border:1px solid var(--border);border-radius:2px;background:#FFF;
    font:inherit;color:var(--ink);
  }
  textarea{min-height:110px;resize:vertical;}
  input:focus,select:focus,textarea:focus{outline:2px solid var(--gold);outline-offset:0;border-color:var(--gold);}
  .opts{display:flex;flex-direction:column;gap:8px;}
  .opt{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:2px;cursor:pointer;background:#FFF;}
  .opt input{margin-top:4px;accent-color:var(--gold-dark);flex:none;}
  .opt:has(input:checked){border-color:var(--gold);background:#FBF7EA;}
  .scale{display:grid;grid-template-columns:repeat(10,1fr);gap:6px;}
  .scale label{
    display:flex;align-items:center;justify-content:center;height:44px;border:1px solid var(--border);
    cursor:pointer;font-weight:600;color:var(--ink);background:#FFF;border-radius:2px;
  }
  .scale input{position:absolute;opacity:0;pointer-events:none;}
  .scale label:has(input:checked){background:var(--navy);border-color:var(--navy);color:var(--gold);}
  .scale-ends{display:flex;justify-content:space-between;font-size:13px;color:var(--muted);margin-top:5px;}
  .file-box{border:2px dashed var(--border);padding:18px;background:#FFF;border-radius:2px;}
  .file-box input{width:100%;}
  .consent{margin:10px 0 16px;}
  .consent .opt{border-color:transparent;padding:6px 0;background:transparent;}
  .consent .opt:has(input:checked){background:transparent;border-color:transparent;}
  .consent a{color:var(--navy);font-weight:600;}
  .err{color:var(--danger);font-size:14px;margin-top:5px;display:none;}
  .field.invalid .err{display:block;}
  .field.invalid input[type=text],.field.invalid input[type=email],.field.invalid input[type=tel],
  .field.invalid select,.field.invalid textarea,.field.invalid .file-box{border-color:var(--danger);}
  .field.invalid .opts,.field.invalid .scale{outline:1px solid var(--danger);outline-offset:3px;}
  button.submit{
    width:100%;padding:16px;background:var(--navy);color:var(--gold);border:2px solid var(--gold);
    font:inherit;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;border-radius:2px;
  }
  button.submit:hover{background:var(--navy-2);}
  button.submit:disabled{opacity:.6;cursor:wait;}
  .banner{display:none;padding:14px 16px;margin:14px 0;border-radius:2px;font-weight:600;}
  .banner.error{display:block;background:#FBECEC;border:1px solid var(--danger);color:var(--danger);}
  .done,.closed{display:none;background:var(--white);border:1px solid var(--border);border-top:4px solid var(--gold);padding:36px 26px;text-align:center;}
  .done h2,.closed h2{color:var(--navy);font-size:26px;margin-bottom:10px;}
  .done p,.closed p{margin-bottom:8px;}
  .closed a{color:var(--navy);font-weight:600;}
  footer{text-align:center;color:var(--muted);font-size:13px;padding:0 18px 30px;}
  .hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;}
  @media (max-width:520px){
    .intro h1{font-size:24px;}
    fieldset{padding:20px 16px 6px;}
    .scale{gap:4px;}
    .scale label{height:40px;font-size:14px;}
  }
  @media (prefers-color-scheme:dark){
    :root:not([data-theme="light"]){color-scheme:light;}
  }
</style>
</head>
<body>
<header><img src="${logo}" alt="Live 2 Help Recruitment"></header>

<div class="wrap">
  <div id="formArea">
    <section class="intro">
      <div class="meta">${esc(def.location)} &middot; ${esc(def.employment || 'Permanent')} &middot; <span id="salaryText">Competitive salary</span></div>
      <h1 id="roleTitle">${esc(def.title)}</h1>
      <p>${esc(def.intro)}</p>
      <ul>
        ${(def.bullets || []).map(b => `<li>${esc(b)}</li>`).join('\n        ')}
      </ul>
      ${def.also ? `<p class="also">${esc(def.also)}</p>` : ''}
      ${def.outro ? `<p style="margin-top:12px;">${esc(def.outro)}</p>` : ''}
    </section>

    <form id="applyForm" novalidate autocomplete="on">
      <div class="hp" aria-hidden="true"><label>Leave this empty<input type="text" id="website" name="website" tabindex="-1" autocomplete="off"></label></div>

      <fieldset>
        <legend>About you</legend>

        <div class="field" data-f="name">
          <label class="q" for="name">Full name<span class="req">*</span></label>
          <input type="text" id="name" name="name" autocomplete="name">
          <div class="err">Please enter your full name.</div>
        </div>
        <div class="field" data-f="email">
          <label class="q" for="email">Email address<span class="req">*</span></label>
          <input type="email" id="email" name="email" autocomplete="email" inputmode="email">
          <div class="err">Please enter a valid email address.</div>
        </div>
        <div class="field" data-f="phone">
          <label class="q" for="phone">Mobile number<span class="req">*</span></label>
          <input type="tel" id="phone" name="phone" autocomplete="tel" inputmode="tel">
          <div class="err">Please enter a contact number.</div>
        </div>
        ${(def.about || []).map(questionHtml).join('\n        ')}
        <div class="field" data-f="employmentStatus">
          <label class="q" for="employmentStatus">Current employment status<span class="req">*</span></label>
          <select id="employmentStatus" name="employmentStatus">
            <option value="">Please select</option>
            <option>Employed full-time</option>
            <option>Employed part-time</option>
            <option>Contractor or self-employed</option>
            <option>Unemployed, available immediately</option>
            <option>Other</option>
          </select>
          <div class="err">Please select an option.</div>
        </div>
        <div class="field" data-f="noticePeriod">
          <label class="q" for="noticePeriod">Notice period<span class="req">*</span></label>
          <select id="noticePeriod" name="noticePeriod">
            <option value="">Please select</option>
            <option>Immediately available</option>
            <option>1 week</option>
            <option>2 weeks</option>
            <option>4 weeks</option>
            <option>8 weeks</option>
            <option>12 weeks or more</option>
          </select>
          <div class="err">Please select an option.</div>
        </div>
        <div class="field" data-f="salaryExpectation">
          <label class="q" for="salaryExpectation"><span id="salaryQ">What basic salary are you looking for?</span><span class="req">*</span>
            <span class="hint">Your current basic salary and what you would want to move for both help</span></label>
          <input type="text" id="salaryExpectation" name="salaryExpectation" maxlength="200">
          <div class="err">Please tell us your salary expectations.</div>
        </div>
      </fieldset>

${def.sections.map(s => `      <fieldset>
        <legend>${esc(s.legend)}</legend>

        ${s.questions.map(questionHtml).join('\n        ')}
      </fieldset>`).join('\n\n')}

      <fieldset>
        <legend>Your CV and consent</legend>

        <div class="field" data-f="cv">
          <label class="q" for="cv">Upload your CV<span class="req">*</span>
            <span class="hint">PDF, DOC or DOCX, up to 5MB</span></label>
          <div class="file-box"><input type="file" id="cv" name="cv" accept=".pdf,.doc,.docx,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document"></div>
          <div class="err" id="cvErr">Please upload your CV as a PDF, DOC or DOCX file under 5MB.</div>
        </div>
        <div class="field">
          <label class="q" for="additionalInfo">Anything else you would like us to know? <span class="hint">Optional</span></label>
          <textarea id="additionalInfo" name="additionalInfo" maxlength="1500" style="min-height:80px;"></textarea>
        </div>

        <div class="field consent" data-f="consentApplication">
          <label class="opt"><input type="checkbox" id="consentApplication"> <span>I have read the <a href="https://live2helprecruitment.co.uk/privacy-policy" target="_blank" rel="noopener">privacy policy</a> and I agree to Live 2 Help Recruitment using my details to process this application and share them with the employer for this role.<span class="req">*</span></span></label>
          <div class="err">You need to accept this to submit your application.</div>
        </div>
        <div class="field consent">
          <label class="opt"><input type="checkbox" id="consentPool"> <span>Optional: I would like Live 2 Help Recruitment to keep my details so they can contact me about future roles.</span></label>
        </div>
      </fieldset>

      <div class="banner" id="banner" role="alert"></div>
      <button type="submit" class="submit" id="submitBtn">Submit application</button>
    </form>
  </div>

  <section class="done" id="doneBox" role="status">
    <h2>Thank you, application received</h2>
    <p>Your application and CV have arrived safely. We will review everything and be in touch shortly if your experience matches what the employer is looking for.</p>
    <p>A confirmation email is on its way to you.</p>
  </section>

  <section class="closed" id="closedBox" role="status">
    <h2>This role is no longer open</h2>
    <p>Thank you for your interest. This vacancy has now closed.</p>
    <p>See our other live roles at <a href="https://careers.live2helprecruitment.co.uk/">careers.live2helprecruitment.co.uk</a>.</p>
  </section>
</div>
<footer>Live 2 Help Recruitment &middot; Anyone &middot; Anywhere &middot; Anytime</footer>

<script>
(function(){
  var API_BASE = "${API_BASE}";
  var SLUG = "${esc(def.slug)}";
  var ROLE_ID = "${esc(def.roleId || '')}";
  var ENDPOINT = API_BASE + "/api/applications/" + SLUG;
  var MAX_BYTES = 5 * 1024 * 1024;
  var QUESTIONS = ${JSON.stringify(qConfig)};

  // Salary and open status come live from the Roles tab, so the form never needs editing for them
  function money(s){
    s = String(s || '').trim();
    if (!s) return '';
    return s.replace(/(^|[^\\u00a3\\d,.])(\\d{2,3}(,\\d{3})|\\d{4,6})/g, function(m, pre, num){ return pre + '\\u00a3' + num; });
  }
  try {
    var ctrl = window.AbortController ? new AbortController() : null;
    if (ctrl) setTimeout(function(){ ctrl.abort(); }, 12000);
    fetch(API_BASE + "/api/public/forms/" + SLUG, ctrl ? { signal: ctrl.signal } : {})
      .then(function(r){ return r.ok ? r.json() : null; })
      .then(function(j){
        if (!j) return;
        if (j.found && j.open === false){
          document.getElementById('formArea').style.display = 'none';
          document.getElementById('closedBox').style.display = 'block';
          return;
        }
        // the public title from the Roles tab always wins, so renaming a role updates the form
        if (j.title){
          document.getElementById('roleTitle').textContent = j.title;
          document.title = 'Apply - ' + j.title;
        }
        var sal = money(j.salary);
        if (sal){
          document.getElementById('salaryText').textContent = sal;
          document.getElementById('salaryQ').textContent = 'The salary for this role is ' + sal + '. What basic salary are you looking for?';
        }
      }).catch(function(){ /* keep "Competitive salary" */ });
  } catch (e) {}

  document.querySelectorAll('.scale').forEach(function(box){
    var name = box.getAttribute('data-scale');
    for (var i = 1; i <= 10; i++){
      var l = document.createElement('label');
      var inp = document.createElement('input');
      inp.type = 'radio'; inp.name = name; inp.value = String(i);
      l.appendChild(inp); l.appendChild(document.createTextNode(String(i)));
      box.appendChild(l);
    }
  });

  function fieldWrap(key){ return document.querySelector('[data-f="'+key+'"]'); }
  function setInvalid(key, bad){
    var w = fieldWrap(key); if (!w) return;
    if (bad) w.classList.add('invalid'); else w.classList.remove('invalid');
  }
  function val(id){ var el = document.getElementById(id); return el ? (el.value || '').trim() : ''; }
  function answerOf(q){
    if (q.type === 'radio' || q.type === 'scale'){
      var el = document.querySelector('input[name="'+q.id+'"]:checked');
      return el ? el.value : '';
    }
    if (q.type === 'checkbox'){
      return Array.prototype.map.call(document.querySelectorAll('input[name="'+q.id+'"]:checked'), function(x){ return x.value; });
    }
    return val(q.id);
  }
  function isEmpty(v){ return Array.isArray(v) ? v.length === 0 : !v; }

  var form = document.getElementById('applyForm');
  form.addEventListener('input', function(e){ var w = e.target.closest('[data-f]'); if (w) w.classList.remove('invalid'); });
  form.addEventListener('change', function(e){ var w = e.target.closest('[data-f]'); if (w) w.classList.remove('invalid'); });

  function readFileBase64(file){
    return new Promise(function(resolve, reject){
      var r = new FileReader();
      r.onload = function(){ var s = String(r.result || ''); resolve(s.substring(s.indexOf(',') + 1)); };
      r.onerror = function(){ reject(new Error('Could not read the file')); };
      r.readAsDataURL(file);
    });
  }

  function validate(){
    var firstBad = null;
    function flag(key, bad){ setInvalid(key, bad); if (bad && !firstBad) firstBad = fieldWrap(key); }
    ['name','email','phone'].forEach(function(k){
      var v = val(k);
      flag(k, k === 'email' ? !/^\\S+@\\S+\\.\\S+$/.test(v) : !v);
    });
    QUESTIONS.forEach(function(q){ if (q.required) flag(q.id, isEmpty(answerOf(q))); });
    ['employmentStatus','noticePeriod','salaryExpectation'].forEach(function(k){ flag(k, !val(k)); });
    flag('consentApplication', !document.getElementById('consentApplication').checked);
    var f = document.getElementById('cv').files[0];
    flag('cv', !f || !/\\.(pdf|docx?)$/i.test(f.name) || f.size > MAX_BYTES);
    // show errors in page order
    var bad = document.querySelector('.field.invalid');
    return bad || firstBad;
  }

  form.addEventListener('submit', function(e){
    e.preventDefault();
    var banner = document.getElementById('banner');
    banner.className = 'banner'; banner.textContent = '';
    if (document.getElementById('website').value) return; // honeypot

    var firstBad = validate();
    if (firstBad){
      banner.className = 'banner error';
      banner.textContent = 'Please complete the highlighted questions.';
      firstBad.scrollIntoView({behavior:'smooth', block:'center'});
      return;
    }

    var btn = document.getElementById('submitBtn');
    btn.disabled = true; btn.textContent = 'Submitting, please wait...';
    var file = document.getElementById('cv').files[0];
    var params = new URLSearchParams(window.location.search);

    readFileBase64(file).then(function(b64){
      var body = {
        roleId: ROLE_ID,
        name: val('name'), email: val('email'), phone: val('phone'),
        employmentStatus: val('employmentStatus'), noticePeriod: val('noticePeriod'),
        salaryExpectation: val('salaryExpectation'),
        additionalInfo: val('additionalInfo'),
        answers: QUESTIONS.map(function(q){ return { key: q.id, label: q.label, value: answerOf(q), required: q.required }; }),
        cvData: b64, cvFileName: file.name,
        consentApplication: document.getElementById('consentApplication').checked,
        consentPool: document.getElementById('consentPool').checked,
        src: params.get('src') || ''
      };
      return fetch(ENDPOINT, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) });
    }).then(function(res){
      return res.json().catch(function(){ return {}; }).then(function(j){
        if (res.status === 410){
          document.getElementById('formArea').style.display = 'none';
          document.getElementById('closedBox').style.display = 'block';
          window.scrollTo({top:0, behavior:'smooth'});
          return;
        }
        if (!res.ok || !j.success) throw new Error(j.error || 'Something went wrong');
        document.getElementById('formArea').style.display = 'none';
        document.getElementById('doneBox').style.display = 'block';
        window.scrollTo({top:0, behavior:'smooth'});
      });
    }).catch(function(err){
      banner.className = 'banner error';
      banner.textContent = (err && err.message ? err.message + '. ' : '') + 'Please try again, or email your CV to office@live2helprecruitment.co.uk.';
      btn.disabled = false; btn.textContent = 'Submit application';
      banner.scrollIntoView({behavior:'smooth', block:'center'});
    });
  });
})();
</script>
</body>
</html>
`;
}

function main() {
  const args = process.argv.slice(2);
  const files = args[0] === '--all'
    ? fs.readdirSync(path.join(ROOT, 'forms')).filter(f => f.endsWith('.json')).map(f => path.join(ROOT, 'forms', f))
    : args.map(a => path.resolve(a));
  if (!files.length) { console.log('Usage: node scripts/build-role-form.mjs forms/<slug>.json | --all'); process.exit(1); }
  const logo = fs.readFileSync(path.join(ROOT, 'forms', 'logo.txt'), 'utf8').trim();
  files.forEach(f => {
    const def = JSON.parse(fs.readFileSync(f, 'utf8'));
    checkNoLongDashes(def, f);
    const html = buildForm(def, logo);
    const dir = path.join(ROOT, 'apply', def.slug);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'index.html'), html);
    console.log(`Built apply/${def.slug}/index.html`);
    // older title-based addresses forward to the neutral one so links already shared still work
    (def.oldSlugs || []).forEach(o => {
      const od = path.join(ROOT, 'apply', o);
      fs.mkdirSync(od, { recursive: true });
      fs.writeFileSync(path.join(od, 'index.html'), `<!DOCTYPE html><html lang="en-GB"><head><meta charset="UTF-8"><meta name="robots" content="noindex"><title>Live 2 Help Recruitment</title>
<meta http-equiv="refresh" content="0; url=/apply/${def.slug}/"><script>location.replace('/apply/${def.slug}/' + location.search);</script></head>
<body><p><a href="/apply/${def.slug}/">Continue to the application form</a></p></body></html>
`);
      console.log(`Redirect apply/${o}/ -> apply/${def.slug}/`);
    });
  });
}

main();
