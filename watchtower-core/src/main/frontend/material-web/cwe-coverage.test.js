const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/cwe-coverage.js'), 'utf8');
const tick = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise(resolve => setTimeout(resolve, 0)); };

const markup = (canModify, hidden = false) => `
<section data-rule-report-page data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">
 <p data-rule-report-status></p>
 <section data-cwe-coverage data-can-modify="${canModify}" ${hidden ? 'hidden' : ''}>
  <div data-cov-chips></div>
  <div data-cov-table><span>Loading coverage…</span></div>
 </section>
 <md-dialog data-cov-profile-dialog>
  <span data-cov-profile-count-label></span>
  <input data-cov-search>
  <div data-cov-results></div>
  <div data-cov-entries></div>
  <p data-cov-error></p>
 </md-dialog>
 <md-dialog data-cov-gap-dialog>
  <span data-cov-gap-title></span>
  <div data-cov-gap-state></div>
  <div data-gap-suggestion>old answer</div><button data-gap-suggest></button>
  <input data-cov-note>
  <p data-cov-gap-error></p>
  <button data-cov-clear hidden></button>
  <button data-cov-decide="DEFERRED">Defer</button>
  <button data-cov-decide="NOT_COVERABLE">Not coverable yet</button>
 </md-dialog>
</section>`;

const cell = (language, status, extra = {}) =>
  ({language, status, ruleCount: 0, rules: [], decisionNote: null, decidedBy: null, ...extra});
const COLUMNS = [{key: 'JAVA', label: 'Java / Spring'}, {key: 'PYTHON', label: 'Python'}, {key: 'JAVASCRIPT', label: 'JS / TS'}, {key: 'OTHER', label: 'Other'}];
const rule = (name, reason = null) => ({id: 1, name, module: 'pmd', working: reason === null, reason});
const sql = {
  cwe: 89, label: 'CWE-89', name: '<img src=x onerror=alert(1)>', priority: 'CRITICAL', note: 'biggest risk',
  cells: [
    cell('JAVA', 'COVERED', {ruleCount: 12, rules: [rule('A'), rule('B')]}),
    cell('PYTHON', 'GAP'),
    cell('JAVASCRIPT', 'WEAK', {ruleCount: 1, rules: [rule('no-unsanitized', 'has not run in the last 30 days')]}),
    cell('OTHER', 'NONE')
  ]
};
const xss = {
  cwe: 79, label: 'CWE-79', name: 'Cross-site Scripting', priority: 'HIGH', note: null,
  cells: [cell('JAVA', 'NOT_COVERABLE', {decisionNote: 'needs taint tracking', decidedBy: 'alice'}), cell('PYTHON', 'NONE'),
    cell('JAVASCRIPT', 'NONE'), cell('OTHER', 'NONE')]
};
const table = (rows, counts = {covered: 1, weak: 1, gap: 1, decided: 1}) => ({columns: COLUMNS, rows, counts, catalogLoaded: true});

function setup(canModify, respond, hidden = false) {
  const dom = new JSDOM(`<body>${markup(canModify, hidden)}</body>`, {url: 'https://watchtower.example/rules/review-reports?view=coverage', runScripts: 'dangerously'});
  const w = dom.window;
  const requests = [];
  const timers = [];
  w.HTMLElement.prototype.show = function () { this.open = true; };
  w.HTMLElement.prototype.close = function () { this.open = false; };
  w.confirm = () => true;
  w.fetch = async (url, options = {}) => {
    requests.push({url, options, body: options.body ? Object.fromEntries(new w.URLSearchParams(options.body)) : null});
    const reply = respond(url, options);
    return {ok: reply.status === 200, status: reply.status, json: async () => reply.body};
  };
  w.setTimeout = (fn, ms) => { timers.push({fn, ms}); return timers.length; };
  w.clearTimeout = () => {};
  w.eval(script);
  const q = selector => w.document.querySelector(selector);
  const all = selector => [...w.document.querySelectorAll(selector)];
  return {w, requests, timers, q, all};
}

async function main() {
  // The table is drawn from the server's answer: one chip per cell, the profile chip and the counts.
  let coverage = table([sql, xss]);
  const editor = setup(true, () => ({status: 200, body: coverage}));
  await tick();
  assert.equal(editor.requests[0].url, '/rules/coverage');
  const chips = editor.all('[data-cov-chips] .wt-mini-chip').map(c => c.textContent);
  assert.ok(chips.some(text => text.includes('Profile · 2 CWEs')), chips.join('|'));
  assert.ok(chips.some(text => text.includes('Covered') && text.includes('1')));
  assert.ok(chips.some(text => text.includes('Gap')));
  assert.ok(chips.some(text => text.includes('Decided')));
  const heads = editor.all('[data-cov-table] thead th').map(th => th.textContent);
  assert.deepEqual(heads, ['Weakness', 'Java / Spring', 'Python', 'JS / TS', 'Other']);
  const firstRow = editor.q('[data-cov-table] tbody tr');
  assert.ok(firstRow.querySelector('th').textContent.endsWith('CWE-89 <img src=x onerror=alert(1)>'));
  assert.equal(firstRow.querySelector('th img'), null, 'a name from the server is text, never markup');
  const cells = [...firstRow.querySelectorAll('td')];
  assert.ok(cells[0].querySelector('.wt-mini-chip--ok'));
  assert.match(cells[0].querySelector('.wt-mini-chip').dataset.tip, /12 rules\nA · B · \+10 more/);
  assert.ok(cells[1].querySelector('button.wt-mini-chip--bad[data-cov-gap]'));
  assert.ok(cells[2].querySelector('.wt-mini-chip--warn'));
  assert.match(cells[2].querySelector('.wt-mini-chip').dataset.tip, /no-unsanitized: has not run in the last 30 days/);
  assert.equal(cells[3].textContent, '—');
  assert.equal(firstRow.querySelector('.rv-dot').classList.contains('wt-tone-danger'), true);

  // Opening a gap fills the dialog; deferring sends the decision with CSRF and redraws the table.
  editor.q('[data-cov-gap]').click();
  assert.equal(editor.q('[data-cov-gap-dialog]').open, true);
  assert.match(editor.q('[data-cov-gap-title]').textContent, /^CWE-89 · .* · Python$/);
  assert.equal(editor.q('[data-cov-clear]').hidden, true);
  // The assistant's "Suggest a rule" in this dialog reads which gap it is about, and starts with no old answer.
  assert.equal(editor.q('[data-cov-gap-dialog]').dataset.cwe, 'CWE-89');
  assert.equal(editor.q('[data-cov-gap-dialog]').dataset.language, 'PYTHON');
  assert.equal(editor.q('[data-gap-suggestion]').textContent, '');
  assert.equal(editor.q('[data-gap-suggest]').hidden, false);
  editor.q('[data-cov-note]').value = 'later';
  coverage = table([sql, xss], {covered: 1, weak: 1, gap: 0, decided: 2});
  editor.q('[data-cov-decide="DEFERRED"]').click();
  await tick();
  const decision = editor.requests[editor.requests.length - 1];
  assert.equal(decision.url, '/rules/coverage/decision');
  assert.equal(decision.options.method, 'POST');
  assert.equal(decision.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.deepEqual(decision.body, {cwe: 'CWE-89', language: 'PYTHON', decision: 'DEFERRED', note: 'later'});
  assert.equal(editor.q('[data-cov-gap-dialog]').open, false);

  // A cell that already has a decision can be changed or cleared.
  editor.all('[data-cov-gap]').filter(c => c.dataset.cwe === 'CWE-79')[0].click();
  assert.equal(editor.q('[data-cov-clear]').hidden, false);
  assert.equal(editor.q('[data-cov-note]').value, 'needs taint tracking');
  editor.q('[data-cov-clear]').click();
  await tick();
  const cleared = editor.requests[editor.requests.length - 1];
  assert.equal(cleared.url, '/rules/coverage/decision/clear');
  assert.deepEqual(cleared.body, {cwe: 'CWE-79', language: 'JAVA'});

  // A refused decision is explained inside the dialog and nothing closes.
  const failing = setup(true, (url, options) => (options.method === 'POST' ? {status: 400, body: {error: 'Add the weakness to the profile first.'}} : {status: 200, body: table([sql])}));
  await tick();
  failing.q('[data-cov-gap]').click();
  failing.q('[data-cov-decide="DEFERRED"]').click();
  await tick();
  assert.equal(failing.q('[data-cov-gap-error]').textContent, 'Add the weakness to the profile first.');
  assert.equal(failing.q('[data-cov-gap-dialog]').open, true);

  // Someone who cannot modify sees the same chips but nothing to click.
  const viewer = setup(false, () => ({status: 200, body: table([sql, xss])}));
  await tick();
  assert.equal(viewer.all('[data-cov-gap]').length, 0);
  assert.equal(viewer.all('[data-cov-open-profile]').length, 0);
  assert.ok(viewer.q('[data-cov-table] .wt-mini-chip--bad'), 'the gap is still shown');

  // An empty profile is a picture with the one-click Top 25; adding says how many were added.
  let empty = true;
  const starter = setup(true, (url, options) => {
    if (options.method === 'POST') { empty = false; return {status: 200, body: {added: 25, coverage: table([sql, xss])}}; }
    return {status: 200, body: empty ? table([], {covered: 0, weak: 0, gap: 0, decided: 0}) : table([sql, xss])};
  });
  await tick();
  assert.match(starter.q('[data-cov-table] .wt-empty-picture').textContent, /No CWE profile yet/);
  starter.q('[data-cov-top25]').click();
  await tick();
  const top = starter.requests[starter.requests.length - 1];
  assert.equal(top.url, '/rules/coverage/profile/top25');
  assert.equal(top.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(starter.all('[data-cov-table] tbody tr').length, 2);
  assert.equal(starter.q('[data-cov-profile-count-label]').textContent, '2 selected');
  assert.equal(starter.q('[data-rule-report-status]').textContent, 'Added 25 to the profile.');

  // Searching waits for a pause, then lists catalog matches; clicking one adds it with normal priority.
  const search = setup(true, url => {
    if (url.startsWith('/rules/coverage/search')) {
      return {status: 200, body: [{cwe: 918, label: 'CWE-918', name: 'Server-Side Request Forgery', discouraged: false},
        {cwe: 74, label: 'CWE-74', name: 'Injection', discouraged: true}]};
    }
    return {status: 200, body: table([sql, xss])};
  });
  await tick();
  const box = search.q('[data-cov-search]');
  box.value = 'request forgery';
  box.dispatchEvent(new search.w.Event('input', {bubbles: true}));
  assert.equal(search.timers.length, 1);
  assert.equal(search.requests.length, 1, 'nothing is asked until typing pauses');
  search.timers[0].fn();
  await tick();
  assert.equal(search.requests[1].url, '/rules/coverage/search?q=request%20forgery');
  const results = search.all('[data-cov-results] [data-cov-add]');
  assert.deepEqual(results.map(r => r.dataset.cwe), ['CWE-918', 'CWE-74']);
  assert.ok(results[1].classList.contains('wt-mini-chip--warn'), 'a weakness MITRE discourages is marked');
  results[0].click();
  await tick();
  const added = search.requests[search.requests.length - 1];
  assert.equal(added.url, '/rules/coverage/profile');
  assert.deepEqual(added.body, {cwe: 'CWE-918', priority: 'NORMAL'});
  assert.equal(search.q('[data-cov-search]').value, '');
  box.value = 'x';
  box.dispatchEvent(new search.w.Event('input', {bubbles: true}));
  search.timers[search.timers.length - 1].fn();
  await tick();
  assert.equal(search.requests.filter(r => r.url.startsWith('/rules/coverage/search')).length, 1, 'one character is not searched');

  // The dot changes the priority and keeps the note; the cross removes after a confirmation.
  const manage = setup(true, () => ({status: 200, body: table([sql, xss])}));
  await tick();
  manage.all('[data-cov-priority]')[0].click();
  await tick();
  const priority = manage.requests[manage.requests.length - 1];
  assert.deepEqual(priority.body, {cwe: 'CWE-89', priority: 'HIGH', note: 'biggest risk'});
  const before = manage.requests.length;
  manage.w.confirm = () => false;
  manage.all('[data-cov-remove]')[0].click();
  await tick();
  assert.equal(manage.requests.length, before, 'declining the confirmation changes nothing');
  manage.w.confirm = () => true;
  manage.all('[data-cov-remove]')[1].click();
  await tick();
  const removal = manage.requests[manage.requests.length - 1];
  assert.equal(removal.url, '/rules/coverage/profile/remove');
  assert.deepEqual(removal.body, {cwe: 'CWE-79'});

  // A failed load says so in the table area; a hidden tab asks for nothing.
  const broken = setup(true, () => ({status: 500, body: {}}));
  await tick();
  assert.match(broken.q('[data-cov-table]').textContent, /That did not work \(500\)/);
  const hidden = setup(true, () => ({status: 200, body: table([sql])}), true);
  await tick();
  assert.equal(hidden.requests.length, 0);
  console.log('cwe-coverage.test.js passed');
}

main().catch(error => { console.error(error); process.exit(1); });
