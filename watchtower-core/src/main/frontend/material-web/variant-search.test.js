const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const fragment = fs.readFileSync(path.join(resources, 'templates/fragments/missedcase.html'), 'utf8');
const markup = fragment.match(/<md-dialog th:fragment="variant"[\s\S]*?<\/md-dialog>/)[0];
const CASE = '0f0e0d0c-0b0a-4900-8000-000000000001';
const SEARCH = '11111111-2222-4333-8444-555555555555';

async function main() {
  const dom = new JSDOM(`<body><button data-variant-open="${CASE}" data-case-summary="CWE-89 in src/OrderDao.java:3" data-rule-id="42">Find similar code</button>${markup}</body>`,
    {url: 'https://watchtower.example/configuration/repository/7', runScripts: 'dangerously'});
  const w = dom.window;
  const dialog = w.document.querySelector('[data-variant-dialog]');
  Object.assign(dialog.dataset, {csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'});
  dialog.show = async () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; };
  const requests = [];
  let started = false;
  const repos = Array.from({length: 30}, (_, i) => ({id: i + 1, name: i === 0 ? '<img src=x onerror=alert(1)>' : 'repo-' + i, integration: 'bb', default_branch: 'main'}));
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    const reply = body => ({ok: true, status: 200, json: async () => body});
    if (url.startsWith('/repository/evidence/variants/repositories')) return reply(repos);
    if (url === '/repository/evidence/variants/case/' + CASE) return reply(started ? [{id: SEARCH}] : []);
    if (url === '/repository/evidence/variants/' + SEARCH) return reply({id: SEARCH, status: 'DONE', total_matches: 1, rule_id: 42, candidate_id: null, requested_by: 'steward',
      repositories: [{repository: 'billing-service', commit: 'c'.repeat(40), status: 'COMPLETE', error: null, matches: 1, truncated: false, locations: [{path: 'src/<b>InvoiceDao</b>.java', line: 88}]},
        {repository: 'big-monolith', commit: null, status: 'SKIPPED', error: 'SOURCE_UNAVAILABLE', matches: 0, truncated: false, locations: []}]});
    if (url.endsWith('/proposal')) return reply({status: 'READY', explanation: 'Compared both commits.', line: 3, recorded_line_changed: true,
      excerpt: [{line: 3, text: 'return "SELECT * FROM orders WHERE id = " + id; <script>', changed: true, recorded: true}],
      fixtures: [{expected: 'MATCH', reference: 'missed/' + CASE + '/vulnerable-OrderDao.java', sha256: 'a'.repeat(64), commit: 'a'.repeat(40)},
        {expected: 'NO_MATCH', reference: 'missed/' + CASE + '/fixed-OrderDao.java', sha256: 'b'.repeat(64), commit: 'b'.repeat(40)}]});
    if (url.endsWith('/fixtures')) return reply({fixtures: ['f1', 'f2']});
    if (url === '/repository/evidence/variants' && options.method === 'POST') { started = true; return reply({id: SEARCH}); }
    return {ok: false, status: 404, json: async () => ({error: 'Not found'})};
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/variant-search.js'), 'utf8'));
  const settle = () => new Promise(resolve => setTimeout(resolve, 0));
  const q = name => dialog.querySelector('[data-variant-' + name + ']');
  w.document.querySelector('[data-variant-open]').click();
  await settle(); await settle();
  assert.match(q('case').textContent, /CWE-89 in src\/OrderDao.java:3/);
  assert.equal(q('rule').value, '42');
  assert.equal(dialog.dataset.caseId, CASE, 'the open case is on the dialog so the AI fixture helper can find it');
  // Three numbered steps, each one line with its button; the details are the buttons' hover text.
  const steps = [...dialog.querySelectorAll('.wt-variant-step')].map(step =>
    step.querySelector('.wt-step-number').textContent + '. ' + step.querySelector('strong').textContent);
  assert.deepEqual(steps, ['1. Compare the commits', '2. Save as regression tests', '3. Search other repositories']);
  assert.deepEqual([...dialog.querySelectorAll('.wt-variant-step button:not([hidden])')].map(b => b.textContent.trim()),
    ['differenceCompare', 'scienceSave tests', 'travel_exploreStart search']);
  assert.match(q('start').dataset.tip, /same rule and commits always give the same results/);
  assert.match(q('start').dataset.tip, /not confirmed vulnerabilities/);
  assert.equal(q('repositories').querySelector('img'), null);

  q('compare').click(); await settle(); await settle();
  assert.match(q('proposal').textContent, /recorded line 3 is part of the fix/);
  assert.equal(q('proposal').querySelector('script'), null);
  assert.equal(q('proposal').querySelector('.is-changed').textContent.includes('SELECT'), true);
  assert.match(q('proposal').textContent, /Must be flagged: missed\/.*vulnerable-OrderDao.java/);
  assert.match(q('proposal').textContent, /Must stay clean: missed\/.*fixed-OrderDao.java/);

  q('save-tests').click(); await settle(); await settle();
  const saved = requests.find(r => r.url.endsWith('/fixtures'));
  assert.deepEqual(JSON.parse(saved.options.body), {ruleId: 42});
  assert.equal(saved.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.match(q('status').textContent, /2 regression tests saved for rule 42/);

  q('start').click(); await settle();
  assert.match(q('status').textContent, /Choose at least one repository/);
  const boxes = [...q('repositories').querySelectorAll('input[type=checkbox]')];
  boxes.forEach(box => { box.checked = true; box.dispatchEvent(new w.Event('change')); });
  assert.match(q('selected').textContent, /^25 of 25 repositories chosen/);
  assert.match(q('status').textContent, /at most 25 repositories/);
  q('start').click(); await settle(); await settle(); await settle();
  const start = requests.find(r => r.url === '/repository/evidence/variants' && r.options.method === 'POST');
  const startBody = JSON.parse(start.options.body);
  assert.equal(startBody.repositoryIds.length, 25);
  assert.equal(startBody.caseId, CASE); assert.equal(startBody.ruleId, 42); assert.equal(startBody.candidateId, null);
  assert.equal(start.options.headers['X-CSRF-TOKEN'], 'fixture');
  const results = q('searches').textContent;
  assert.match(results, /Finished\. 1 places to review · rule 42 as it is now/);
  assert.match(results, /billing-service @ cccccccccc: Searched · 1 match/);
  assert.match(results, /src\/<b>InvoiceDao<\/b>.java:88/);
  assert.equal(q('searches').querySelector('b'), null);
  assert.match(results, /big-monolith @ not pinned yet: Not searched because the code could not be downloaded/);
  q('close').click();
  assert.equal(dialog.open, false);
  w.close();
  console.log('Find similar code: explained steps, safe rendering, CSRF, 25-repository cap and plain-language results passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
