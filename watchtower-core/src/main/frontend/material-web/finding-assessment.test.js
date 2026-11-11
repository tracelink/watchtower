const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const fragment = fs.readFileSync(path.join(resources, 'templates/feedback/review.html'), 'utf8');
const tick = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise(resolve => setTimeout(resolve, 0)); };

async function main() {
  const dom = new JSDOM(`<body><button data-feedback-open>Feedback</button>${fragment}</body>`, {url: 'https://watchtower.example/', runScripts: 'dangerously'});
  const w = dom.window;
  const d = w.document.querySelector('[data-feedback-dialog]');
  Object.assign(d.dataset, {scanType: 'pull_request', scanId: '5', csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'});
  const selection = d.querySelector('[data-feedback-selection]');
  selection.replaceChildren();
  for (const key of ['9', '10']) { const box = w.document.createElement('input'); box.type = 'checkbox'; box.value = key; box.checked = true; selection.appendChild(box); }
  const requests = [];
  let reply = {state: 'ASSESSED', verdict: 'LIKELY_FALSE_POSITIVE', model: 'fixture-model', created_at: Date.UTC(2026, 9, 14), note: 'Advisory only.',
    cited_lines: [81, 88], knowledge_ids: ['K-7'],
    criteria: {input_reaches_sink: {answer: 'yes', reason: '<img src=x onerror=alert(1)> reaches line 88'}, sanitized: {answer: 'yes', reason: 'Escaped on line 86.'},
      test_or_generated_code: {answer: 'no', reason: 'Production code.'}, matches_rule_intent: {answer: 'yes', reason: 'Unescaped HTML output.'}}};
  let status = 200;
  w.fetch = async (url, options = {}) => { requests.push({url, options}); return {ok: status === 200, status, json: async () => reply}; };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/finding-assessment.js'), 'utf8'));
  const ask = d.querySelector('[data-assessment-ask]');
  const result = d.querySelector('[data-assessment-result]');
  assert.equal(requests.length, 0, 'nothing is fetched until the person asks');
  ask.click(); await tick();
  assert.match(result.textContent, /Select exactly one finding/);
  assert.equal(requests.length, 0);
  selection.querySelectorAll('input')[1].checked = false;
  ask.click(); await tick();
  assert.equal(requests[0].url, '/finding-assessment');
  assert.deepEqual(JSON.parse(requests[0].options.body), {scanType: 'pull_request', scanId: 5, findingKey: '9'});
  assert.equal(requests[0].options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.match(result.textContent, /AI \(advisory\): Likely false positive/);
  assert.match(result.textContent, /Input reaches sink: yes — <img src=x onerror=alert\(1\)> reaches line 88/);
  assert.match(result.textContent, /Cites lines 81, 88; approved knowledge K-7\. fixture-model/);
  assert.equal(result.querySelector('img'), null);
  // Changing the selection or reopening never shows an answer for another finding.
  selection.querySelector('input').dispatchEvent(new w.Event('change', {bubbles: true}));
  assert.equal(result.textContent, '');
  reply = {state: 'INSUFFICIENT_EVIDENCE', message: 'This rule detects secrets. Findings of secret rules are never sent to the AI.'};
  ask.click(); await tick();
  assert.match(result.textContent, /never sent to the AI/);
  w.document.querySelector('[data-feedback-open]').click();
  assert.equal(result.textContent, '');
  // A slow answer for one finding never lands under another; the button is disabled while asking.
  reply = {state: 'ASSESSED', verdict: 'LIKELY_TRUE_POSITIVE', model: 'm', created_at: 0, note: 'n', cited_lines: [], knowledge_ids: [], criteria: {}};
  let release;
  w.fetch = async (url, options = {}) => { requests.push({url, options}); await new Promise(r => { release = r; }); return {ok: true, status: 200, json: async () => reply}; };
  ask.click(); await tick(2);
  assert.equal(ask.disabled, true);
  selection.querySelector('input').dispatchEvent(new w.Event('change', {bubbles: true}));
  release(); await tick();
  assert.equal(result.textContent, '', 'the late answer is dropped');
  assert.equal(ask.disabled, false);
  w.fetch = async (url, options = {}) => { requests.push({url, options}); return {ok: status === 200, status, json: async () => reply}; };
  status = 429; reply = {error: 'The daily AI budget is used up; try again tomorrow.'};
  ask.click(); await tick();
  assert.match(result.textContent, /daily AI budget is used up/);
  console.log('Finding assessment: on-request only, one finding, CSRF, safe rendering, no carry-over and errors passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
