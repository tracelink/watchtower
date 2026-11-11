const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/cwe-starter.js'), 'utf8');
const tick = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise(resolve => setTimeout(resolve, 0)); };

const markup = `
<button data-cwe-starter-open>Fill from starter map</button>
<md-dialog data-cwe-starter-dialog data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">
 <div data-starter-chips></div><div data-starter-list></div><span data-starter-status></span>
 <button data-starter-apply disabled><span data-starter-apply-label>Apply</span></button>
</md-dialog>`;

const proposal = (id, name) => ({ruleId: id, name, module: 'pmd', cwe: 'CWE-390', cweName: 'Detection of Error Condition Without Action'});

function setup(respond) {
  const dom = new JSDOM(`<body>${markup}</body>`, {url: 'https://watchtower.example/rules/work?queue=setup', runScripts: 'dangerously'});
  const w = dom.window;
  const requests = [];
  const timers = [];
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    const reply = respond(options);
    return {ok: reply.status === 200, status: reply.status, json: async () => reply.body};
  };
  w.setTimeout = (fn, ms) => { timers.push({fn, ms}); return timers.length; };
  w.eval(script);
  const q = selector => w.document.querySelector(selector);
  return {w, requests, timers, q, all: selector => [...w.document.querySelectorAll(selector)]};
}

async function main() {
  // Opening the dialog previews the rules that would get a CWE; text from the server stays text.
  const page = setup(options => (options.method === 'POST'
    ? {status: 200, body: {changed: 2, coverage: {}}}
    : {status: 200, body: {proposals: [proposal(1, 'EmptyCatchBlock'), proposal(2, '<img src=x onerror=alert(1)>')], skippedUnknownCwe: 1}}));
  page.q('[data-cwe-starter-open]').click();
  await tick();
  assert.equal(page.requests[0].url, '/rules/coverage/starter');
  assert.equal(page.requests[0].options.method, undefined);
  assert.equal(page.all('[data-starter-list] tbody tr').length, 2);
  assert.equal(page.q('[data-starter-list] img'), null);
  assert.match(page.q('[data-starter-chips]').textContent, /2 rules would get a CWE/);
  assert.match(page.q('[data-starter-chips]').textContent, /1 skipped/);
  assert.equal(page.q('[data-starter-list] .wt-mini-chip').dataset.tip, 'Detection of Error Condition Without Action');
  assert.equal(page.q('[data-starter-apply]').disabled, false);
  assert.equal(page.q('[data-starter-apply-label]').textContent, 'Apply to 2 rules');

  // Apply posts with CSRF, says what changed and reloads the list after a moment.
  page.q('[data-starter-apply]').click();
  await tick();
  const post = page.requests[1];
  assert.equal(post.options.method, 'POST');
  assert.equal(post.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(page.q('[data-starter-status]').textContent, 'Updated 2 rules.');
  assert.equal(page.timers.length, 1);
  assert.equal(page.q('[data-starter-apply]').disabled, true, 'a second press while reloading does nothing');

  // Nothing to fill: the button stays off. A long list shows the first rows and counts the rest.
  const none = setup(() => ({status: 200, body: {proposals: [], skippedUnknownCwe: 0}}));
  none.q('[data-cwe-starter-open]').click();
  await tick();
  assert.equal(none.q('[data-starter-apply]').disabled, true);
  assert.match(none.q('[data-starter-chips]').textContent, /0 rules would get a CWE/);
  const many = setup(() => ({status: 200, body: {proposals: Array.from({length: 230}, (_, i) => proposal(i + 1, 'rule-' + i)), skippedUnknownCwe: 0}}));
  many.q('[data-cwe-starter-open]').click();
  await tick();
  assert.equal(many.all('[data-starter-list] tbody tr').length, 50);
  assert.match(many.q('[data-starter-list]').textContent, /\+ 180 more/);

  // A refusal (the catalog is not loaded) is shown plainly and nothing can be applied.
  const refused = setup(() => ({status: 400, body: {error: 'Load the CWE catalog on the Knowledge page first.'}}));
  refused.q('[data-cwe-starter-open]').click();
  await tick();
  assert.equal(refused.q('[data-starter-status]').textContent, 'Load the CWE catalog on the Knowledge page first.');
  assert.equal(refused.q('[data-starter-apply]').disabled, true);

  // A failed apply re-enables the button so it can be tried again.
  const failing = setup(options => (options.method === 'POST'
    ? {status: 400, body: {error: '0 rules were updated before this stopped: Select between 1 and 100 rules.'}}
    : {status: 200, body: {proposals: [proposal(1, 'EmptyCatchBlock')], skippedUnknownCwe: 0}}));
  failing.q('[data-cwe-starter-open]').click();
  await tick();
  failing.q('[data-starter-apply]').click();
  await tick();
  assert.match(failing.q('[data-starter-status]').textContent, /stopped/);
  assert.equal(failing.q('[data-starter-apply]').disabled, false);
  console.log('cwe-starter.test.js passed');
}

main().catch(error => { console.error(error); process.exit(1); });
