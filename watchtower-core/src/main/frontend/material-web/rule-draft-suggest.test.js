const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const helpers = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/ai-helpers.js'), 'utf8');

const PAGE = `<!doctype html><body>
  <wt-assistant-drawer data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture"></wt-assistant-drawer>
  <md-dialog id="gap" data-cwe="CWE-89" data-language="PYTHON">
    <div data-gap-suggestion></div>
    <div><span data-ai-helper="ruleDraft" hidden><button type="button" data-gap-suggest>Suggest a rule</button></span></div>
  </md-dialog></body>`;
const DRAFT = '5d1c5a0e-0000-4000-8000-000000000001';

function ok(body) { return {ok: true, status: 200, json: async () => body}; }
function fail(status, body) { return {ok: false, status, json: async () => body}; }
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

async function load(flags, respond) {
  const dom = new JSDOM(PAGE, {runScripts: 'dangerously', url: 'https://watchtower.example/rules/review-reports?view=coverage'});
  const w = dom.window;
  const calls = [];
  w.fetch = async (url, options = {}) => {
    const call = {url, method: options.method || 'GET', headers: options.headers || {}, body: options.body ? JSON.parse(options.body) : null};
    calls.push(call);
    if (url === '/assistant/helpers') return ok(flags);
    return respond(call);
  };
  w.eval(helpers);
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  await settle();
  return {w, doc: w.document, calls};
}

async function main() {
  // Nobody without the grants (or with the feature off) ever sees the button.
  const off = await load({ruleDraft: false}, () => ok({}));
  assert.equal(off.doc.querySelector('[data-ai-helper="ruleDraft"]'), null);
  off.w.close();

  // The gap the dialog is about is sent; the draft opens in the designer through a checked link.
  const good = await load({ruleDraft: true}, () => ok({state: 'OK', draft_id: DRAFT, engine: 'opengrep', reason: 'It can follow data into the query.',
    url: `/designer/opengrep?draft=${DRAFT}`}));
  const button = good.doc.querySelector('[data-gap-suggest]');
  assert.equal(good.doc.querySelector('[data-ai-helper="ruleDraft"]').hidden, false);
  button.click();
  assert.equal(button.disabled, true, 'a second press while asking does nothing');
  await settle();
  const post = good.calls.find((call) => call.url === '/assistant/rule-drafts');
  assert.equal(post.method, 'POST');
  assert.equal(post.headers['X-CSRF-TOKEN'], 'fixture');
  assert.deepEqual(post.body, {cwe: 'CWE-89', language: 'PYTHON'});
  const area = good.doc.querySelector('[data-gap-suggestion]');
  assert.match(area.textContent, /Suggested scanner: Opengrep/);
  assert.match(area.querySelector('.wt-mini-chip').dataset.tip, /It can follow data into the query\. You can switch scanner in the designer\. Nothing is saved yet\./);
  const link = area.querySelector('a');
  assert.equal(link.getAttribute('href'), `/designer/opengrep?draft=${DRAFT}`);
  assert.match(link.textContent, /Open in the designer/);
  assert.equal(button.disabled, false);
  good.w.close();

  // A link that is not a designer draft link is never followed.
  for (const url of ['https://evil.example/designer/regex?draft=' + DRAFT, '/designer/checkov?draft=' + DRAFT, '/designer/regex', 'javascript:alert(1)', undefined]) {
    const bad = await load({ruleDraft: true}, () => ok({state: 'OK', engine: 'regex', reason: 'x', url}));
    bad.doc.querySelector('[data-gap-suggest]').click();
    await settle();
    assert.equal(bad.doc.querySelector('[data-gap-suggestion] a'), null, String(url));
    assert.match(bad.doc.querySelector('[data-gap-suggestion]').textContent, /could not be opened/);
    bad.w.close();
  }

  // Refusals and failures are explained in words, and the text stays text.
  const blocked = await load({ruleDraft: true}, () => ok({state: 'BLOCKED', message: 'Rules about secrets are never drafted by the assistant.'}));
  blocked.doc.querySelector('[data-gap-suggest]').click();
  await settle();
  assert.match(blocked.doc.querySelector('[data-gap-suggestion]').textContent, /never drafted/);
  blocked.w.close();
  const budget = await load({ruleDraft: true}, () => fail(429, {message: 'The daily AI budget for rule drafts is used up; try again tomorrow.'}));
  budget.doc.querySelector('[data-gap-suggest]').click();
  await settle();
  assert.match(budget.doc.querySelector('[data-gap-suggestion]').textContent, /used up/);
  assert.equal(budget.doc.querySelector('[data-gap-suggest]').disabled, false);
  budget.w.close();
  const markup = await load({ruleDraft: true}, () => ok({state: 'UNUSABLE', message: '<img src=x onerror=alert(1)> Nothing was saved.'}));
  markup.doc.querySelector('[data-gap-suggest]').click();
  await settle();
  assert.equal(markup.doc.querySelector('[data-gap-suggestion] img'), null);
  markup.w.close();

  // Without a gap chosen there is nothing to ask about.
  const none = await load({ruleDraft: true}, () => ok({}));
  none.doc.getElementById('gap').dataset.cwe = '';
  none.doc.querySelector('[data-gap-suggest]').click();
  await settle();
  assert.equal(none.calls.filter((call) => call.url === '/assistant/rule-drafts').length, 0);
  none.w.close();
  console.log('rule-draft-suggest.test.js passed');
}

main().catch((error) => { console.error(error); process.exit(1); });
