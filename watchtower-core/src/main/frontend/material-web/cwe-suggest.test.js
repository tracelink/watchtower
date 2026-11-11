const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const resources = path.resolve(__dirname, '../../resources/static/scripts');
const helpers = fs.readFileSync(path.join(resources, 'ai-helpers.js'), 'utf8');
const ruleWork = fs.readFileSync(path.join(resources, 'rule-work.js'), 'utf8');

const PAGE = `<!doctype html><body>
  <wt-assistant-drawer data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture"></wt-assistant-drawer>
  <span data-ai-helper="cwe" hidden><button type="button" data-work-cwe-open disabled>Suggest CWEs</button></span>
  <input type="checkbox" value="1" data-work-select aria-label="Select Unescaped output">
  <input type="checkbox" value="2" data-work-select aria-label="Select Debug print">
  <input type="checkbox" value="3" data-work-select aria-label="Select Untouched rule">
  <div id="cweSuggestDialog">
    <div data-cwe-list></div><div data-cwe-left></div><span data-cwe-status></span>
    <button type="button" data-cwe-apply disabled><span data-cwe-apply-label>Apply</span></button>
  </div></body>`;

function ok(body) { return {ok: true, status: 200, json: async () => body}; }
function fail(status, body) { return {ok: false, status, json: async () => body}; }
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

async function load(flags, respond) {
  const dom = new JSDOM(PAGE, {runScripts: 'dangerously', url: 'https://watchtower.example/rules/work?queue=setup'});
  const w = dom.window;
  const calls = [];
  w.fetch = async (url, options = {}) => {
    const call = {url, method: options.method || 'GET', headers: options.headers || {}, body: options.body ? JSON.parse(options.body) : null};
    calls.push(call);
    if (url === '/assistant/helpers') return ok(flags);
    return respond(call);
  };
  const dialog = w.document.getElementById('cweSuggestDialog');
  dialog.shown = 0;
  dialog.show = () => { dialog.shown += 1; };
  w.eval(ruleWork);
  w.eval(helpers);
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  await settle();
  return {w, doc: w.document, calls, dialog};
}

function tick(w, value) {
  const box = w.document.querySelector(`[data-work-select][value="${value}"]`);
  box.checked = true;
  box.dispatchEvent(new w.Event('change', {bubbles: true}));
}

async function main() {
  // A person who cannot use the helper never sees it.
  const off = await load({cwe: false}, () => ok({}));
  assert.equal(off.doc.querySelector('[data-ai-helper="cwe"]'), null);
  off.w.close();

  // Only the ticked rules are sent; answers are reviewed before anything is saved.
  const suggestions = {
    state: 'OK',
    suggestions: [
      {rule_id: 1, cwe: 'CWE-79', reason: 'It writes input into a page.', confidence: 'high'},
      {rule_id: 2, cwe: 'CWE-489', reason: 'Not clearly a weakness.', confidence: 'low'}
    ],
    skipped: {secret: 1, already_set: 0, missing: 0, unanswered: 0},
    stopped: null
  };
  const page = await load({cwe: true}, (call) => {
    if (call.url === '/assistant/cwe-suggestions') return ok(suggestions);
    if (call.url === '/rules/work/setup/cwes') return ok({changed: 2, skipped: 0});
    return ok({});
  });
  const {w, doc, calls, dialog} = page;
  const anchor = doc.querySelector('[data-ai-helper="cwe"]');
  const button = doc.querySelector('[data-work-cwe-open]');
  assert.equal(anchor.hidden, false, 'the helper shows when the server says it will work');
  assert.equal(button.disabled, true, 'nothing ticked: the button is disabled');

  tick(w, 1);
  tick(w, 2);
  assert.equal(button.disabled, false, 'ticking rules enables it, like the bulk button');
  button.click();
  await settle();
  const asked = calls.find((call) => call.url === '/assistant/cwe-suggestions');
  assert.deepEqual(asked.body, {ruleIds: [1, 2]}, 'the unticked rule is never sent');
  assert.equal(asked.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(dialog.shown, 1);

  const list = doc.querySelector('[data-cwe-list]');
  const boxes = list.querySelectorAll('input[type=checkbox]');
  assert.equal(boxes.length, 2);
  assert.equal(boxes[0].checked, true, 'a confident suggestion starts ticked');
  assert.equal(boxes[1].checked, false, 'a low-confidence suggestion starts unticked');
  assert.match(list.textContent, /Unescaped output/);
  assert.match(list.textContent, /CWE-79/);
  const reasons = Array.from(list.querySelectorAll('.wt-ai-reason')).map((p) => p.textContent);
  assert.deepEqual(reasons, ['It writes input into a page.', 'Not clearly a weakness.'], 'each suggestion says why, as text');
  assert.match(doc.querySelector('[data-cwe-left]').textContent, /1 secret rule left out/);
  const apply = doc.querySelector('[data-cwe-apply]');
  const label = doc.querySelector('[data-cwe-apply-label]');
  assert.equal(label.textContent, 'Apply 1 CWE');
  assert.equal(apply.disabled, false);
  assert.equal(calls.some((call) => call.url === '/rules/work/setup/cwes'), false, 'nothing is saved before Apply');

  // Keeping the low-confidence one too, then applying sends exactly the kept choices.
  boxes[1].checked = true;
  boxes[1].dispatchEvent(new w.Event('change'));
  assert.equal(label.textContent, 'Apply 2 CWEs');
  apply.click();
  await settle();
  const saved = calls.find((call) => call.url === '/rules/work/setup/cwes');
  assert.equal(saved.method, 'POST');
  assert.deepEqual(saved.body, {assignments: [{ruleId: 1, cwe: 'CWE-79'}, {ruleId: 2, cwe: 'CWE-489'}]});
  assert.equal(saved.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(doc.querySelector('[data-cwe-status]').textContent, 'Saved a CWE for 2 rules.');
  assert.equal(apply.disabled, true, 'it cannot be applied twice');
  w.close();

  // A used-up daily share keeps what was answered and says what was not.
  const partial = await load({cwe: true}, () => ok({
    state: 'OK', suggestions: [], skipped: {secret: 0, already_set: 0, missing: 0, unanswered: 3}, stopped: 'BUDGET'}));
  tick(partial.w, 1);
  partial.doc.querySelector('[data-work-cwe-open]').click();
  await settle();
  assert.match(partial.doc.querySelector('[data-cwe-left]').textContent, /daily AI budget is used up/);
  assert.match(partial.doc.querySelector('[data-cwe-list]').textContent, /No suggestions/);
  partial.w.close();

  // A refusal is shown in words, and Apply stays off.
  const refused = await load({cwe: true}, () => fail(429, {error: 'The daily AI budget for cwe suggestions is used up; try again tomorrow.'}));
  tick(refused.w, 1);
  refused.doc.querySelector('[data-work-cwe-open]').click();
  await settle();
  assert.match(refused.doc.querySelector('[data-cwe-list]').textContent, /used up; try again tomorrow/);
  assert.equal(refused.doc.querySelector('[data-cwe-apply]').disabled, true);
  refused.w.close();

  // A style rule can be answered "not a security rule"; it is applied with that outcome, and a missing catalog is said.
  const style = await load({cwe: true}, (call) => {
    if (call.url === '/assistant/cwe-suggestions') {
      return ok({state: 'OK', catalog: false, suggestions: [
        {rule_id: 1, outcome: 'cwe', cwe: 'CWE-79', cwe_name: 'CWE-79 · Cross-site Scripting', reason: 'It writes input into a page.', confidence: 'high'},
        {rule_id: 2, outcome: 'not_security', cwe: '', reason: 'A formatting rule.', confidence: 'high'}],
        skipped: {secret: 0, already_set: 0, missing: 0, unanswered: 0}, stopped: null});
    }
    if (call.url === '/rules/work/setup/cwes') return ok({changed: 2, skipped: 0});
    return ok({});
  });
  tick(style.w, 1);
  tick(style.w, 2);
  style.doc.querySelector('[data-work-cwe-open]').click();
  await settle();
  const styleList = style.doc.querySelector('[data-cwe-list]');
  assert.match(styleList.textContent, /Not a security rule/);
  assert.match(style.doc.querySelector('[data-cwe-left]').textContent, /Not checked against the MITRE catalog/);
  assert.match(styleList.querySelector('input[value="2"]').getAttribute('aria-label'), /not a security rule/i);
  assert.equal(style.doc.querySelector('[data-cwe-apply-label]').textContent, 'Apply 2 answers');
  style.doc.querySelector('[data-cwe-apply]').click();
  await settle();
  const styleSaved = style.calls.find((call) => call.url === '/rules/work/setup/cwes');
  assert.deepEqual(styleSaved.body, {assignments: [{ruleId: 1, cwe: 'CWE-79'}, {ruleId: 2, cwe: '', outcome: 'not_security'}]});
  assert.equal(style.doc.querySelector('[data-cwe-status]').textContent, 'Saved 2 rules.');
  style.w.close();

  console.log('Rule work: suggest CWEs, review and apply tests passed');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
