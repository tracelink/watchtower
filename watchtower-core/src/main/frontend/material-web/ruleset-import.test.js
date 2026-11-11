const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// Ruleset import (UAT #26): Import stays disabled until a clean server preview of the chosen file.
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/rulesets.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <form id="importModalForm" action="https://watchtower.example/rulesets/53/import" method="post">
    <input type="file" name="file" data-import-file><input type="hidden" name="_csrf" value="fixture">
    <div data-import-preview></div>
  </form>
  <button type="submit" form="importModalForm" data-import-submit disabled>Import</button>
</body>`, {url: 'https://watchtower.example/rulesets/53', runScripts: 'dangerously'});
const w = dom.window;
const requests = [];
let reply = {status: 200, body: {rulesetName: '<b>Team</b>', existingRuleset: true, newRules: 2, updatedRules: 1,
  priorityOnlyRules: 0, removedFromRuleset: ['Old rule'], removedCount: 1, problems: []}};
w.fetch = async (url, options) => { requests.push({url, options}); return {ok: reply.status === 200, json: async () => reply.body}; };
w.eval(script);
const tick = async () => { for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0)); };
const file = w.document.querySelector('[data-import-file]');
const submit = w.document.querySelector('[data-import-submit]');
const preview = w.document.querySelector('[data-import-preview]');
const choose = async () => {
  Object.defineProperty(file, 'files', {value: [new w.File(['{}'], 'export.json')], configurable: true});
  file.dispatchEvent(new w.Event('change'));
  await tick();
};

(async () => {
  await choose();
  assert.equal(requests[0].url, 'https://watchtower.example/rulesets/53/import/preview');
  assert.equal(requests[0].options.method, 'POST');
  assert.equal(requests[0].options.body.get('_csrf'), 'fixture');
  assert.equal(preview.querySelector('b'), null);
  assert.match(preview.textContent, /Updates the existing ruleset "<b>Team<\/b>"/);
  assert.match(preview.textContent, /2 new rules/);
  assert.match(preview.textContent, /1 rules removed from this ruleset \(not deleted\): Old rule/);
  assert.equal(submit.disabled, false);

  reply = {status: 200, body: {rulesetName: 'Team', existingRuleset: false, newRules: 0, updatedRules: 0,
    priorityOnlyRules: 0, removedFromRuleset: [], removedCount: 0, problems: ['Rule X already belongs to the PMD module.']}};
  await choose();
  assert.match(preview.textContent, /Import is blocked until these are fixed:Rule X already belongs to the PMD module\./);
  assert.equal(submit.disabled, true);

  // A slow preview for the previous file cannot enable import for the newly selected file.
  const pending = [];
  const normalFetch = w.fetch;
  w.fetch = () => new Promise(resolve => pending.push(resolve));
  const first = choose();
  const second = choose();
  const valid = {rulesetName: 'Old file', existingRuleset: false, newRules: 0, updatedRules: 0,
    priorityOnlyRules: 0, removedFromRuleset: [], removedCount: 0, problems: []};
  pending[0]({ok: true, json: async () => valid});
  await first;
  assert.equal(submit.disabled, true);
  assert.doesNotMatch(preview.textContent, /Old file/);
  pending[1]({ok: false, json: async () => ({error: 'New file is invalid.'})});
  await second;
  assert.equal(preview.textContent, 'New file is invalid.');
  assert.equal(submit.disabled, true);
  const submission = new w.Event('submit', {cancelable: true});
  w.document.querySelector('form').dispatchEvent(submission);
  assert.equal(submission.defaultPrevented, true);
  w.fetch = normalFetch;

  reply = {status: 400, body: {error: 'This is not a Watchtower ruleset export.'}};
  await choose();
  assert.equal(preview.textContent, 'This is not a Watchtower ruleset export.');
  assert.equal(submit.disabled, true);
  console.log('Ruleset import: preview before import, escaped names, blocking problems and unreadable files passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
