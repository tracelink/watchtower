const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// Setup gaps: ticking rules (or the page) enables one "Set owner and CWE for selected" button.
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/rule-work.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <input type="checkbox" data-work-select-all>
  <span data-work-selected></span>
  <button type="button" data-work-bulk-open disabled>Set owner and CWE for selected</button>
  <span data-work-bulk-count></span>
  <input type="checkbox" name="ruleId" value="1" data-work-select>
  <input type="checkbox" name="ruleId" value="2" data-work-select>
  <input type="checkbox" name="ruleId" value="3" data-work-select></body>`, {runScripts: 'dangerously'});
const w = dom.window;
const doc = w.document;
w.eval(script);
doc.dispatchEvent(new w.Event('DOMContentLoaded'));
const button = doc.querySelector('[data-work-bulk-open]');
const page = doc.querySelector('[data-work-select-all]');
const rows = doc.querySelectorAll('[data-work-select]');
assert.equal(button.disabled, true, 'nothing ticked: the bulk button is disabled');

rows[0].checked = true;
rows[0].dispatchEvent(new w.Event('change', {bubbles: true}));
assert.equal(button.disabled, false);
assert.equal(doc.querySelector('[data-work-selected]').textContent, '1 selected');
assert.equal(doc.querySelector('[data-work-bulk-count]').textContent, '1 rule selected');
assert.equal(page.indeterminate, true, 'some ticked: the page box is mixed');

page.checked = true;
page.dispatchEvent(new w.Event('change', {bubbles: true}));
assert.ok(Array.from(rows).every((row) => row.checked), 'the page box ticks every row');
assert.equal(doc.querySelector('[data-work-bulk-count]').textContent, '3 rules selected');

page.checked = false;
page.dispatchEvent(new w.Event('change', {bubbles: true}));
assert.equal(button.disabled, true);
console.log('Rule work: bulk owner and CWE selection');
