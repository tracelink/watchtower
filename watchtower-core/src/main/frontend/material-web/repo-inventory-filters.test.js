// Code repositories (Fixes board, 2026-10-22): Scan selected appears only once rows are ticked,
// and the search pill filters as you type, keeping the focus after the results swap.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const repoScan = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/repo-scan.js'), 'utf8');

const dom = new JSDOM(`<!doctype html><body>
  <div data-repo-scan>
    <form data-filter-form><input type="search" name="q" data-repository-search></form>
    <input type="checkbox" class="wt-repo-select" value="7">
    <button type="button" data-no-selection>Add repository</button>
    <button type="button" data-requires-selection data-hide-unselected data-no-matching disabled hidden>Scan selected</button>
  </div></body>`, {runScripts: 'outside-only', pretendToBeVisual: true});
const w = dom.window;
w.eval(repoScan);
w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
const document = w.document;

const box = document.querySelector('.wt-repo-select');
const scanSelected = document.querySelector('[data-hide-unselected]');
const add = document.querySelector('[data-no-selection]');
assert.equal(scanSelected.hidden, true, 'no disabled grey button before anything is ticked');
box.checked = true;
box.dispatchEvent(new w.Event('change', {bubbles: true}));
assert.equal(scanSelected.hidden, false, 'Scan selected appears once a row is ticked');
assert.equal(scanSelected.disabled, false);
assert.equal(add.hidden, true, 'and replaces Add repository');
box.checked = false;
box.dispatchEvent(new w.Event('change', {bubbles: true}));
assert.equal(scanSelected.hidden, true);
assert.equal(add.hidden, false);
console.log('Repositories: Scan selected shows only for a selection, in place of Add repository');

(async () => {
  const form = document.querySelector('[data-filter-form]');
  let submitted = 0;
  form.requestSubmit = () => { submitted += 1; };
  const search = document.querySelector('[data-repository-search]');
  search.value = 'pay';
  search.dispatchEvent(new w.Event('input', {bubbles: true}));
  search.value = 'payments';
  search.dispatchEvent(new w.Event('input', {bubbles: true}));
  assert.equal(submitted, 0, 'waits for typing to pause');
  await new Promise((resolve) => setTimeout(resolve, 450));
  assert.equal(submitted, 1, 'one search for a burst of typing');
  // htmx swaps the region: the new field gets the focus and the caret at the end.
  const swapped = search.cloneNode();
  swapped.value = 'payments';
  search.replaceWith(swapped);
  document.dispatchEvent(new w.Event('htmx:afterSettle'));
  assert.equal(document.activeElement, swapped, 'typing carries on in the new field');
  assert.equal(swapped.selectionStart, 'payments'.length);
  console.log('Repositories: the search pill filters as you type and keeps the focus');
})().catch((error) => { console.error(error); process.exit(1); });
