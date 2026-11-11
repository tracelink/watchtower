const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/rule-edit.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <input data-rule-search><span data-rule-search-status></span>
  <div role="tablist"><button data-rule-kind-filter="custom" aria-selected="true"></button>
    <button data-rule-kind-filter="provided" aria-selected="false"></button></div>
  <nav data-rule-list>${Array.from({length: 12}, (_, index) =>
    `<a data-rule-link data-rule-kind="custom">${index === 0 ? 'AlphaRule1' : index === 1 ? 'BetaRule2' : `Custom${index + 1}`}</a>`).join('')}
    ${Array.from({length: 12}, (_, index) =>
    `<a data-rule-link data-rule-kind="provided">Provided${index + 1}</a>`).join('')}</nav>
  <nav class="wt-client-pagination"><p data-rule-page-status></p><button data-rule-page-previous>Previous</button>
  <button data-rule-page-next>Next</button></nav>
  <section data-rule-detail><form><input name="message"></form></section>
  <button data-wt-dialog-target="#deleteRuleModal" data-action="/delete"
    data-id="4" data-name="&lt;img src=x&gt;" data-rulesets="It has one ruleset."></button>
  <div id="deleteRuleModal"></div><button id="cancelDeleteRuleModal"></button>
  <form id="deleteModalForm"><p id="deleteModalContent"></p><input id="deleteModalInput"></form>
  <button data-wt-dialog-target="#stewardshipModal"></button>
  <div id="stewardshipModal"></div><button id="cancelStewardshipModal"></button>
  <form id="stewardshipForm"><input name="owner"></form>
</body>`, {runScripts: 'dangerously'});

const dialog = dom.window.document.getElementById('deleteRuleModal');
dialog.show = () => { dialog.dataset.open = 'true'; };
dialog.close = () => { delete dialog.dataset.open; };
const stewardshipDialog = dom.window.document.getElementById('stewardshipModal');
stewardshipDialog.show = () => { stewardshipDialog.dataset.open = 'true'; };
stewardshipDialog.close = () => { delete stewardshipDialog.dataset.open; };
dom.window.eval(script);

const document = dom.window.document;
assert.equal(document.querySelector('[data-rule-search-status]').textContent, '12 custom rules shown');
assert.equal(document.querySelector('[data-rule-page-status]').textContent, '1\u201310 of 12');
assert.equal(document.querySelector('.wt-client-pagination').hidden, false, 'two pages show the pager');
assert.equal(document.querySelectorAll('[data-rule-link]')[10].hidden, true);
assert.equal(document.querySelectorAll('[data-rule-link]')[12].hidden, true);
document.querySelector('[data-rule-page-next]').click();
assert.equal(document.querySelector('[data-rule-page-status]').textContent, '11\u201312 of 12');
document.querySelector('[data-rule-kind-filter="provided"]').click();
assert.equal(document.querySelector('[data-rule-search-status]').textContent, '12 provided rules shown');
assert.equal(document.querySelector('[data-rule-page-status]').textContent, '1\u201310 of 12');
assert.equal(document.querySelectorAll('[data-rule-link]')[0].hidden, true);
assert.equal(document.querySelectorAll('[data-rule-link]')[12].hidden, false);
const search = document.querySelector('[data-rule-search]');
search.value = 'provided12';
search.dispatchEvent(new dom.window.Event('input'));
assert.equal(document.querySelectorAll('[data-rule-link]')[0].hidden, true);
assert.equal(document.querySelectorAll('[data-rule-link]')[23].hidden, false);
assert.equal(document.querySelector('[data-rule-page-status]').textContent, '1\u20131 of 1');
assert.equal(document.querySelector('.wt-client-pagination').hidden, true, 'one page hides the pager');
search.value = 'no such rule';
search.dispatchEvent(new dom.window.Event('input'));
assert.equal(document.querySelector('.wt-client-pagination').hidden, true, 'an empty list shows no "0-0 of 0" pager');
search.value = '';
search.dispatchEvent(new dom.window.Event('input'));

document.querySelector('[data-wt-dialog-target]').click();
assert.equal(dialog.dataset.open, 'true');
assert.equal(document.querySelector('#deleteModalContent img'), null);
assert.match(document.querySelector('#deleteModalContent').textContent, /<img src=x>/);
assert.equal(document.querySelector('#deleteModalInput').value, '4');

document.querySelector('[data-wt-dialog-target="#stewardshipModal"]').click();
assert.equal(stewardshipDialog.dataset.open, 'true');
document.querySelector('#cancelStewardshipModal').click();
assert.equal(stewardshipDialog.dataset.open, undefined);
document.querySelector('#stewardshipForm input').dispatchEvent(new dom.window.Event('input', {bubbles: true}));
const navigation = new dom.window.Event('beforeunload', {cancelable: true});
dom.window.dispatchEvent(navigation);
assert.equal(navigation.defaultPrevented, true);

console.log('Rule edit jsdom test passed');
