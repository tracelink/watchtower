const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/role-privileges.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <input data-privilege-search><span data-privilege-status></span>
  <section data-privilege-group>
    <button data-toggle-group>Select all</button>
    <div data-privilege-row data-privilege-text="core user view"><input type="checkbox"></div>
    <div data-privilege-row data-privilege-text="core role modify"><input type="checkbox"></div>
  </section>
</body>`, {runScripts: 'dangerously'});

dom.window.eval(script);
const document = dom.window.document;
const toggle = document.querySelector('[data-toggle-group]');
const boxes = () => [...document.querySelectorAll('input[type=checkbox]')];
assert.equal(document.querySelector('[data-privilege-status]').textContent,
  '2 privileges shown');
assert.equal(toggle.textContent, 'Select all', 'nothing granted: the one button selects');

toggle.click();
assert.equal(boxes().every((checkbox) => checkbox.checked), true);
assert.equal(toggle.textContent, 'Clear all', 'all granted: the same button clears');

const search = document.querySelector('[data-privilege-search]');
search.value = 'user';
search.dispatchEvent(new dom.window.Event('input'));
assert.equal(document.querySelector('[data-privilege-status]').textContent,
  '1 privilege shown');

toggle.click();
assert.equal(boxes().every((checkbox) => !checkbox.checked), true);
assert.equal(toggle.textContent, 'Select all');

// Ticking a box by hand keeps the label honest.
boxes().forEach((checkbox) => { checkbox.checked = true; });
boxes()[0].dispatchEvent(new dom.window.Event('change', {bubbles: true}));
assert.equal(toggle.textContent, 'Clear all');

console.log('Role privilege filter jsdom test passed');
