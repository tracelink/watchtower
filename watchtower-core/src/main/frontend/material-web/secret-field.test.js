const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// A saved secret shows "Saved" and Replace; Replace reveals the empty field (UAT walkthrough).
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/secret-field.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <div data-secret-field>
    <div data-secret-saved><span>Saved</span><button type="button" data-secret-replace>Replace</button></div>
    <input type="password" name="auth" data-secret-input hidden>
  </div></body>`, {runScripts: 'dangerously'});
const w = dom.window;
// Loaded after the page is ready and with no DOMContentLoaded or htmx:afterSwap to follow, as when the
// page is reached through a boosted link (the Replace button did nothing then).
w.eval(script);
const input = w.document.querySelector('[data-secret-input]');
const saved = w.document.querySelector('[data-secret-saved]');
assert.equal(input.hidden, true, 'the field stays hidden until Replace');
assert.equal(input.value, '', 'the stored value is never on the page');
w.document.querySelector('[data-secret-replace]').click();
assert.equal(input.hidden, false);
assert.equal(saved.hidden, true);
assert.equal(w.document.activeElement, input, 'Replace focuses the new field');

// A field swapped in later works too, and loading the script twice does not bind it twice.
w.document.body.insertAdjacentHTML('beforeend', `
  <div data-secret-field id="late">
    <div data-secret-saved><button type="button" data-secret-replace><span>Replace</span></button></div>
    <input type="password" name="auth2" data-secret-input hidden>
  </div>`);
w.eval(script);
const lateInput = w.document.querySelector('#late [data-secret-input]');
w.document.querySelector('#late [data-secret-replace] span').click();
assert.equal(lateInput.hidden, false, 'a field added after load works, including a click on its icon or label');
assert.equal(w.document.querySelector('#late [data-secret-saved]').hidden, true);
console.log('Secret field: Replace reveals an empty field');
