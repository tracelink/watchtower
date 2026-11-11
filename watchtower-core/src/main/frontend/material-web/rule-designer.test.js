const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/rule-designer.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <section data-rule-designer>
    <form data-designer-run-form>
      <textarea data-designer-input name="source">const value = 1;</textarea>
      <button data-run-rule type="submit">Run Rule</button>
    </form>
    <span data-designer-status role="status" aria-live="polite">Ready.</span>
    <section data-designer-output>
      <button type="button" data-designer-match-line="1" data-tip="Matched by the pattern">Line 1</button>
      <button type="button" data-designer-match-line="5">Line 5</button>
    </section>
  </section>
</body>`, {runScripts: 'dangerously'});

dom.window.eval(script);

const document = dom.window.document;
const workspace = document.querySelector('[data-rule-designer]');
const input = document.querySelector('[data-designer-input]');
const form = document.querySelector('[data-designer-run-form]');
const status = document.querySelector('[data-designer-status]');
const runButton = document.querySelector('[data-run-rule]');

input.value = 'const value = 2;';
input.dispatchEvent(new dom.window.Event('input', {bubbles: true}));
assert.equal(workspace.dataset.dirty, 'true');

dom.window.confirm = () => false;
const externalRequest = new dom.window.CustomEvent('htmx:beforeRequest', {
  bubbles: true,
  cancelable: true,
  detail: {elt: document.body}
});
document.dispatchEvent(externalRequest);
assert.equal(externalRequest.defaultPrevented, true);

const unload = new dom.window.Event('beforeunload', {cancelable: true});
dom.window.dispatchEvent(unload);
assert.equal(unload.defaultPrevented, true);

form.dispatchEvent(new dom.window.Event('submit', {bubbles: true, cancelable: true}));
assert.equal(workspace.getAttribute('aria-busy'), 'true');
assert.equal(workspace.dataset.dirty, 'false');
assert.equal(runButton.disabled, true);
assert.equal(status.textContent, 'Running rule…');

// Match chips: the sample editor highlights the matched lines and "Line N" jumps there.
const calls = {highlighted: null, jumps: []};
dom.window.wtDesignerMatches({
  highlightLines(lines) { calls.highlighted = lines; },
  jumpToLine(line) { calls.jumps.push(line); return true; }
});
assert.equal(JSON.stringify(calls.highlighted), "[1,5]");
document.querySelector('[data-designer-match-line="5"]').click();
assert.deepEqual(calls.jumps, [5]);
// An editor without the helpers (or no editor at all) is left alone.
dom.window.wtDesignerMatches(null);
dom.window.wtDesignerMatches({});

console.log('Rule designer jsdom test passed');
