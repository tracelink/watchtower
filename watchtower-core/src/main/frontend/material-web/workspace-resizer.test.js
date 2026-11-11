const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/workspace-resizer.js'), 'utf8');

function createDom(mobile = false) {
  const dom = new JSDOM(`<!doctype html><body>
    <div data-split-workspace data-split-key="test" data-split-default="45">
      <div></div>
      <div role="separator" data-workspace-resizer></div>
      <div></div>
    </div>
  </body>`, {runScripts: 'dangerously', url: 'https://watchtower.test/'});
  dom.window.matchMedia = () => ({matches: mobile, addEventListener() {}});
  return dom;
}

const dom = createDom();
dom.window.eval(script);
const workspace = dom.window.document.querySelector('[data-split-workspace]');
const handle = workspace.querySelector('[data-workspace-resizer]');
assert.equal(handle.tabIndex, 0);
assert.equal(handle.getAttribute('aria-valuenow'), '45');

handle.dispatchEvent(new dom.window.KeyboardEvent('keydown', {key: 'ArrowRight', bubbles: true}));
assert.equal(workspace.style.getPropertyValue('--wt-split-percent'), '47%');
assert.equal(dom.window.localStorage.getItem('watchtower-split-test'), '47');

handle.dispatchEvent(new dom.window.KeyboardEvent('keydown', {key: 'End', bubbles: true}));
assert.equal(handle.getAttribute('aria-valuenow'), '70');
handle.dispatchEvent(new dom.window.MouseEvent('dblclick', {bubbles: true}));
assert.equal(handle.getAttribute('aria-valuenow'), '45');

const mobileDom = createDom(true);
mobileDom.window.eval(script);
const mobileHandle = mobileDom.window.document.querySelector('[data-workspace-resizer]');
assert.equal(mobileHandle.tabIndex, -1);
assert.equal(mobileHandle.getAttribute('aria-disabled'), 'true');

console.log('Workspace resizer jsdom test passed');
