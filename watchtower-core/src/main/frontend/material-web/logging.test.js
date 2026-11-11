const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/logging.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <span data-log-status class="wt-mini-chip--ok"><span data-log-status-text>Live</span></span>
  <button data-log-pause aria-pressed="false"><span slot="icon">pause</span><span data-log-pause-label>Pause</span></button>
  <div data-log-severity>
    <button data-log-level-filter="all" aria-pressed="true">All</button>
    <button data-log-level-filter="warn" aria-pressed="false">Warnings</button>
  </div>
  <input data-log-filter type="search"><button data-log-refresh></button>
  <span data-log-filter-status></span>
  <div data-log-region><div data-log-lines>
    <div data-log-line data-level="info"><span class="wt-log-line__logger" data-tip="c.t.CatalogSyncHandler">CatalogSyncHandler</span><span>ready</span></div>
    <div data-log-line data-level="error"><span class="wt-log-line__logger" data-tip="c.t.IntegrationHealthService">IntegrationHealthService</span><span>failed</span></div>
    <div data-log-line data-level="warn"><span>slow</span></div>
  </div></div>
  <select name="lines"><option selected value="200">200</option></select>
</body>`, {runScripts: 'dangerously', url: 'https://watchtower.test/logging'});
dom.window.setInterval = callback => { dom.window.refreshCallback = callback; return 1; };
dom.window.clearInterval = () => {};
dom.window.fetch = async () => ({ok: false});
dom.window.eval(script);

const document = dom.window.document;
const lines = () => Array.from(document.querySelectorAll('[data-log-line]'));
const search = document.querySelector('[data-log-filter]');
search.value = 'failed';
search.dispatchEvent(new dom.window.Event('input'));
assert.deepEqual(lines().map(line => line.hidden), [true, false, true]);
assert.match(document.querySelector('[data-log-filter-status]').textContent, /1 of 3/);

// The logger's full name (hover text) is searchable.
search.value = 'c.t.catalogsync';
search.dispatchEvent(new dom.window.Event('input'));
assert.deepEqual(lines().map(line => line.hidden), [false, true, true]);

// Level segments filter by the line's level, not by matching words in the text.
search.value = '';
search.dispatchEvent(new dom.window.Event('input'));
assert.equal(document.querySelector('[data-log-filter-status]').textContent, '');
document.querySelector('[data-log-level-filter="warn"]').click();
assert.deepEqual(lines().map(line => line.hidden), [true, true, false]);
assert.equal(document.querySelector('[data-log-level-filter="warn"]').getAttribute('aria-pressed'), 'true');
assert.equal(document.querySelector('[data-log-level-filter="all"]').getAttribute('aria-pressed'), 'false');
document.querySelector('[data-log-level-filter="all"]').click();
assert.deepEqual(lines().map(line => line.hidden), [false, false, false]);

document.querySelector('[data-log-pause]').click();
assert.equal(document.querySelector('[data-log-pause]').getAttribute('aria-pressed'), 'true');
assert.equal(document.querySelector('[data-log-status-text]').textContent, 'Paused');
assert.equal(document.querySelector('[data-log-status]').classList.contains('wt-mini-chip--ok'), false);
assert.equal(document.querySelector('[data-log-pause-label]').textContent, 'Resume');
assert.equal(script.includes('$('), false);

// Changing "Lines" reloads at once - no separate Apply button.
document.querySelector('[data-log-pause]').click();
let requested = null;
dom.window.fetch = async (url) => { requested = url; return {ok: false}; };
const lineSelect = document.querySelector('[name="lines"]');
lineSelect.innerHTML += '<option value="500">500</option>';
lineSelect.value = '500';
lineSelect.dispatchEvent(new dom.window.Event('change'));
setImmediate(() => {
  assert.equal(requested, '/logging?lines=500');
  console.log('Logging jsdom test passed');
});
