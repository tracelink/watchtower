const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const resources = path.resolve(__dirname, '../../resources/static/scripts');
const shellScript = fs.readFileSync(path.join(resources, 'loading-indicator.js'), 'utf8');
const timeScript = fs.readFileSync(path.join(resources, 'localizetime.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><html><head><title>Watchtower</title></head><body>
  <main id="content"><h1 class="page-title" tabindex="-1">Scan Results Viewer</h1>
    <span class="localizetime">1789145751165</span>
    <span class="localizetime" id="preformatted" data-millis="1789145751165">11 Sep 2026, 16:55:51</span></main>
</body></html>`, {runScripts: 'dangerously', url: 'https://watchtower.test/scan/results/all'});

dom.window.HTMLElement.prototype.scrollIntoView = function () {};
dom.window.eval(shellScript);
dom.window.eval(timeScript);
dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));

const document = dom.window.document;
assert.equal(document.title, 'Scan Results Viewer · Watchtower');
assert.equal(document.querySelector('[data-shell-page-title]'), null);
assert.doesNotMatch(document.querySelector('.localizetime').textContent, /^\d{10,}$/);
// A time the server already printed (UTC, same format) is re-localized from data-millis, so the
// text barely changes width when the script runs (no layout shift in one-line headers).
const preformatted = document.getElementById('preformatted');
assert.equal(preformatted.dataset.localized, 'true', 'data-millis times are localized too');
assert.equal(preformatted.textContent, document.querySelector('.localizetime').textContent,
  'both forms localize the same instant to the same text');

document.querySelector('.page-title').textContent = 'Manual Code Reviews';
const detachedTarget = document.createElement('div');
dom.window.document.dispatchEvent(new dom.window.CustomEvent('htmx:afterSwap', {
  detail: {target: detachedTarget}
}));
assert.equal(document.title, 'Manual Code Reviews · Watchtower');

document.querySelector('.page-title').textContent = 'Scan Results Viewer';
dom.window.document.dispatchEvent(new dom.window.CustomEvent('htmx:historyRestore'));
assert.equal(document.title, 'Scan Results Viewer · Watchtower');

console.log('Shell navigation and date localization jsdom test passed');
