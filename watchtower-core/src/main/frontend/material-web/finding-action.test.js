const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/finding-workspace.js'), 'utf8');

function item(index, action) {
  const attrs = action
    ? ` data-action-label="${action.label}" data-action-url="${action.url}"` : '';
  return `<button data-finding-item${index === 1 ? ' class="is-selected" aria-pressed="true"' : ''}
      data-severity="1" data-location="a${index}.yml" data-location-label="a${index}.yml:1"
      data-title="Finding ${index}" data-guidance="g" data-file="a${index}.yml" data-line="1"
      data-source-action="false"${attrs}><span class="wt-sev wt-sev-1">High</span></button>`;
}

const dom = new JSDOM(`<!doctype html><body><section data-finding-workspace>
  <input data-finding-search>
  <select data-finding-severity><option value="">All</option></select>
  <select data-finding-location><option value="">All</option></select>
  <span data-finding-status></span><div data-finding-empty hidden></div>
  <div data-finding-list-viewport>
    ${item(1, {label: 'Allowlist…', url: '/betterleaks/allowlist?rule=aws'})}
    ${item(2)}
    ${item(3, {label: 'Bad', url: 'https://evil.example/x'})}
  </div>
  <nav data-finding-pagination><span data-finding-range></span>
    <button data-finding-previous></button><button data-finding-next></button></nav>
  <aside>
    <div class="wt-finding-detail-heading"><span class="wt-sev"></span></div>
    <h3 data-detail-title></h3><span data-detail-location></span><p data-detail-guidance></p>
    <div data-detail-cvss><span data-detail-score></span></div>
    <div data-detail-vector-row><span data-detail-vector></span></div>
    <a data-detail-url></a><a class="wt-loc" data-detail-source></a>
    <a data-detail-action hidden><span data-detail-action-label></span></a>
    <span data-copy-status></span>
  </aside>
</section></body>`, {runScripts: 'dangerously'});
dom.window.matchMedia = () => ({matches: true});
dom.window.HTMLElement.prototype.scrollIntoView = function () {};
dom.window.eval(script);

const document = dom.window.document;
const items = document.querySelectorAll('[data-finding-item]');
const action = document.querySelector('[data-detail-action]');
const label = document.querySelector('[data-detail-action-label]');

items[0].click();
assert.equal(action.hidden, false, 'a finding with an action shows it');
assert.equal(action.getAttribute('href'), '/betterleaks/allowlist?rule=aws');
assert.equal(label.textContent, 'Allowlist…');

items[1].click();
assert.equal(action.hidden, true, 'a finding without an action hides it');

items[2].click();
assert.equal(action.hidden, true, 'an action leaving Watchtower is never shown');

console.log('Finding action jsdom test passed');
