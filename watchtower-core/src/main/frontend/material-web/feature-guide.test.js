const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// Feature guide (UAT #7): searching shows matching topics only, opens them and hides empty sections.
const resources = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(resources, 'templates/help/features.html'), 'utf8');
const ids = [...template.matchAll(/<details id="([a-z-]+)" data-feature-topic>/g)].map(m => m[1]);
for (const anchor of ['assistant', 'assistant-settings', 'bypass-reasons', 'finding-feedback', 'owner-status', 'review-report', 'rule-health', 'scan-evidence']) {
  assert.ok(ids.includes(anchor), 'help links elsewhere still reach #' + anchor);
}
// One segmented tab per section (UAT walkthrough, 2026-10-16).
const tabs = [...template.matchAll(/data-feature-tab="([a-z-]+)"/g)].map(m => m[1]);
const panes = [...template.matchAll(/<section id="([a-z-]+)"[^>]*data-feature-pane/g)].map(m => m[1]);
assert.deepEqual(tabs, panes);

const page = (hash) => new JSDOM(`<body><div data-feature-guide>
  <form data-feature-search-form><input data-feature-search><span data-feature-search-status></span></form>
  <nav><a href="#start-here" data-feature-tab="start-here">Start</a><a href="#a" data-feature-tab="a">A</a><a href="#b" data-feature-tab="b">B</a></nav>
  <section id="start-here" data-feature-pane><ol><li>Connect</li></ol></section>
  <section data-feature-section data-feature-pane id="a"><details data-feature-topic id="bypass"><summary>Bypass</summary>request an exception</details></section>
  <section data-feature-section data-feature-pane id="b"><details data-feature-topic id="health"><summary>Rule health</summary>false positive rate</details></section>
  <p data-feature-no-results hidden>No topics match.</p></div></body>`,
  {runScripts: 'dangerously', url: 'https://watchtower.test/help/features' + hash});
const dom = page('');
const w = dom.window;
w.HTMLElement.prototype.scrollIntoView = () => {};
w.eval(fs.readFileSync(path.join(resources, 'static/scripts/feature-guide.js'), 'utf8'));
w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
const $ = id => w.document.getElementById(id);
const hidden = () => ['start-here', 'a', 'b'].map(id => $(id).hidden);

// Start here is shown first; the other sections wait behind their tabs.
assert.deepEqual(hidden(), [false, true, true]);
assert.equal(w.document.querySelector('[data-feature-tab="start-here"]').getAttribute('aria-current'), 'page');
w.document.querySelector('[data-feature-tab="b"]').click();
assert.deepEqual(hidden(), [true, true, false]);
assert.equal(w.document.querySelector('[data-feature-tab="b"]').getAttribute('aria-current'), 'page');

const input = w.document.querySelector('[data-feature-search]');
const type = value => { input.value = value; input.dispatchEvent(new w.Event('input', {bubbles: true})); };
type('exception');
assert.equal($('bypass').hidden, false);
assert.equal($('bypass').open, true);
assert.equal($('health').hidden, true);
assert.deepEqual(hidden(), [true, false, true], 'search shows every section with a match');
assert.equal(w.document.querySelector('[data-feature-search-status]').textContent, '1 topic matches');
type('nothing like this');
assert.equal(w.document.querySelector('[data-feature-no-results]').hidden, false);
type('');
assert.equal($('health').hidden, false);
assert.deepEqual(hidden(), [true, true, false], 'clearing the search returns to the chosen section');
assert.equal(w.document.querySelector('[data-feature-no-results]').hidden, true);

// A help link to a topic opens its section and the topic.
const linked = page('#health');
linked.window.HTMLElement.prototype.scrollIntoView = () => {};
linked.window.eval(fs.readFileSync(path.join(resources, 'static/scripts/feature-guide.js'), 'utf8'));
linked.window.document.dispatchEvent(new linked.window.Event('DOMContentLoaded'));
assert.equal(linked.window.document.getElementById('b').hidden, false);
assert.equal(linked.window.document.getElementById('start-here').hidden, true);
assert.equal(linked.window.document.getElementById('health').open, true);
console.log('Feature guide: anchors kept, tabs show one section, search filters and opens topics');
