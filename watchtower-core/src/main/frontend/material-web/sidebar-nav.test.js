const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const bundle = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/material-web-bundle.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><html><body>
  <wt-sidebar-nav>
    <a class="nav-link" href="#" data-section-index="1" aria-expanded="false">Rules</a>
    <div class="wt-nav-section" data-section-index="1"><a class="nav-link" href="/rulesets">Rulesets</a></div>
  </wt-sidebar-nav><button id="outside">Outside</button>
  <wt-user-menu><a href="#" class="dropdown-toggle">Account</a>
    <div class="dropdown-menu"><a class="dropdown-item" href="/profile">Profile</a>
      <button class="dropdown-item" role="switch">Dark mode</button>
      <button class="dropdown-item">Log out</button></div></wt-user-menu>
</body></html>`, {runScripts: 'dangerously', url: 'https://watchtower.test/'});

dom.window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
dom.window.eval(bundle);
dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));

const document = dom.window.document;
const trigger = document.querySelector('[data-section-index="1"].nav-link');
const panel = document.querySelector('.wt-nav-section');

trigger.click();
assert.equal(trigger.getAttribute('aria-expanded'), 'true');
assert.equal(panel.classList.contains('is-open'), true);

document.getElementById('outside').click();
assert.equal(trigger.getAttribute('aria-expanded'), 'false');

const account = document.querySelector('wt-user-menu');
const accountToggle = account.querySelector('.dropdown-toggle');
const accountItems = [...account.querySelectorAll('.dropdown-item')];
let delegatedDropdownKeys = 0;
document.addEventListener('keydown', event => {
  if (account.contains(event.target)) delegatedDropdownKeys++;
}, true);
const accountKey = (element, key) => element.dispatchEvent(
  new dom.window.KeyboardEvent('keydown', {key, bubbles: true, cancelable: true}));
accountToggle.focus();
accountKey(accountToggle, 'ArrowDown');
assert.equal(document.activeElement, accountItems[0], 'Arrow Down opens the account menu and focuses its first row');
accountKey(accountItems[0], 'ArrowDown');
assert.equal(document.activeElement, accountItems[1], 'keyboard navigation reaches Dark mode');
accountKey(accountItems[1], 'Escape');
assert.equal(accountToggle.getAttribute('aria-expanded'), 'false');
assert.equal(document.activeElement, accountToggle, 'Escape returns focus to the account toggle');
assert.equal(delegatedDropdownKeys, 0, 'owned menu keys never reach Bootstrap dropdown delegation');

trigger.click();
document.dispatchEvent(new dom.window.KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
assert.equal(trigger.getAttribute('aria-expanded'), 'false');
assert.equal(document.activeElement, trigger);

trigger.click();
const destination = document.querySelector('a[href="/rulesets"]');
destination.addEventListener('click', event => event.preventDefault());
destination.dispatchEvent(
  new dom.window.MouseEvent('click', {bubbles: true, cancelable: true}));
assert.equal(trigger.getAttribute('aria-expanded'), 'false');

// A report page names its sidebar entry: /scan/report/1 highlights Results, not New Scan (/scan).
const page = new JSDOM(`<!doctype html><html><body>
  <wt-sidebar-nav>
    <a class="nav-link" href="#" data-section-index="2" aria-expanded="false">Pull Requests</a>
    <div class="wt-nav-section" data-section-index="2">
      <a class="nav-link" href="/scan">New Scan</a><a class="nav-link" href="/scan/results">Results</a></div>
  </wt-sidebar-nav>
  <div id="content"><span data-nav-active="/scan/results" hidden></span></div>
</body></html>`, {runScripts: 'dangerously', url: 'https://watchtower.test/scan/report/158707'});
page.window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
page.window.eval(bundle);
page.window.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
assert.equal(page.window.document.querySelector('a[href="/scan/results"]').classList.contains('active'), true);
assert.equal(page.window.document.querySelector('a[href="/scan"]').classList.contains('active'), false);

console.log('Sidebar navigation jsdom test passed');
