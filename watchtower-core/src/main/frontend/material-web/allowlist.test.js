const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// The Betterleaks module ships this script; its behaviour is tested here with the other pages.
const script = fs.readFileSync(path.resolve(__dirname,
  '../../../../../watchtower-module-betterleaks/src/main/resources/static/scripts/allowlist.js'),
  'utf8');

function load(prefilled) {
  const dom = new JSDOM(`<!doctype html><body>
    <md-filled-button id="add" data-wt-dialog-target="#allowlistDialog">Add entry</md-filled-button>
    <md-dialog id="allowlistDialog" ${prefilled ? 'data-allowlist-prefill' : ''}>
      <form id="allowlistForm">
        <select name="scope" data-allowlist-scope>
          <option value="GLOBAL">All</option><option value="REPO" selected>One</option>
        </select>
        <div data-allowlist-repo-field><input name="repoName"></div>
      </form>
      <button id="cancelAllowlistDialog">Cancel</button>
    </md-dialog></body>`, {runScripts: 'dangerously'});
  const {window} = dom;
  const dialog = window.document.getElementById('allowlistDialog');
  dialog.open = false;
  dialog.show = () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; dialog.dispatchEvent(new window.Event('closed')); };
  window.eval(script);
  return window;
}

{
  const window = load(false);
  const document = window.document;
  const dialog = document.getElementById('allowlistDialog');
  assert.equal(dialog.open, false, 'the add form stays closed until asked for');
  document.getElementById('add').click();
  assert.equal(dialog.open, true, 'Add entry opens the dialog');
  document.getElementById('cancelAllowlistDialog').click();
  assert.equal(dialog.open, false);

  // The repository only matters for a one-repository entry.
  const scope = document.querySelector('[data-allowlist-scope]');
  const repo = document.querySelector('[data-allowlist-repo-field]');
  assert.equal(repo.hidden, false);
  scope.value = 'GLOBAL';
  scope.dispatchEvent(new window.Event('change'));
  assert.equal(repo.hidden, true, 'all repositories: no repository field');
  scope.value = 'REPO';
  scope.dispatchEvent(new window.Event('change'));
  assert.equal(repo.hidden, false);
}

{
  const window = load(true);
  assert.equal(window.document.getElementById('allowlistDialog').open, true,
    'coming from a finding opens the pre-filled dialog');
}

// Scope as two buttons (radio chips); the amber warning only for "every rule and no path".
{
  const dom = new JSDOM(`<!doctype html><body>
    <md-dialog id="allowlistDialog">
      <form id="allowlistForm">
        <fieldset data-allowlist-scope>
          <input type="radio" name="scope" value="REPO" checked><input type="radio" name="scope" value="GLOBAL">
        </fieldset>
        <div data-allowlist-repo-field><input name="repoName"></div>
        <input name="pathGlob" data-allowlist-path>
        <select name="ruleId" data-allowlist-rule><option value="" selected>Every rule</option><option value="github-pat">github-pat</option></select>
        <span data-allowlist-warning hidden><span data-allowlist-warning-text></span></span>
      </form>
    </md-dialog></body>`, {runScripts: 'dangerously'});
  const {window} = dom;
  const dialog = window.document.getElementById('allowlistDialog');
  dialog.show = () => {};
  dialog.close = () => {};
  window.eval(script);
  const document = window.document;
  const warning = document.querySelector('[data-allowlist-warning]');
  const text = document.querySelector('[data-allowlist-warning-text]');
  const repo = document.querySelector('[data-allowlist-repo-field]');
  assert.equal(warning.hidden, false, 'every rule and no path: the warning shows');
  assert.match(text.textContent, /in this repository$/);
  const [one, all] = document.querySelectorAll('input[name="scope"]');
  all.checked = true;
  all.dispatchEvent(new window.Event('change', {bubbles: true}));
  assert.equal(repo.hidden, true, 'all repositories: no repository field');
  assert.match(text.textContent, /in every repository$/);
  const path = document.querySelector('[data-allowlist-path]');
  path.value = 'src/test/**';
  path.dispatchEvent(new window.Event('input', {bubbles: true}));
  assert.equal(warning.hidden, true, 'a path narrows it: no warning');
  path.value = '';
  path.dispatchEvent(new window.Event('input', {bubbles: true}));
  const rule = document.querySelector('[data-allowlist-rule]');
  rule.value = 'github-pat';
  rule.dispatchEvent(new window.Event('change', {bubbles: true}));
  assert.equal(warning.hidden, true, 'one rule narrows it: no warning');
  one.checked = true;
  one.dispatchEvent(new window.Event('change', {bubbles: true}));
  assert.equal(repo.hidden, false);
}

console.log('allowlist tests passed');
