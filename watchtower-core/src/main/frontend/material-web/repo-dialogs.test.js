// The repository and scan dialogs (UAT walkthrough, 2026-10-16): the searchable ruleset picker,
// criticality buttons filled by Edit, the When buttons with their day pickers, and New scan's
// repository chips posted as the same newline-separated selector.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const scripts = path.resolve(__dirname, '../../resources/static/scripts');
const picker = fs.readFileSync(path.join(scripts, 'ruleset-picker.js'), 'utf8');
const repoScan = fs.readFileSync(path.join(scripts, 'repo-scan.js'), 'utf8');

// Rendered picker markup (fragments/rulesetpicker.html, mode "edit").
const pickerMarkup = (id, initial) => `
  <div class="wt-choice-picker" data-ruleset-picker>
    <span id="${id}-label">Ruleset</span>
    <input type="hidden" name="rulesetId" value="${initial}" data-initial="${initial}" data-edit-field="ruleset" data-ruleset-value>
    <button type="button" aria-haspopup="listbox" aria-expanded="false" data-ruleset-toggle>
      <span data-ruleset-icon>rule_folder</span><span data-ruleset-current></span></button>
    <div hidden data-ruleset-panel>
      <input type="search" aria-label="Search rulesets" data-ruleset-search>
      <div role="listbox">
        <div role="group" data-ruleset-group>
          <button type="button" role="option" class="wt-picker-option" value="-1" data-label="None: pull requests not scanned" data-search="none" data-icon="block">None</button>
        </div>
        <div role="group" data-ruleset-group>
          <button type="button" role="option" class="wt-picker-option" value="4" data-label="Default Dev Ruleset" data-search="Default Dev Ruleset" data-icon="folder">Default Dev Ruleset</button>
          <button type="button" role="option" class="wt-picker-option" value="5" data-label="DNP App Dev" data-search="DNP App Dev" data-icon="folder">DNP App Dev</button>
        </div>
        <div role="group" data-ruleset-group>
          <button type="button" role="option" class="wt-picker-option" value="9" data-label="PMD · Quickstart" data-search="PMD Quickstart" data-icon="coffee">Quickstart</button>
        </div>
        <p hidden data-ruleset-empty>No rulesets match.</p>
      </div>
    </div>
  </div>`;

const dom = new JSDOM(`<!doctype html><body>
  <div data-repo-scan>
    <input type="checkbox" class="wt-repo-select" value="7" checked
      data-edit-id="7" data-edit-name="wt-test" data-edit-project="WPRT" data-edit-ruleset="5"
      data-edit-team="checkout" data-edit-owner="" data-edit-labels="pci" data-edit-criticality="2" data-edit-paused="false">
    <button type="button" data-edit-selection>Edit</button>
    <md-dialog id="repoEditDialog" data-edit-dialog>
      <span data-edit-title>Edit repository</span><span data-edit-project hidden></span>
      <form id="repoEditForm" data-action-base="/repository/pull_request/" action="/repository/pull_request/0">
        <input type="checkbox" name="scanning" value="on" data-edit-field="scanning">
        ${pickerMarkup('edit', '-1')}
        <fieldset data-edit-field="criticality">
          <input type="radio" name="criticality" value="1"><input type="radio" name="criticality" value="2">
          <input type="radio" name="criticality" value="3" checked><input type="radio" name="criticality" value="4">
        </fieldset>
        <input name="team" data-edit-field="team"><input name="owner" data-edit-field="owner"><input name="labels" data-edit-field="labels">
      </form>
    </md-dialog>
    <button type="button" data-wt-dialog-target="#repoScanDialog">New scan</button>
    <md-dialog id="repoScanDialog" data-scan-dialog data-scan-picker="true">
      <form id="repoScanForm" data-scan-form action="/reposcan/submit">
        <input id="repoScanTargetInput" data-scan-target-input>
        <span data-scan-target-chips></span>
        <textarea name="selector" hidden data-scan-selector></textarea>
        <p hidden data-scan-target-error>Add at least one repository.</p>
        <fieldset data-scan-when>
          <input type="radio" name="frequency" value="ONCE" checked><input type="radio" name="frequency" value="DAILY">
          <input type="radio" name="frequency" value="WEEKLY"><input type="radio" name="frequency" value="MONTHLY">
        </fieldset>
        <div data-scan-recurring hidden>
          <select name="hour"><option value="2" selected>02:00</option></select>
          <select name="day" data-scan-day="WEEKLY" disabled><option value="1">Monday</option></select>
          <select name="day" data-scan-day="MONTHLY" disabled hidden><option value="1">1st</option></select>
        </div>
        <span data-scan-next-icon></span><span data-scan-next></span>
      </form>
      <span data-scan-submit-icon></span><span data-scan-submit>Scan</span>
    </md-dialog>
  </div></body>`, {runScripts: 'dangerously'});
const w = dom.window;
const document = w.document;
document.querySelectorAll('md-dialog').forEach(dialog => {
  dialog.show = () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; };
});
w.eval(picker);
w.eval(repoScan);

const click = el => el.dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
const change = el => el.dispatchEvent(new w.Event('change', {bubbles: true}));
const key = (el, k) => el.dispatchEvent(new w.KeyboardEvent('keydown', {key: k, bubbles: true}));

// --- Picker: the starting value's label shows; search filters groups; a choice posts its id.
const pickerRoot = document.querySelector('[data-ruleset-picker]');
const current = pickerRoot.querySelector('[data-ruleset-current]');
const hidden = pickerRoot.querySelector('[data-ruleset-value]');
assert.equal(current.textContent, 'None: pull requests not scanned');
click(pickerRoot.querySelector('[data-ruleset-toggle]'));
assert.equal(pickerRoot.querySelector('[data-ruleset-panel]').hidden, false);
assert.equal(pickerRoot.querySelector('[data-ruleset-toggle]').getAttribute('aria-expanded'), 'true');
const search = pickerRoot.querySelector('[data-ruleset-search]');
search.value = 'pmd';
search.dispatchEvent(new w.Event('input', {bubbles: true}));
const groups = pickerRoot.querySelectorAll('[data-ruleset-group]');
assert.deepEqual(Array.from(groups).map(g => g.hidden), [true, true, false], 'only the PMD group matches');
search.value = 'nothing like this';
search.dispatchEvent(new w.Event('input', {bubbles: true}));
assert.equal(pickerRoot.querySelector('[data-ruleset-empty]').hidden, false);
search.value = 'quickstart';
search.dispatchEvent(new w.Event('input', {bubbles: true}));
key(search, 'Enter');
assert.equal(hidden.value, '9', 'Enter picks the only match');
assert.equal(current.textContent, 'PMD · Quickstart');
assert.equal(pickerRoot.querySelector('[data-ruleset-panel]').hidden, true);

// --- Edit for one selected repository fills the title, project, ruleset label and criticality.
click(document.querySelector('[data-edit-selection]'));
const edit = document.getElementById('repoEditDialog');
assert.equal(edit.open, true);
assert.equal(edit.querySelector('[data-edit-title]').textContent, 'wt-test');
assert.equal(edit.querySelector('[data-edit-project]').textContent, 'WPRT');
assert.equal(edit.querySelector('[data-edit-project]').hidden, false);
assert.equal(hidden.value, '5');
assert.equal(current.textContent, 'DNP App Dev', 'the picker shows the repository\'s ruleset');
assert.equal(edit.querySelector('input[name="criticality"]:checked').value, '2');
assert.equal(edit.querySelector('[name="scanning"]').checked, true);
assert.equal(edit.querySelector('form').action.endsWith('/repository/pull_request/7'), true);

// A form reset puts the picker back to where it started.
edit.querySelector('form').dispatchEvent(new w.Event('reset', {bubbles: true}));
assert.equal(hidden.value, '-1');
assert.equal(current.textContent, 'None: pull requests not scanned');

// --- New scan: When buttons show the right day picker and rename the button.
click(document.querySelector('[data-wt-dialog-target="#repoScanDialog"]'));
const scan = document.getElementById('repoScanDialog');
assert.equal(scan.querySelector('[data-scan-recurring]').hidden, true);
assert.equal(scan.querySelector('[data-scan-submit]').textContent, 'Scan');
const weekly = scan.querySelector('input[value="WEEKLY"]');
weekly.checked = true;
change(weekly);
assert.equal(scan.querySelector('[data-scan-recurring]').hidden, false);
assert.equal(scan.querySelector('[data-scan-day="WEEKLY"]').disabled, false);
assert.equal(scan.querySelector('[data-scan-day="MONTHLY"]').disabled, true, 'only the shown day picker is posted');
assert.equal(scan.querySelector('[data-scan-submit]').textContent, 'Create plan');
const monthly = scan.querySelector('input[value="MONTHLY"]');
monthly.checked = true;
change(monthly);
assert.equal(scan.querySelector('[data-scan-day="WEEKLY"]').disabled, true);
assert.equal(scan.querySelector('[data-scan-day="MONTHLY"]').hidden, false);
const once = scan.querySelector('input[value="ONCE"]');
once.checked = true;
change(once);
assert.equal(scan.querySelector('[data-scan-recurring]').hidden, true);
assert.equal(scan.querySelector('[data-scan-day="MONTHLY"]').disabled, true);

// --- New scan's repositories: chips posted one per line; nothing chosen stops the submit.
const form = scan.querySelector('form');
const submit = () => {
  const event = new w.Event('submit', {bubbles: true, cancelable: true});
  form.dispatchEvent(event);
  return event.defaultPrevented;
};
assert.equal(submit(), true, 'no repositories: the submit stops');
assert.equal(scan.querySelector('[data-scan-target-error]').hidden, false);
const input = scan.querySelector('[data-scan-target-input]');
input.value = 'pay*';
key(input, 'Enter');
input.value = 'label:pci';
key(input, ',');
input.value = 'pay*';
key(input, 'Enter');
assert.equal(scan.querySelectorAll('[data-target]').length, 2, 'a repeated target is added once');
assert.equal(scan.querySelector('[data-scan-selector]').value, 'pay*\nlabel:pci');
assert.equal(scan.querySelector('[data-scan-target-error]').hidden, true);
click(scan.querySelector('[data-target="pay*"] [data-scan-target-remove]'));
assert.equal(scan.querySelector('[data-scan-selector]').value, 'label:pci');
input.value = 'team:checkout';
assert.equal(submit(), false, 'pending text counts and the form submits');
assert.equal(scan.querySelector('[data-scan-selector]').value, 'label:pci\nteam:checkout');
// A chip's text is text, never markup.
input.value = '<img src=x onerror=alert(1)>';
key(input, 'Enter');
assert.equal(scan.querySelector('img'), null);

dom.window.close();
console.log('Repository and scan dialog tests passed');

