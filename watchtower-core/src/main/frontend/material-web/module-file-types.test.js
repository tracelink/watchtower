// Scanner modules: the "Runs on" chips open a file-types dialog (approved on the design canvas,
// board ScannerTypes). Types are chips; the form posts them comma-separated, or asks for the default.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(resources, 'templates/configuration/modules.html'), 'utf8');
const script = fs.readFileSync(path.join(resources, 'static/scripts/module-controls.js'), 'utf8');

function page() {
  const chip = '<button type="button" data-module-types data-module="checkov" data-version="4" data-name="Checkov"'
    + ' data-purpose="Terraform, Kubernetes" data-icon="layers" data-types=".tf,.json,.yaml"'
    + ' data-defaults=".tf,.json,.yaml" data-custom="false">.tf</button>';
  const dom = new JSDOM(chip + template, {runScripts: 'outside-only'});
  const document = dom.window.document;
  const dialog = document.getElementById('module-types-dialog');
  const state = {opened: 0, closed: 0, submitted: 0};
  dialog.show = () => state.opened++;
  dialog.close = () => state.closed++;
  document.getElementById('module-types-form').requestSubmit = () => state.submitted++;
  dom.window.eval(script);
  const q = selector => document.querySelector(selector);
  const types = () => [...document.querySelectorAll('[data-types-list] [data-type]')].map(el => el.dataset.type);
  const add = text => {
    const input = document.getElementById('module-types-input');
    input.value = text;
    input.dispatchEvent(new dom.window.Event('input', {bubbles: true}));
    q('[data-types-add]').click();
  };
  const form = () => document.getElementById('module-types-form').elements;
  return {dom, document, dialog, state, q, types, add, form, open: () => q('[data-module-types]').click()};
}

(() => {
  // opening from a chip fills the dialog from the row
  let p = page();
  p.open();
  assert.equal(p.state.opened, 1);
  assert.equal(p.document.getElementById('module-types-title').textContent, 'Checkov runs on');
  assert.deepEqual(p.types(), ['.tf', '.json', '.yaml']);
  assert.equal(p.form().namedItem('module').value, 'checkov');
  assert.equal(p.form().namedItem('version').value, '4');
  assert.equal(p.form().namedItem('fileTypes').value, '.tf,.json,.yaml');
  assert.equal(p.form().namedItem('useDefault').value, 'false');
  assert.equal(p.q('[data-types-state]').textContent.trim(), 'Default');

  // adding: cleaned, de-duplicated, and invalid input is refused with a message
  p.add(' .YML ');
  assert.deepEqual(p.types(), ['.tf', '.json', '.yaml', '.yml']);
  assert.equal(p.form().namedItem('fileTypes').value, '.tf,.json,.yaml,.yml');
  assert.equal(p.q('[data-types-state]').textContent.trim(), 'Custom');
  p.add('.tf');
  assert.deepEqual(p.types(), ['.tf', '.json', '.yaml', '.yml'], 'a type already listed is not added twice');
  p.add('src/main.java');
  assert.deepEqual(p.types(), ['.tf', '.json', '.yaml', '.yml']);
  assert.equal(p.q('[data-types-error]').hidden, false);
  assert.match(p.q('[data-types-error]').textContent, /extension|file name/i);
  p.add('.ok');
  assert.equal(p.q('[data-types-error]').hidden, true, 'a valid type clears the message');

  // removing a chip
  p.document.querySelector('[data-types-list] [data-type=".json"] button').click();
  assert.deepEqual(p.types(), ['.tf', '.yaml', '.yml', '.ok']);

  // a short word without a dot is almost always an extension: offer the dot
  p = page();
  p.open();
  const input = p.document.getElementById('module-types-input');
  input.value = 'tf';
  input.dispatchEvent(new p.dom.window.Event('input', {bubbles: true}));
  assert.equal(p.q('[data-types-hint]').hidden, false);
  assert.equal(p.q('[data-types-hint]').textContent.trim(), 'Use .tf');
  p.q('[data-types-hint]').click();
  assert.ok(p.types().includes('.tf'));
  input.value = 'Dockerfile';
  input.dispatchEvent(new p.dom.window.Event('input', {bubbles: true}));
  assert.equal(p.q('[data-types-hint]').hidden, true, 'a file name is not an extension');

  // no types at all means every file
  p = page();
  p.open();
  for (const type of ['.tf', '.json', '.yaml']) p.document.querySelector(`[data-types-list] [data-type="${type}"] button`).click();
  assert.deepEqual(p.types(), []);
  assert.equal(p.q('[data-types-state]').textContent.trim(), 'All files');
  assert.equal(p.form().namedItem('fileTypes').value, '');

  // use default posts the request for the scanner's own list
  p.q('[data-types-default]').click();
  assert.equal(p.form().namedItem('useDefault').value, 'true');
  assert.equal(p.state.submitted, 1);

  // cancel closes without posting
  p = page();
  p.open();
  p.document.getElementById('module-types-cancel').click();
  assert.equal(p.state.closed, 1);
  assert.equal(p.state.submitted, 0);

  // Enter in the field adds the type and does not submit the form
  p = page();
  p.open();
  const field = p.document.getElementById('module-types-input');
  field.value = '.scala';
  const enter = new p.dom.window.KeyboardEvent('keydown', {key: 'Enter', bubbles: true, cancelable: true});
  field.dispatchEvent(enter);
  assert.equal(enter.defaultPrevented, true);
  assert.ok(p.types().includes('.scala'));

  console.log('Scanner modules file types: dialog, validation, default and all-files states passed');
})();
