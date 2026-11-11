const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const script = name => fs.readFileSync(path.join(resources, 'static/scripts', name), 'utf8');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

async function main() {
  const template = fs.readFileSync(path.join(resources, 'templates/rules/rulesets.html'), 'utf8');
  const rules = template.match(/<md-dialog id="editRulesModal"[\s\S]*?<\/md-dialog>/)[0];
  const dom = new JSDOM(`<body><button data-wt-dialog-target="#editRulesModal">Rules</button>${rules}</body>`,
    {url: 'https://watchtower.example/rulesets/1', runScripts: 'dangerously'});
  const w = dom.window;
  const doc = w.document;
  const dialog = doc.querySelector('md-dialog');
  dialog.dataset.choicesUrl = '/rulesets/1/rules/choices';
  dialog.show = () => {};
  dialog.close = () => {};
  let requests = 0;
  let reply;
  w.fetch = () => { requests++; return new Promise(resolve => { reply = resolve; }); };
  w.eval(script('rulesets.js'));
  assert.equal(requests, 0, 'the list is loaded only when opened');
  const trigger = doc.querySelector('[data-wt-dialog-target]');
  trigger.click();
  trigger.click();
  assert.equal(requests, 1, 'reopening while loading does not duplicate requests');
  const save = doc.querySelector('[data-rule-choices-save]');
  assert.equal(save.hasAttribute('disabled'), true, 'an unloaded list cannot replace the ruleset');
  reply({ok: true, json: async () => ({rules: [
    {id: 1, name: 'Custom <rule>', custom: true, scanner: 'regex', icon: 'rule', selected: true},
    {id: 2, name: 'Other custom', custom: true, scanner: 'pmd', icon: 'code', selected: false},
    {id: 3, name: 'Retired provided', custom: false, scanner: 'pmd', icon: 'code', selected: true, retired: true}
  ], scanners: [{key: 'regex', name: 'Regex'}, {key: 'pmd', name: 'PMD'}]})});
  await tick();
  assert.equal(save.disabled, false);
  const list = doc.querySelector('[data-rule-choices-list]');
  assert.equal(list.querySelectorAll('input').length, 2);
  assert.equal(list.querySelector('rule'), null, 'rule names are text');
  assert.equal(list.querySelector('input').checked, true);
  const search = doc.querySelector('[data-rule-choices-search]');
  search.value = 'Other';
  search.dispatchEvent(new w.Event('input'));
  doc.querySelector('[data-rule-choices-all]').click();
  assert.equal(doc.querySelector('[data-rule-choices-count]').textContent, '3');
  doc.querySelector('[data-rule-choices-kind="provided"]').click();
  search.value = '';
  search.dispatchEvent(new w.Event('input'));
  assert.equal(list.querySelector('input').checked, true, 'hidden provided selections survive filtering');
  assert.match(list.textContent, /Retired/);
  const form = doc.querySelector('form');
  form.dispatchEvent(new w.Event('submit', {cancelable: true}));
  assert.deepEqual(Array.from(form.querySelectorAll('input[name="ruleIds"]'), input => input.value), ['1', '3', '2']);
  doc.querySelector('[data-rule-choices-none]').click();
  form.dispatchEvent(new w.Event('submit', {cancelable: true}));
  assert.deepEqual(Array.from(form.querySelectorAll('input[name="ruleIds"]'), input => input.value), ['1', '2']);
  dom.window.close();

  const deletion = fs.readFileSync(path.join(resources, 'templates/configuration/deleteintegration.html'), 'utf8');
  const confirm = new JSDOM(`<body>
    <button data-wt-dialog-target="#deleteModal" data-label="Team &lt;connection&gt;" data-repo-count="1"
      data-repo-name="payments" data-provider="Bitbucket">Delete</button>${deletion}</body>`, {runScripts: 'dangerously'});
  const cd = confirm.window.document;
  const modal = cd.querySelector('md-dialog');
  modal.show = () => {};
  modal.close = () => modal.dispatchEvent(new confirm.window.Event('closed'));
  confirm.window.eval(script('wt-dialog.js'));
  confirm.window.eval(script('modal-delete-api.js'));
  cd.querySelector('[data-wt-dialog-target]').click();
  const field = cd.querySelector('[data-wt-confirm-name]');
  const button = cd.querySelector('[data-wt-confirm-submit]');
  assert.equal(button.disabled, true);
  assert.equal(cd.querySelector('connection'), null);
  assert.match(cd.querySelector('[data-delete-repos-label]').textContent, /payments/);
  field.value = 'wrong';
  field.dispatchEvent(new confirm.window.Event('input', {bubbles: true}));
  assert.equal(button.disabled, true);
  field.value = 'Team <connection>';
  field.dispatchEvent(new confirm.window.Event('input', {bubbles: true}));
  assert.equal(button.disabled, false);
  modal.close();
  assert.equal(field.value, '');
  assert.equal(button.disabled, true);
  confirm.window.close();

  const profile = fs.readFileSync(path.join(resources, 'templates/profile.html'), 'utf8');
  const secretMarkup = profile.match(/<md-dialog data-new-api-key-dialog[\s\S]*?<\/md-dialog>/)[0];
  const secretDom = new JSDOM(`<body>${secretMarkup}</body>`, {runScripts: 'dangerously'});
  const sw = secretDom.window;
  class Dialog extends sw.HTMLElement {
    show() { this.setAttribute('open', ''); }
    close() { this.dispatchEvent(new sw.Event('closed')); }
  }
  sw.customElements.define('md-dialog', Dialog);
  const secretField = sw.document.querySelector('#newApiKeySecret');
  secretField.value = 'fixture-secret';
  secretField.setAttribute('value', 'fixture-secret');
  let copied;
  Object.defineProperty(sw.navigator, 'clipboard', {value: {writeText: async value => { copied = value; }}});
  sw.eval(script('profile.js'));
  await tick();
  assert.equal(sw.document.querySelector('md-dialog').hasAttribute('open'), true);
  sw.document.querySelector('[data-copy-api-secret]').click();
  await tick();
  assert.equal(copied, 'fixture-secret');
  assert.equal(sw.document.querySelector('[data-copy-status]').textContent, 'Secret copied.');
  sw.document.querySelector('[data-close-api-secret]').click();
  assert.equal(sw.document.querySelector('[data-new-api-key-dialog]'), null);
  assert.equal(secretField.value, '');
  assert.equal(secretField.hasAttribute('value'), false);
  secretDom.window.close();
  console.log('Settings popups: lazy rules, preserved selections, confirmation and one-time secret copy passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
