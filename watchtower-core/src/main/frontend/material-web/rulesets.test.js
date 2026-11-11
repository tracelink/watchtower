const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// Rulesets (UAT walkthrough, 2026-10-16): rules are paged and filtered on the server; the page
// script opens dialogs from the More menu (closing the menu) and shows loading while the
// picker opens another ruleset.
const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/rulesets.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <div data-ruleset-region aria-busy="false"><div data-ruleset-loading hidden></div>
  <details data-ruleset-menu open><summary>Default Dev Ruleset</summary>
    <a href="#other" data-ruleset-link>Other ruleset</a></details>
  <details data-ruleset-more open><summary>More</summary>
    <button type="button" data-wt-dialog-target="#editRulesModal">Edit rules</button></details>
  <md-dialog id="editRulesModal"><button type="button" id="cancelEditRulesModal" data-wt-dialog-close>Cancel</button>
    <button type="button" id="nestedDelete" data-wt-dialog-target="#deleteRulesetModal">Delete</button></md-dialog>
  <md-dialog id="deleteRulesetModal"><button type="button" data-wt-dialog-close>Cancel</button></md-dialog></div>
</body>`, {runScripts: 'dangerously', url: 'https://watchtower.example/rulesets/1'});
const w = dom.window;
const doc = w.document;
const dialog = doc.getElementById('editRulesModal');
let shown = 0;
let closed = 0;
dialog.show = () => { shown++; dialog.open = true; doc.getElementById('cancelEditRulesModal').focus(); };
dialog.close = () => { closed++; dialog.open = false; dialog.dispatchEvent(new w.Event('closed')); };
const deleteDialog = doc.getElementById('deleteRulesetModal');
deleteDialog.show = () => { deleteDialog.open = true; deleteDialog.querySelector('button').focus(); };
deleteDialog.close = () => { deleteDialog.open = false; deleteDialog.dispatchEvent(new w.Event('closed')); };
w.eval(fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/wt-dialog.js'), 'utf8'));
w.eval(script);

const more = doc.querySelector('[data-ruleset-more]');
more.querySelector('[data-wt-dialog-target]').click();
assert.equal(shown, 1, 'Edit rules opens its dialog');
assert.equal(more.hasAttribute('open'), false, 'the More menu closes as the dialog opens');
doc.getElementById('cancelEditRulesModal').click();
assert.equal(closed, 1);
assert.equal(doc.activeElement, more.querySelector('summary'), 'Cancel returns focus to the visible More summary');

more.setAttribute('open', '');
more.querySelector('[data-wt-dialog-target]').click();
doc.getElementById('nestedDelete').click();
assert.equal(dialog.open, false, 'opening the nested delete confirmation closes its parent');
assert.equal(doc.activeElement, deleteDialog.querySelector('button'), 'parent close does not steal focus from the child');
// Escape and Cancel both emit Material Dialog's closed event.
deleteDialog.close();
assert.equal(doc.activeElement, more.querySelector('summary'), 'nested dialog dismissal returns focus to More');

doc.querySelector('[data-ruleset-link]').click();
assert.equal(doc.querySelector('[data-ruleset-loading]').hidden, false, 'loading shows while another ruleset opens');
assert.equal(doc.querySelector('[data-ruleset-region]').getAttribute('aria-busy'), 'true');

// No client-side rule filtering or paging is left: the server pages the rules.
assert.equal(script.includes('data-rule-pagination'), false);
console.log('Rulesets: More menu dialogs and picker loading passed');
