const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../../../../watchtower-module-eslint/src/main/resources/static/scripts/eslint-designer.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <textarea id="sourceCode">source</textarea><details data-eslint-tree><textarea id="ast"></textarea></details>
  <span data-eslint-messages-label>1 message: one</span>
  <textarea id="createFunction">create</textarea><textarea id="customCreateFunction"></textarea>
  <button class="add-message"></button>
  <div class="messages-table"><table><thead><tr><th>Key</th><th>Value</th><th>Action</th></tr></thead>
    <tbody class="messages-tbody"><tr><td><input name="messages[0].key" value="one"></td><td><input name="messages[0].value" value="first"></td><td><button class="delete-message"><i>delete</i></button></td></tr></tbody>
  </table></div>
  <button id="save-rule-btn" data-wt-dialog-target="#save-rule-dialog"></button>
  <button id="cancel-save-rule-dialog"></button><div id="save-rule-dialog"></div>
  <div class="save-messages"></div><input id="customSourceCode">
</body>`, {runScripts: 'dangerously'});
dom.window.requestAnimationFrame = callback => callback();
const editors = [];
dom.window.CodeMirror = {fromTextArea: field => {
  const editor = {field, refreshed: 0,
    setSize() {}, refresh() { this.refreshed += 1; }, setValue(value) { field.value = value; }, getValue() { return field.value; }};
  editors.push(editor);
  return editor;
}};
let matchedEditor = null;
dom.window.wtDesignerMatches = editor => { matchedEditor = editor; };
const dialog = dom.window.document.getElementById('save-rule-dialog');
dialog.show = () => { dialog.dataset.open = 'true'; };
dialog.close = () => { delete dialog.dataset.open; };
dom.window.eval(script);

const document = dom.window.document;
document.querySelector('.add-message').click();
assert.equal(document.querySelectorAll('.messages-tbody tr').length, 2);
document.querySelectorAll('.messages-tbody input')[2].value = '<script>';
document.querySelectorAll('.delete-message')[0].click();
assert.equal(document.querySelector('.messages-tbody input').name, 'messages[0].key');
assert.equal(document.querySelector('.messages-tbody input').value, '<script>');

// The match chips highlight the sample (not the rule); the folded syntax tree measures when opened.
assert.equal(matchedEditor.field.id, 'sourceCode');
const ast = editors.find(editor => editor.field.id === 'ast');
document.querySelector('[data-eslint-tree]').dispatchEvent(new dom.window.Event('toggle'));
assert.equal(ast.refreshed, 1);
// The Messages chip names the IDs and follows adds, edits and deletes.
assert.equal(document.querySelector('[data-eslint-messages-label]').textContent, '1 message: <script>');
document.querySelector('.add-message').click();
assert.equal(document.querySelector('[data-eslint-messages-label]').textContent, '2 messages: <script>');
document.querySelectorAll('.messages-tbody input')[2].value = 'unexpected';
document.querySelectorAll('.messages-tbody input')[2].dispatchEvent(new dom.window.Event('input', {bubbles: true}));
assert.equal(document.querySelector('[data-eslint-messages-label]').textContent, '2 messages: <script>, unexpected');
document.querySelectorAll('.delete-message')[1].click();

document.getElementById('save-rule-btn').click();
assert.equal(dialog.dataset.open, 'true');
assert.equal(document.querySelector('.save-messages script'), null);
assert.equal(document.querySelector('.save-messages input').value, '<script>');
assert.equal(document.querySelector('.save-messages input').readOnly, true);
assert.equal(script.includes('$('), false);
assert.equal(script.includes('innerHTML'), false);
console.log('ESLint designer jsdom test passed');
