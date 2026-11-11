const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/pr-bypass.js'), 'utf8');

function load(body) {
  const dom = new JSDOM(`<!doctype html><body>${body}</body>`, {runScripts: 'dangerously'});
  const {window} = dom;
  window.document.querySelectorAll('md-dialog').forEach((dialog) => {
    dialog.open = false;
    dialog.show = () => { dialog.open = true; };
    dialog.close = () => {
      dialog.open = false;
      dialog.dispatchEvent(new window.Event('closed'));
    };
  });
  window.eval(script);
  return window;
}

const page = `
  <md-outlined-button id="open" data-wt-dialog-target="#bypassDialog">Bypass</md-outlined-button>
  <md-dialog id="bypassDialog">
    <div slot="content"><form id="bypassForm"><md-outlined-text-field name="reason"></md-outlined-text-field></form></div>
    <md-text-button id="cancelBypassDialog">Close</md-text-button>
  </md-dialog>`;

{
  const window = load(page);
  const dialog = window.document.getElementById('bypassDialog');
  const open = window.document.getElementById('open');

  open.click();
  assert.equal(dialog.open, true, 'the one bypass button opens the dialog');

  let focused = false;
  open.focus = () => { focused = true; };
  window.document.getElementById('cancelBypassDialog').click();
  assert.equal(dialog.open, false, 'close closes the dialog');
  assert.equal(focused, true, 'closing returns focus to the bypass button');
}

{
  // Nothing blocks and nothing is pending: the page has no dialog and the script does nothing.
  const window = load('<p>No bypass</p>');
  assert.equal(window.document.getElementById('bypassDialog'), null);
}

console.log('pr-bypass tests passed');
